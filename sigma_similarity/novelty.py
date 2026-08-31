"""
Portable novelty / dedup layer over the deterministic similarity engine.

In Huntable CTI Studio this logic lives in ``src/services/sigma_novelty_service.py``
and is entangled with SQLAlchemy/Postgres. Here it runs against a local JSON corpus
index, so the whole pipeline stays PyYAML + stdlib with no database and no I/O beyond
reading rule files.

Pipeline: build_index() -> retrieve_candidates() -> compare_precomputed() -> classify()
          -> assess_rule()

No global mutable state; no wall-clock; no randomness. Same inputs -> identical output.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from sigma_similarity.ast_builder import build_ast
from sigma_similarity.atom_extractor import (
    extract_negative_atoms,
    extract_positive_atoms,
)
from sigma_similarity.canonical_logsource import resolve_canonical_class
from sigma_similarity.containment_estimator import compute_containment
from sigma_similarity.detection_normalizer import normalize_detection
from sigma_similarity.dnf_normalizer import ast_to_dnf
from sigma_similarity.errors import (
    DeterministicExpansionLimitError,
    UnknownTelemetryClassError,
    UnsupportedSigmaFeatureError,
)
from sigma_similarity.filter_analyzer import filter_penalty
from sigma_similarity.surface_estimator import surface_score_from_dnf

INDEX_VERSION = "1"
ENGINE_VERSION = "2.0"

#: Classification thresholds. Inclusive (``>=``) on both boundaries.
#:
#: These come from the current precomputed-engine rule. Huntable also carries a
#: legacy backend rule (strict ``>`` on atom_jaccard 0.95/0.80 plus a logic_shape
#: input) that predates the engine consolidation; it is deliberately NOT ported —
#: logic shape no longer exists and the weighted similarity is the only score.
DUPLICATE_THRESHOLD = 0.75
SIMILAR_THRESHOLD = 0.50

#: Default suppression threshold for CI-style gating (Huntable's similarity_threshold).
DEFAULT_SUPPRESSION_THRESHOLD = 0.5

#: Fields whose atom values name an executable. Used only by the soft-exe fallback
#: (§8.6) to catch cross-field matches, e.g. rundll32.exe named in Image on one side
#: and inside CommandLine on the other.
_PROCESS_EXE_CANONICAL_FIELDS: frozenset[str] = frozenset(
    {
        "process.image",
        "process.parent_image",
        "process.command_line",
        "process.parent_command_line",
        "process.original_file_name",
        # Legacy / un-aliased forms that may appear in a stored index.
        "image",
        "parentimage",
        "commandline",
        "parentcommandline",
        "originalfilename",
        "command_line",
        "parent_image",
    }
)

SKIP_LOGSOURCE_UNRESOLVED = "logsource_unresolved"
SKIP_DNF_EXPANSION_LIMIT = "dnf_expansion_limit"
SKIP_UNSUPPORTED_FEATURE = "unsupported_sigma_feature"

VERDICT_DUPLICATE = "DUPLICATE"
VERDICT_SIMILAR = "SIMILAR"
VERDICT_NOVEL = "NOVEL"
VERDICT_NEEDS_REVIEW = "NEEDS_REVIEW"


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExtractedRule:
    """Atoms extracted from one rule, or the reason extraction was skipped.

    A skipped rule keeps ``canonical_class`` when it was resolvable and sets every
    atom field to ``None``. ``None`` atoms must always stay distinguishable from an
    empty atom set — "we could not extract" is not "this rule has no atoms".
    """

    canonical_class: str | None = None
    positive_atoms: tuple[str, ...] | None = None
    negative_atoms: tuple[str, ...] | None = None
    surface_score: float | None = None
    skip_reason: str | None = None

    @property
    def extracted(self) -> bool:
        """True when atoms are available for scoring."""
        return self.positive_atoms is not None


def extract_rule(rule: dict, *, require_canonical_class: bool = True) -> ExtractedRule:
    """Extract atoms and surface from a Sigma rule dict.

    Args:
        rule: Parsed Sigma rule.
        require_canonical_class: Strict (index-time) semantics. When True, a rule that
            maps to no canonical class is skipped with ``logsource_unresolved`` rather
            than raising. When False (candidate rescoring), extraction continues with
            ``canonical_class=None`` so unmodeled logsources can still be scored.

    Returns:
        ExtractedRule — never raises for rule-level problems; failures become skip_reason.
    """
    try:
        canonical_class: str | None = resolve_canonical_class(rule)
    except UnknownTelemetryClassError:
        if require_canonical_class:
            return ExtractedRule(skip_reason=SKIP_LOGSOURCE_UNRESOLVED)
        canonical_class = None

    try:
        normalized = normalize_detection(rule.get("detection") or {})
        dnf = ast_to_dnf(build_ast(normalized))
        surface = surface_score_from_dnf(dnf)
    except DeterministicExpansionLimitError:
        return ExtractedRule(canonical_class=canonical_class, skip_reason=SKIP_DNF_EXPANSION_LIMIT)
    except UnsupportedSigmaFeatureError:
        return ExtractedRule(canonical_class=canonical_class, skip_reason=SKIP_UNSUPPORTED_FEATURE)

    return ExtractedRule(
        canonical_class=canonical_class,
        positive_atoms=tuple(sorted(extract_positive_atoms(dnf))),
        negative_atoms=tuple(sorted(extract_negative_atoms(dnf))),
        surface_score=surface,
    )


def logsource_key(rule: dict) -> str:
    """``"product|category"``, lowercased. Used only by the retrieval fallback path.

    Returns ``"|"`` when neither slot is set and ``""`` when there is no logsource
    block at all; both are treated as "no candidates" by retrieve_candidates().
    """
    logsource = rule.get("logsource")
    if not isinstance(logsource, dict):
        return ""
    product = str(logsource.get("product") or "").strip().lower()
    category = str(logsource.get("category") or "").strip().lower()
    return f"{product}|{category}"


def generate_exact_hash(
    canonical_class: str | None,
    positive_atoms: list[str] | tuple[str, ...] | None,
    negative_atoms: list[str] | tuple[str, ...] | None,
    surface_score: float | None,
) -> str | None:
    """SHA-256 over the rule's canonical form, or None when it has no positive atoms.

    The None guard is load-bearing. Atom-less rules all collapse to one degenerate
    canonical form, and an exact-hash match classifies DUPLICATE — in Huntable this
    once put 84 unrelated process_creation rules on a single hash and silently
    suppressed novel rules. Companion guard lives in retrieve_candidates(), which
    only probes when the proposed hash is not None (NULL must never equal NULL).

    These hashes are deliberately NOT compatible with Huntable's DB ``exact_hash``
    column, which hashes the app-side canonical-rule JSON. Only the semantics are
    the contract: identical canonical form => duplicate, atom-less => never hash.
    """
    if not positive_atoms:
        return None
    payload = {
        "canonical_class": canonical_class,
        "positive_atoms": sorted(positive_atoms),
        "negative_atoms": sorted(negative_atoms or ()),
        "surface_score": surface_score,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# ---------------------------------------------------------------------------
# Corpus index
# ---------------------------------------------------------------------------


def _surface_out(surface: float | None) -> int | None:
    """Surface is always a whole branch count; emit it as an int in serialized shapes."""
    return None if surface is None else int(surface)


def build_index_entry(rule: dict, *, rule_id: str, path: str) -> dict[str, Any]:
    """Build one corpus index entry. Index-time extraction is strict."""
    extracted = extract_rule(rule, require_canonical_class=True)
    return {
        "rule_id": rule_id,
        "path": path,
        "title": str(rule.get("title") or ""),
        "canonical_class": extracted.canonical_class,
        "logsource_key": logsource_key(rule),
        "positive_atoms": list(extracted.positive_atoms) if extracted.positive_atoms is not None else None,
        "negative_atoms": list(extracted.negative_atoms) if extracted.negative_atoms is not None else None,
        "surface_score": _surface_out(extracted.surface_score),
        "exact_hash": generate_exact_hash(
            extracted.canonical_class,
            extracted.positive_atoms,
            extracted.negative_atoms,
            _surface_out(extracted.surface_score),
        ),
        "skip_reason": extracted.skip_reason,
    }


def load_rule_file(path: Path) -> dict:
    """Load one Sigma YAML rule. Raises ValueError if it is not a mapping."""
    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid rule YAML (expected a mapping): {path}")
    return data


def iter_rule_paths(rules_dir: Path) -> list[Path]:
    """All .yml/.yaml files under rules_dir, sorted for deterministic index order."""
    found = [p for p in rules_dir.rglob("*") if p.is_file() and p.suffix.lower() in (".yml", ".yaml")]
    return sorted(found, key=lambda p: p.relative_to(rules_dir).as_posix())


def build_index(rules_dir: Path) -> dict[str, Any]:
    """Walk a directory of Sigma rules and build the corpus index.

    Rules that cannot be extracted are RETAINED with null atom fields and a
    ``skip_reason``. Persisting the reason per rule is deliberate — Huntable does not,
    and its ADR flags that as a known gap; the portable replica closes it.
    """
    rules: list[dict[str, Any]] = []
    for path in iter_rule_paths(rules_dir):
        relative = path.relative_to(rules_dir).as_posix()
        try:
            rule = load_rule_file(path)
        except Exception:
            # Unparseable YAML is not a Sigma-feature problem; record it and move on
            # so one bad file cannot abort a corpus build.
            rules.append(
                {
                    "rule_id": relative,
                    "path": relative,
                    "title": "",
                    "canonical_class": None,
                    "logsource_key": "",
                    "positive_atoms": None,
                    "negative_atoms": None,
                    "surface_score": None,
                    "exact_hash": None,
                    "skip_reason": "unparseable_yaml",
                }
            )
            continue
        rule_id = str(rule.get("id") or relative)
        rules.append(build_index_entry(rule, rule_id=rule_id, path=relative))

    return {"index_version": INDEX_VERSION, "engine_version": ENGINE_VERSION, "rules": rules}


# ---------------------------------------------------------------------------
# Candidate retrieval
# ---------------------------------------------------------------------------


def retrieve_candidates(
    proposed: dict[str, Any],
    index: dict[str, Any],
    top_k: int = 20,
) -> list[dict[str, Any]]:
    """Retrieve corpus candidates for a proposed rule, in Huntable's phase-1 order.

    1. Exact-hash probe — only when the proposed hash is not None. First hit returns
       immediately; hash identity is proof, so no further filtering is applied.
    2. Canonical-class path — every indexed rule in the same class, unlimited.
    3. Logsource fallback — equal logsource_key, sorted by rule_id, truncated to top_k.
       Sorting before truncation is what makes the top-k stable; an unordered LIMIT
       here was a real nondeterminism bug.

    Args:
        proposed: Mapping with ``exact_hash``, ``canonical_class`` and ``logsource_key``.
        index: Corpus index as produced by build_index().
        top_k: Fallback-path cap.

    Returns:
        List of ``{"entry", "exact_hash_match", "phase1_path"}`` dicts.
    """
    entries: list[dict[str, Any]] = index.get("rules") or []

    proposed_hash = proposed.get("exact_hash")
    if proposed_hash is not None:
        for entry in entries:
            if entry.get("exact_hash") == proposed_hash:
                return [{"entry": entry, "exact_hash_match": True, "phase1_path": "exact_hash"}]

    proposed_class = proposed.get("canonical_class")
    if proposed_class:
        matched = [e for e in entries if e.get("canonical_class") == proposed_class]
        return [{"entry": e, "exact_hash_match": False, "phase1_path": "canonical_class"} for e in matched]

    key = proposed.get("logsource_key") or ""
    if key in ("", "|"):
        return []
    matched = sorted(
        (e for e in entries if e.get("logsource_key") == key),
        key=lambda e: str(e.get("rule_id") or ""),
    )[:top_k]
    return [{"entry": e, "exact_hash_match": False, "phase1_path": "logsource_fallback"} for e in matched]


def apply_phase1_gate(candidates: list[dict[str, Any]], proposed_logsource_key: str) -> list[dict[str, Any]]:
    """Drop logsource-mismatched candidates on the fallback path only.

    On the canonical_class path the class filter is already authoritative, and on the
    exact_hash path hash identity is proof — gating either would discard valid matches.
    """
    kept: list[dict[str, Any]] = []
    for candidate in candidates:
        path = candidate.get("phase1_path")
        if path in ("exact_hash", "canonical_class"):
            kept.append(candidate)
            continue
        if candidate["entry"].get("logsource_key") == proposed_logsource_key:
            kept.append(candidate)
    return kept


# ---------------------------------------------------------------------------
# Precomputed scoring (set math over stored atom identities)
# ---------------------------------------------------------------------------


def _extract_exe_value(atom_id: str) -> str | None:
    """Value slot of an atom whose field names an executable, else None.

    Field matching is case-insensitive so a non-normalized stored identity
    (``Image|endswith|...``) still resolves.
    """
    segments = atom_id.split("|")
    if len(segments) < 3:
        return None
    if segments[0].lower() not in _PROCESS_EXE_CANONICAL_FIELDS:
        return None
    return segments[-1]


def soft_exe_jaccard(atoms_a: set[str], atoms_b: set[str], union: set[str]) -> float:
    """Cross-field executable-name fallback used only when strict Jaccard is 0.

    Dampened by 0.5: the same exe named in Image on one side and CommandLine on the
    other is real but weaker evidence than an exact atom match.
    """
    if not union:
        return 0.0
    values_a = {v for a in atoms_a if (v := _extract_exe_value(a)) is not None}
    values_b = {v for b in atoms_b if (v := _extract_exe_value(b)) is not None}
    shared = values_a & values_b
    if not shared:
        return 0.0
    return min((len(shared) / len(union)) * 0.5, 1.0)


def compare_precomputed(
    a: ExtractedRule,
    b: ExtractedRule,
    *,
    enable_soft_exe: bool = True,
) -> dict[str, Any]:
    """Score two already-extracted rules by pure set math.

    Mirrors compare_rules() but skips parsing, and adds the soft-exe fallback that
    Huntable applies on its live precomputed path.
    """
    atoms_a = set(a.positive_atoms or ())
    atoms_b = set(b.positive_atoms or ())
    filters_a = set(a.negative_atoms or ())
    filters_b = set(b.negative_atoms or ())
    surface_a = a.surface_score or 0.0
    surface_b = b.surface_score or 0.0

    intersection = atoms_a & atoms_b
    union = atoms_a | atoms_b
    penalty = filter_penalty(filters_a, filters_b, len(atoms_a), len(atoms_b))

    reason_flags: list[str] = []
    jaccard = len(intersection) / len(union) if union else 0.0
    effective_intersection = len(intersection)

    if jaccard == 0.0 and enable_soft_exe:
        soft = soft_exe_jaccard(atoms_a, atoms_b, union)
        if soft > 0.0:
            jaccard = soft
            # Synthesize an intersection size so containment still has something to
            # divide; at least 1, since a shared exe value did match.
            effective_intersection = max(1, round(soft * len(union)))
            reason_flags.append("soft_exe_match")

    shared_display = sorted(intersection)
    only_a = sorted(atoms_a - atoms_b)
    only_b = sorted(atoms_b - atoms_a)
    filter_differences = sorted(filters_a.symmetric_difference(filters_b))

    if jaccard == 0.0:
        return {
            "similarity": 0.0,
            "jaccard": 0.0,
            "containment_factor": 0.65,
            "containment": 0.0,
            "overlap_ratio_a": 0.0,
            "overlap_ratio_b": 0.0,
            "filter_penalty": penalty,
            "surface_score_a": surface_a,
            "surface_score_b": surface_b,
            "reason_flags": ["no_shared_atoms"],
            "shared_atoms": shared_display,
            "atoms_only_in_a": only_a,
            "atoms_only_in_b": only_b,
            "filter_differences": filter_differences,
        }

    factor, overlap_a, overlap_b = compute_containment(
        effective_intersection, len(atoms_a), len(atoms_b), surface_a, surface_b
    )
    similarity = max(0.0, min(1.0, (jaccard * factor) - penalty))

    return {
        "similarity": similarity,
        "jaccard": jaccard,
        "containment_factor": factor,
        # `containment` is the raw directional ratio (how much of A is covered by B).
        # `containment_factor` is the 4-way bucket. Different numbers from the same
        # function; conflating them was a real Huntable bug (fixed 2026-06-05).
        "containment": overlap_a,
        "overlap_ratio_a": overlap_a,
        "overlap_ratio_b": overlap_b,
        "filter_penalty": penalty,
        "surface_score_a": surface_a,
        "surface_score_b": surface_b,
        "reason_flags": reason_flags,
        "shared_atoms": shared_display,
        "atoms_only_in_a": only_a,
        "atoms_only_in_b": only_b,
        "filter_differences": filter_differences,
    }


def classify(match: dict[str, Any]) -> str:
    """Label one match. Per match — never broadcast the best match's label to the rest."""
    if match.get("exact_hash_match"):
        return VERDICT_DUPLICATE
    similarity = match.get("similarity", 0.0)
    if similarity >= DUPLICATE_THRESHOLD:
        return VERDICT_DUPLICATE
    if similarity >= SIMILAR_THRESHOLD:
        return VERDICT_SIMILAR
    return VERDICT_NOVEL


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


def atom_identity_to_display(atom_id: str) -> str:
    """Render a 3-slot identity as ``field|op:value`` (or ``field:value`` for eq).

    Display only — all set math runs on raw identities.
    """
    segments = atom_id.split("|")
    if len(segments) < 2:
        return atom_id
    field = segments[0]
    value = segments[-1]
    mod_tokens = segments[1:-1]
    op = mod_tokens[0] if mod_tokens and mod_tokens[0] else ""
    return f"{field}|{op}:{value}" if op else f"{field}:{value}"


def _round(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(value, digits)


def _entry_to_extracted(entry: dict[str, Any]) -> ExtractedRule | None:
    """Rehydrate stored atoms into an ExtractedRule, or None when the entry was skipped."""
    positive = entry.get("positive_atoms")
    if positive is None:
        return None
    surface = entry.get("surface_score")
    return ExtractedRule(
        canonical_class=entry.get("canonical_class"),
        positive_atoms=tuple(positive),
        negative_atoms=tuple(entry.get("negative_atoms") or ()),
        surface_score=float(surface) if surface is not None else 0.0,
    )


def _candidate_extracted(entry: dict[str, Any], base_dir: Path | None) -> ExtractedRule | None:
    """Stored atoms if present; otherwise re-extract live with a relaxed class requirement.

    Relaxed extraction lets rules on unmodeled logsources still be scored. When neither
    works the candidate is skipped rather than scored as a zero.
    """
    stored = _entry_to_extracted(entry)
    if stored is not None:
        return stored
    if base_dir is None:
        return None
    path = entry.get("path")
    if not path:
        return None
    candidate_path = base_dir / path
    if not candidate_path.is_file():
        return None
    try:
        rule = load_rule_file(candidate_path)
    except Exception:
        return None
    live = extract_rule(rule, require_canonical_class=False)
    return live if live.extracted else None


def assess_rule(
    rule: dict,
    index: dict[str, Any],
    *,
    rule_id: str | None = None,
    top_k: int = 20,
    threshold: float = DEFAULT_SUPPRESSION_THRESHOLD,
    enable_soft_exe: bool = True,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    """Assess one proposed rule against a corpus index.

    Verdict order: exact-hash hit -> DUPLICATE; inconclusive -> NEEDS_REVIEW (fail open);
    otherwise classify the best match, with NOVEL when nothing scored above zero.

    An unassessable rule is a *failure to assess*, not a duplicate — it must never be
    silently passed as novel nor suppressed. Note the two distinct ``total == 0`` cases:
    an empty corpus with atoms extracted fine is genuinely NOVEL (max_similarity 0.0),
    while a proposed rule that extracted zero atoms is NEEDS_REVIEW (max_similarity null).
    Collapsing those once disabled novelty suppression for ~86% of Huntable's queue.
    """
    # Scoring the proposed rule uses the RELAXED requirement, matching Huntable
    # (sigma_novelty_service extracts both the proposed rule and its candidates with
    # require_canonical_class=False; only index-time precompute is strict). Strict
    # extraction here would leave every unmodeled-logsource rule with no atoms, which
    # would make the logsource fallback path in retrieve_candidates unreachable —
    # it retrieves candidates that could never be scored.
    extracted = extract_rule(rule, require_canonical_class=False)
    key = logsource_key(rule)
    positive = extracted.positive_atoms or ()
    proposed_hash = generate_exact_hash(
        extracted.canonical_class, positive, extracted.negative_atoms, _surface_out(extracted.surface_score)
    )

    proposed = {
        "exact_hash": proposed_hash,
        "canonical_class": extracted.canonical_class,
        "logsource_key": key,
    }
    candidates = apply_phase1_gate(retrieve_candidates(proposed, index, top_k=top_k), key)

    matches: list[dict[str, Any]] = []
    evaluated = 0
    exact_hit = False

    for candidate in candidates:
        entry = candidate["entry"]
        if candidate["exact_hash_match"]:
            exact_hit = True
            evaluated += 1
            matches.append(
                _build_match(
                    entry,
                    {
                        "similarity": 1.0,
                        "jaccard": 1.0,
                        "containment_factor": 1.0,
                        "containment": 1.0,
                        "overlap_ratio_a": 1.0,
                        "overlap_ratio_b": 1.0,
                        "filter_penalty": 0.0,
                        "surface_score_a": extracted.surface_score or 0.0,
                        "surface_score_b": float(entry.get("surface_score") or 0.0),
                        "reason_flags": ["exact_hash_match"],
                        "shared_atoms": sorted(positive),
                        "atoms_only_in_a": [],
                        "atoms_only_in_b": [],
                        "filter_differences": [],
                    },
                    exact_hash_match=True,
                    phase1_path=candidate["phase1_path"],
                )
            )
            continue

        other = _candidate_extracted(entry, base_dir)
        if other is None:
            continue
        evaluated += 1
        if not extracted.extracted:
            # Nothing to score against; the rule is inconclusive, handled below.
            continue
        scored = compare_precomputed(extracted, other, enable_soft_exe=enable_soft_exe)
        if scored["similarity"] > 0.0:
            matches.append(
                _build_match(entry, scored, exact_hash_match=False, phase1_path=candidate["phase1_path"])
            )

    matches.sort(key=lambda m: (-m["similarity"], str(m.get("rule_id") or "")))
    matches = matches[:10]

    no_atoms = len(positive) == 0
    behavioral = sum(1 for m in matches if m["jaccard"] > 0)
    inconclusive = no_atoms or (evaluated > 0 and behavioral == 0)

    if exact_hit:
        verdict = VERDICT_DUPLICATE
        max_similarity: float | None = 1.0
    elif inconclusive:
        verdict = VERDICT_NEEDS_REVIEW
        max_similarity = None
    elif matches:
        verdict = classify(matches[0])
        max_similarity = matches[0]["similarity"]
    else:
        verdict = VERDICT_NOVEL
        max_similarity = 0.0

    suppressed = False if max_similarity is None else max_similarity >= threshold

    return {
        "rule_id": rule_id or str(rule.get("id") or ""),
        "title": str(rule.get("title") or ""),
        "verdict": verdict,
        "max_similarity": _round(max_similarity),
        "no_atoms": no_atoms,
        "inconclusive": inconclusive,
        "suppressed": suppressed,
        "threshold": threshold,
        "canonical_class": extracted.canonical_class,
        "logsource_key": key,
        "skip_reason": extracted.skip_reason,
        "exact_hash": proposed_hash,
        "phase1_path": candidates[0]["phase1_path"] if candidates else None,
        "candidates_evaluated": evaluated,
        "behavioral_matches": behavioral,
        "positive_atoms": [atom_identity_to_display(a) for a in positive],
        "matches": [_round_match(m) for m in matches],
    }


def _build_match(
    entry: dict[str, Any],
    scored: dict[str, Any],
    *,
    exact_hash_match: bool,
    phase1_path: str,
) -> dict[str, Any]:
    """Assemble the serialized match shape from a scored pair."""
    match = {
        "rule_id": entry.get("rule_id"),
        "title": entry.get("title") or "",
        "similarity": scored["similarity"],
        "jaccard": scored["jaccard"],
        "containment_factor": scored["containment_factor"],
        "containment": scored["containment"],
        "overlap_ratio_a": scored["overlap_ratio_a"],
        "overlap_ratio_b": scored["overlap_ratio_b"],
        "filter_penalty": scored["filter_penalty"],
        "surface_score_a": _surface_out(scored["surface_score_a"]),
        "surface_score_b": _surface_out(scored["surface_score_b"]),
        "canonical_class": entry.get("canonical_class"),
        "exact_hash_match": exact_hash_match,
        "phase1_path": phase1_path,
        "reason_flags": scored["reason_flags"],
        "shared_atoms": [atom_identity_to_display(a) for a in scored["shared_atoms"]],
        "atoms_only_in_a": [atom_identity_to_display(a) for a in scored["atoms_only_in_a"]],
        "atoms_only_in_b": [atom_identity_to_display(a) for a in scored["atoms_only_in_b"]],
        "filter_differences": [atom_identity_to_display(a) for a in scored["filter_differences"]],
    }
    match["novelty_label"] = classify(match)
    return match


def _round_match(match: dict[str, Any]) -> dict[str, Any]:
    """Round float fields to 4dp at emit time (Huntable serializer precision)."""
    out = dict(match)
    for field in (
        "similarity",
        "jaccard",
        "containment_factor",
        "containment",
        "overlap_ratio_a",
        "overlap_ratio_b",
        "filter_penalty",
    ):
        out[field] = _round(out[field])
    return out
