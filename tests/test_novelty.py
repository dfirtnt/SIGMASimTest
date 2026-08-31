"""Novelty layer: exact hash, retrieval, classification, verdicts, soft-exe fallback.

Each test here encodes a behavior that fixed a real shipped bug — treat them as
regression contracts, not illustrations.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sigma_similarity.novelty import (
    ExtractedRule,
    apply_phase1_gate,
    assess_rule,
    atom_identity_to_display,
    build_index,
    classify,
    compare_precomputed,
    extract_rule,
    generate_exact_hash,
    logsource_key,
    retrieve_candidates,
    soft_exe_jaccard,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_rule(**overrides) -> dict:
    """Minimal windows.process_creation rule."""
    rule = {
        "title": "Test",
        "id": "rule-a",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
    }
    rule.update(overrides)
    return rule


def entry_for(rule: dict, *, rule_id: str, path: str = "r.yml") -> dict:
    from sigma_similarity.novelty import build_index_entry

    return build_index_entry(rule, rule_id=rule_id, path=path)


def index_of(*entries: dict) -> dict:
    return {"index_version": "1", "engine_version": "2.0", "rules": list(entries)}


def write_rules(tmp_path: Path, rules: dict[str, dict]) -> Path:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    for name, rule in rules.items():
        (rules_dir / name).write_text(json.dumps(rule), encoding="utf-8")  # JSON is valid YAML
    return rules_dir


# ---------------------------------------------------------------------------
# 15. exact_hash
# ---------------------------------------------------------------------------


class TestExactHash:
    def test_identical_canonical_forms_collide(self):
        a = extract_rule(make_rule())
        b = extract_rule(make_rule(id="rule-b", title="Different title"))
        assert generate_exact_hash(
            a.canonical_class, a.positive_atoms, a.negative_atoms, a.surface_score
        ) == generate_exact_hash(b.canonical_class, b.positive_atoms, b.negative_atoms, b.surface_score)

    def test_different_atoms_do_not_collide(self):
        a = extract_rule(make_rule())
        b = extract_rule(
            make_rule(detection={"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"})
        )
        assert generate_exact_hash(
            a.canonical_class, a.positive_atoms, a.negative_atoms, a.surface_score
        ) != generate_exact_hash(b.canonical_class, b.positive_atoms, b.negative_atoms, b.surface_score)

    def test_atom_less_rule_hashes_to_none(self):
        """LOAD-BEARING: atom-less rules collapse to one degenerate form and must not hash."""
        assert generate_exact_hash("windows.process_creation", [], [], 1.0) is None
        assert generate_exact_hash("windows.process_creation", None, None, None) is None

    def test_two_atom_less_rules_do_not_match_each_other(self):
        """The NULL == NULL contract: a None hash must never retrieve another None hash.

        In Huntable this guard's absence put 84 unrelated rules on one hash, and since
        an exact-hash hit classifies DUPLICATE, novel rules were silently suppressed.
        """
        empty_entry = {
            "rule_id": "other-empty",
            "canonical_class": None,
            "logsource_key": "windows|process_creation",
            "exact_hash": None,
            "positive_atoms": None,
            "negative_atoms": None,
            "surface_score": None,
        }
        proposed = {"exact_hash": None, "canonical_class": None, "logsource_key": "windows|process_creation"}
        candidates = retrieve_candidates(proposed, index_of(empty_entry))
        assert all(not c["exact_hash_match"] for c in candidates)

    def test_exact_hash_hit_short_circuits_to_duplicate(self):
        rule = make_rule()
        index = index_of(entry_for(make_rule(id="corpus-twin"), rule_id="corpus-twin"))
        result = assess_rule(rule, index)
        assert result["verdict"] == "DUPLICATE"
        assert result["matches"][0]["exact_hash_match"] is True
        assert result["matches"][0]["phase1_path"] == "exact_hash"

    def test_exact_hash_probe_returns_only_first_hit(self):
        entry = entry_for(make_rule(id="twin"), rule_id="twin")
        proposed = {
            "exact_hash": entry["exact_hash"],
            "canonical_class": entry["canonical_class"],
            "logsource_key": entry["logsource_key"],
        }
        candidates = retrieve_candidates(proposed, index_of(entry, dict(entry, rule_id="twin2")))
        assert len(candidates) == 1


# ---------------------------------------------------------------------------
# 16. Retrieval
# ---------------------------------------------------------------------------


class TestRetrieval:
    def test_canonical_class_path_is_unlimited(self):
        entries = [
            entry_for(
                make_rule(
                    id=f"r{i}",
                    detection={"selection": {"Image|endswith": f"\\p{i}.exe"}, "condition": "selection"},
                ),
                rule_id=f"r{i}",
            )
            for i in range(40)
        ]
        proposed = {
            "exact_hash": "nomatch",
            "canonical_class": "windows.process_creation",
            "logsource_key": "windows|process_creation",
        }
        candidates = retrieve_candidates(proposed, index_of(*entries), top_k=20)
        assert len(candidates) == 40
        assert all(c["phase1_path"] == "canonical_class" for c in candidates)

    def test_fallback_path_is_sorted_top_k_and_order_independent(self):
        """Sorting before truncation is what makes top-k stable; an unordered LIMIT
        here was a real nondeterminism bug."""
        entries = [
            {
                "rule_id": f"rule-{i:03d}",
                "canonical_class": None,
                "logsource_key": "custom|thing",
                "exact_hash": f"h{i}",
                "positive_atoms": ["f||v"],
                "negative_atoms": [],
                "surface_score": 1,
            }
            for i in range(30)
        ]
        proposed = {"exact_hash": None, "canonical_class": None, "logsource_key": "custom|thing"}

        forward = retrieve_candidates(proposed, index_of(*entries), top_k=5)
        reverse = retrieve_candidates(proposed, index_of(*reversed(entries)), top_k=5)

        assert [c["entry"]["rule_id"] for c in forward] == [f"rule-{i:03d}" for i in range(5)]
        assert [c["entry"]["rule_id"] for c in forward] == [c["entry"]["rule_id"] for c in reverse]
        assert all(c["phase1_path"] == "logsource_fallback" for c in forward)

    def test_phase1_gate_drops_mismatched_logsource_on_fallback(self):
        candidates = [
            {"entry": {"logsource_key": "windows|process_creation"}, "phase1_path": "logsource_fallback"},
            {"entry": {"logsource_key": "linux|process_creation"}, "phase1_path": "logsource_fallback"},
        ]
        kept = apply_phase1_gate(candidates, "windows|process_creation")
        assert len(kept) == 1
        assert kept[0]["entry"]["logsource_key"] == "windows|process_creation"

    def test_phase1_gate_does_not_touch_authoritative_paths(self):
        """canonical_class is already authoritative; exact_hash identity is proof."""
        candidates = [
            {"entry": {"logsource_key": "other|thing"}, "phase1_path": "canonical_class"},
            {"entry": {"logsource_key": "other|thing"}, "phase1_path": "exact_hash"},
        ]
        assert len(apply_phase1_gate(candidates, "windows|process_creation")) == 2

    @pytest.mark.parametrize("key", ["", "|"])
    def test_empty_logsource_key_yields_no_candidates(self, key):
        entry = {"rule_id": "x", "canonical_class": None, "logsource_key": key, "exact_hash": None}
        proposed = {"exact_hash": None, "canonical_class": None, "logsource_key": key}
        assert retrieve_candidates(proposed, index_of(entry)) == []

    def test_logsource_key_shape(self):
        assert logsource_key(make_rule()) == "windows|process_creation"
        assert logsource_key({"logsource": {"product": "  WINDOWS  "}}) == "windows|"
        assert logsource_key({}) == ""


# ---------------------------------------------------------------------------
# 17. Classification
# ---------------------------------------------------------------------------


class TestClassification:
    @pytest.mark.parametrize(
        "similarity, expected",
        [
            (1.0, "DUPLICATE"),
            (0.75, "DUPLICATE"),  # boundary inclusive
            (0.7499, "SIMILAR"),
            (0.50, "SIMILAR"),  # boundary inclusive
            (0.4999, "NOVEL"),
            (0.0, "NOVEL"),
        ],
    )
    def test_boundaries_are_inclusive(self, similarity, expected):
        assert classify({"similarity": similarity}) == expected

    def test_exact_hash_match_wins_regardless_of_similarity(self):
        assert classify({"similarity": 0.0, "exact_hash_match": True}) == "DUPLICATE"

    def test_labels_are_per_match_not_broadcast(self):
        """One near-duplicate must not relabel weaker matches."""
        near = make_rule(id="near")
        weak = make_rule(
            id="weak",
            detection={
                "selection": {"Image|endswith": "\\cmd.exe", "CommandLine|contains": "whoami"},
                "selection2": {"ParentImage|endswith": "\\explorer.exe"},
                "selection3": {"CommandLine|contains": "netstat"},
                "condition": "selection and selection2 and selection3",
            },
        )
        index = index_of(entry_for(near, rule_id="near"), entry_for(weak, rule_id="weak"))
        # Assess something that is a strong match to `near` and a weak one to `weak`.
        proposed = make_rule(
            id="proposed",
            detection={
                "selection": {"Image|endswith": "\\cmd.exe"},
                "selection2": {"CommandLine|contains": "nothing-in-common"},
                "condition": "selection and selection2",
            },
        )
        result = assess_rule(proposed, index)
        labels = {m["rule_id"]: m["novelty_label"] for m in result["matches"]}
        assert len(set(labels.values())) >= 1
        for match in result["matches"]:
            assert match["novelty_label"] == classify(match)


# ---------------------------------------------------------------------------
# 18. Inconclusive / verdicts
# ---------------------------------------------------------------------------


class TestVerdicts:
    def test_extracted_but_atom_less_rule_is_needs_review(self):
        """An all-NOT condition extracts cleanly but yields no positive atoms — the
        exact case the exact_hash None guard protects. Fail open: an unassessable
        rule is a failure to assess, not a duplicate."""
        atom_less = make_rule(
            id="atomless",
            detection={"filter": {"Image|endswith": "\\cmd.exe"}, "condition": "not filter"},
        )
        extracted = extract_rule(atom_less)
        assert extracted.skip_reason is None
        assert extracted.positive_atoms == ()
        assert generate_exact_hash(
            extracted.canonical_class, extracted.positive_atoms, extracted.negative_atoms, extracted.surface_score
        ) is None

        result = assess_rule(atom_less, index_of(entry_for(make_rule(id="c"), rule_id="c")))
        assert result["verdict"] == "NEEDS_REVIEW"
        assert result["max_similarity"] is None
        assert result["no_atoms"] is True
        assert result["inconclusive"] is True

    def test_unextractable_rule_is_needs_review(self):
        """A bare-scalar selection cannot be parsed into blocks at all; it is skipped
        with a reason and still fails open rather than passing as novel."""
        broken = make_rule(id="broken", detection={"selection": "just-a-scalar", "condition": "selection"})
        extracted = extract_rule(broken)
        assert extracted.skip_reason == "unsupported_sigma_feature"
        assert extracted.positive_atoms is None

        result = assess_rule(broken, index_of(entry_for(make_rule(id="c"), rule_id="c")))
        assert result["verdict"] == "NEEDS_REVIEW"
        assert result["max_similarity"] is None
        assert result["skip_reason"] == "unsupported_sigma_feature"

    def test_empty_corpus_with_atoms_is_novel_with_zero_max_similarity(self):
        """Distinct from the atom-less case — conflating the two once disabled
        novelty suppression for ~86% of Huntable's queue."""
        result = assess_rule(make_rule(), index_of())
        assert result["verdict"] == "NOVEL"
        assert result["max_similarity"] == 0.0
        assert result["no_atoms"] is False
        assert result["inconclusive"] is False

    def test_candidates_evaluated_but_zero_behavioral_matches_is_needs_review(self):
        unrelated = make_rule(
            id="unrelated",
            detection={"selection": {"TargetFilename|endswith": "\\zzz.txt"}, "condition": "selection"},
        )
        result = assess_rule(
            make_rule(),
            index_of(entry_for(unrelated, rule_id="unrelated")),
            enable_soft_exe=False,
        )
        assert result["candidates_evaluated"] == 1
        assert result["behavioral_matches"] == 0
        assert result["verdict"] == "NEEDS_REVIEW"
        assert result["max_similarity"] is None

    def test_similar_verdict(self):
        """Subset bucket: proposed atoms fully contained in a broader corpus rule.
        J = 4/6, overlap_a = 1.0 with surface_a < surface_b -> B = 0.85 -> 0.5667."""
        proposed = make_rule(
            id="proposed",
            detection={"selection": {"CommandLine|contains": ["aa", "bb", "cc", "dd"]}, "condition": "selection"},
        )
        corpus_entry = {
            "rule_id": "corpus",
            "title": "Broader",
            "canonical_class": "windows.process_creation",
            "logsource_key": "windows|process_creation",
            "positive_atoms": [f"process.command_line|contains|{v}" for v in ("aa", "bb", "cc", "dd", "ee", "ff")],
            "negative_atoms": [],
            "surface_score": 6,
            "exact_hash": "different-hash",
            "skip_reason": None,
        }
        result = assess_rule(proposed, index_of(corpus_entry))
        assert result["verdict"] == "SIMILAR"
        assert result["max_similarity"] == pytest.approx(0.5667, abs=1e-4)
        assert result["matches"][0]["containment_factor"] == 0.85
        assert result["matches"][0]["novelty_label"] == "SIMILAR"

    def test_suppression_threshold_is_inclusive_and_fails_open(self):
        # Fail open: inconclusive is never suppressed.
        atom_less = make_rule(detection={"selection": "scalar", "condition": "selection"})
        assert assess_rule(atom_less, index_of())["suppressed"] is False
        # Genuinely novel is below threshold.
        assert assess_rule(make_rule(), index_of())["suppressed"] is False
        # A self-identical corpus entry scores 1.0 >= threshold.
        result = assess_rule(make_rule(), index_of(entry_for(make_rule(id="twin"), rule_id="twin")))
        assert result["suppressed"] is True

    def test_batch_verdicts_are_per_rule(self, tmp_path):
        """One near-duplicate must not suppress its novel siblings."""
        dup = make_rule(id="dup")
        novel = make_rule(
            id="novel",
            detection={"selection": {"Image|endswith": "\\wildly-different.exe"}, "condition": "selection"},
        )
        index = index_of(entry_for(dup, rule_id="dup"))
        verdicts = {
            r["rule_id"]: r["verdict"]
            for r in (assess_rule(dup, index, rule_id="dup"), assess_rule(novel, index, rule_id="novel"))
        }
        assert verdicts["dup"] == "DUPLICATE"
        assert verdicts["novel"] != "DUPLICATE"


# ---------------------------------------------------------------------------
# 19. Soft-exe fallback
# ---------------------------------------------------------------------------


class TestSoftExe:
    def test_cross_field_shared_exe_yields_dampened_nonzero_score(self):
        """Same exe value under different fields: real evidence, but weaker than an
        exact atom match, so the score is halved and flagged."""
        a = ExtractedRule(
            canonical_class="windows.process_creation",
            positive_atoms=("process.image|endswith|/rundll32.exe",),
            negative_atoms=(),
            surface_score=1.0,
        )
        b = ExtractedRule(
            canonical_class="windows.process_creation",
            positive_atoms=("process.command_line|contains|/rundll32.exe",),
            negative_atoms=(),
            surface_score=1.0,
        )
        scored = compare_precomputed(a, b, enable_soft_exe=True)
        assert scored["similarity"] > 0.0
        assert scored["jaccard"] > 0.0
        assert "soft_exe_match" in scored["reason_flags"]

    def test_disabled_soft_exe_scores_zero(self):
        a = ExtractedRule(
            positive_atoms=("process.image|endswith|/rundll32.exe",), negative_atoms=(), surface_score=1.0
        )
        b = ExtractedRule(
            positive_atoms=("process.command_line|contains|/rundll32.exe",), negative_atoms=(), surface_score=1.0
        )
        scored = compare_precomputed(a, b, enable_soft_exe=False)
        assert scored["similarity"] == 0.0
        assert scored["reason_flags"] == ["no_shared_atoms"]

    def test_dampening_factor_is_one_half(self):
        atoms_a = {"process.image|endswith|/vssadmin.exe"}
        atoms_b = {"process.command_line|contains|/vssadmin.exe"}
        union = atoms_a | atoms_b
        assert soft_exe_jaccard(atoms_a, atoms_b, union) == pytest.approx((1 / 2) * 0.5)

    def test_no_shared_exe_value_returns_zero(self):
        assert (
            soft_exe_jaccard(
                {"process.image|endswith|/vssadmin.exe"},
                {"process.image|endswith|/cmd.exe"},
                {"process.image|endswith|/vssadmin.exe", "process.image|endswith|/cmd.exe"},
            )
            == 0.0
        )

    def test_non_process_fields_are_ignored(self):
        atoms_a = {"registrypath|endswith|/run"}
        atoms_b = {"registryvalue|endswith|/run"}
        assert soft_exe_jaccard(atoms_a, atoms_b, atoms_a | atoms_b) == 0.0

    def test_soft_exe_never_fires_when_strict_jaccard_is_nonzero(self):
        shared = ("process.image|endswith|/cmd.exe",)
        scored = compare_precomputed(
            ExtractedRule(positive_atoms=shared, negative_atoms=(), surface_score=1.0),
            ExtractedRule(positive_atoms=shared, negative_atoms=(), surface_score=1.0),
        )
        assert "soft_exe_match" not in scored["reason_flags"]


# ---------------------------------------------------------------------------
# Index construction + skip reasons
# ---------------------------------------------------------------------------


class TestIndex:
    def test_unresolvable_logsource_is_retained_with_skip_reason(self):
        """Persisting the reason per rule is deliberate — Huntable's ADR flags its
        absence as a known gap. A null atom field must stay distinguishable from
        'indexing failed'."""
        entry = entry_for(
            {
                "title": "Weird",
                "logsource": {"product": "plan9", "category": "moon_phase"},
                "detection": {"selection": {"Image": "x"}, "condition": "selection"},
            },
            rule_id="weird",
        )
        assert entry["skip_reason"] == "logsource_unresolved"
        assert entry["positive_atoms"] is None
        assert entry["exact_hash"] is None
        assert entry["canonical_class"] is None

    def test_unsupported_feature_is_retained_with_skip_reason(self):
        entry = entry_for(
            make_rule(detection={"selection": {"Image": "x"}, "condition": "selection | count() > 5"}),
            rule_id="agg",
        )
        assert entry["skip_reason"] == "unsupported_sigma_feature"
        assert entry["positive_atoms"] is None
        # The class resolved fine even though the detection did not.
        assert entry["canonical_class"] == "windows.process_creation"

    def test_relaxed_extraction_scores_unmodeled_logsources(self):
        rule = {
            "title": "Weird",
            "logsource": {"product": "plan9", "category": "moon_phase"},
            "detection": {"selection": {"Image": "x"}, "condition": "selection"},
        }
        assert extract_rule(rule, require_canonical_class=True).skip_reason == "logsource_unresolved"
        relaxed = extract_rule(rule, require_canonical_class=False)
        assert relaxed.extracted
        assert relaxed.canonical_class is None

    def test_build_index_is_deterministic_and_sorted(self, tmp_path):
        rules_dir = write_rules(
            tmp_path,
            {
                "z.yml": make_rule(id="z"),
                "a.yml": make_rule(id="a"),
                "m.yaml": make_rule(id="m"),
            },
        )
        first = build_index(rules_dir)
        second = build_index(rules_dir)
        assert first == second
        assert [r["path"] for r in first["rules"]] == ["a.yml", "m.yaml", "z.yml"]

    def test_unparseable_file_does_not_abort_the_build(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "good.yml").write_text(json.dumps(make_rule()), encoding="utf-8")
        (rules_dir / "bad.yml").write_text("just a bare string", encoding="utf-8")
        index = build_index(rules_dir)
        reasons = {r["path"]: r["skip_reason"] for r in index["rules"]}
        assert reasons["bad.yml"] == "unparseable_yaml"
        assert reasons["good.yml"] is None


# ---------------------------------------------------------------------------
# Display helper (naming trap)
# ---------------------------------------------------------------------------


class TestDisplay:
    @pytest.mark.parametrize(
        "identity, expected",
        [
            ("process.image|endswith|/cmd.exe", "process.image|endswith:/cmd.exe"),
            ("process.image||cmd.exe", "process.image:cmd.exe"),
            ("|contains|<script>", "|contains:<script>"),
            ("process.command_line|contains|all|foo", "process.command_line|contains:foo"),
        ],
    )
    def test_display_never_duplicates_the_operator(self, identity, expected):
        assert atom_identity_to_display(identity) == expected

    def test_containment_and_containment_factor_are_distinct_numbers(self):
        """`containment` is the raw directional ratio; `containment_factor` is the
        4-way bucket. Conflating them was a real Huntable bug."""
        a = ExtractedRule(
            positive_atoms=("f||1", "f||2", "f||3", "f||4"), negative_atoms=(), surface_score=1.0
        )
        b = ExtractedRule(positive_atoms=("f||1", "f||2"), negative_atoms=(), surface_score=8.0)
        scored = compare_precomputed(a, b)
        assert scored["containment"] == scored["overlap_ratio_a"]
        assert scored["containment"] == pytest.approx(0.5)
        assert scored["containment_factor"] == 0.65
