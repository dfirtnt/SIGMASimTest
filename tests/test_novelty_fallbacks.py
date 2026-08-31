"""Novelty-layer paths not exercised by the main suite.

Focus: the live candidate re-extraction fallback (spec §8.3), index-time skip reasons
that only a pathological rule can reach, and the assess_rule result contract
(top-10 cap, deterministic ordering, filter penalty, 4dp rounding).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from sigma_similarity.novelty import (
    ExtractedRule,
    _candidate_extracted,
    _extract_exe_value,
    assess_rule,
    atom_identity_to_display,
    build_index_entry,
    compare_precomputed,
    extract_rule,
    soft_exe_jaccard,
)

pytestmark = pytest.mark.unit


def make_rule(**overrides) -> dict:
    rule = {
        "title": "Test",
        "id": "rule-a",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
    }
    rule.update(overrides)
    return rule


def index_of(*entries: dict) -> dict:
    return {"index_version": "1", "engine_version": "2.0", "rules": list(entries)}


#: A rule on a logsource the registry does not model. Index-time extraction is strict,
#: so it stores null atoms — the exact shape that forces the live-extraction fallback.
UNMODELED_RULE = {
    "title": "Unmodeled",
    "id": "unmodeled",
    "logsource": {"product": "plan9", "category": "moon_phase"},
    "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
}


# ---------------------------------------------------------------------------
# §8.3 live candidate re-extraction
# ---------------------------------------------------------------------------


class TestLiveCandidateReExtraction:
    """A candidate stored with null atoms is re-extracted from disk with a RELAXED
    class requirement, so rules on unmodeled logsources still get scored instead of
    silently dropping out of the comparison."""

    @pytest.fixture
    def unmodeled_corpus(self, tmp_path: Path) -> tuple[dict, Path]:
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "unmodeled.yml").write_text(yaml.safe_dump(UNMODELED_RULE), encoding="utf-8")
        entry = build_index_entry(UNMODELED_RULE, rule_id="unmodeled", path="unmodeled.yml")
        # Precondition: strict index-time extraction really did skip it.
        assert entry["skip_reason"] == "logsource_unresolved"
        assert entry["positive_atoms"] is None
        return entry, rules_dir

    def test_stored_null_atoms_are_re_extracted_live(self, unmodeled_corpus):
        entry, rules_dir = unmodeled_corpus
        live = _candidate_extracted(entry, rules_dir)
        assert live is not None
        assert live.extracted
        assert live.positive_atoms == ("process.image|endswith|/cmd.exe",)
        # Relaxed means the class stays unresolved rather than raising.
        assert live.canonical_class is None

    def test_re_extracted_candidate_is_actually_scored(self, unmodeled_corpus):
        """End-to-end: the fallback must feed a real similarity, not a zero."""
        entry, rules_dir = unmodeled_corpus
        proposed = dict(UNMODELED_RULE, id="proposed", title="Proposed")
        result = assess_rule(proposed, index_of(entry), base_dir=rules_dir)
        assert result["candidates_evaluated"] == 1
        assert result["behavioral_matches"] == 1
        assert result["matches"][0]["similarity"] > 0.0
        assert result["matches"][0]["phase1_path"] == "logsource_fallback"

    def test_without_base_dir_the_candidate_is_skipped_not_zero_scored(self, unmodeled_corpus):
        """Skipping keeps the rule inconclusive; scoring it 0.0 would falsely read as
        'compared and found unrelated'."""
        entry, _ = unmodeled_corpus
        assert _candidate_extracted(entry, None) is None

        proposed = dict(UNMODELED_RULE, id="proposed")
        result = assess_rule(proposed, index_of(entry), base_dir=None)
        assert result["candidates_evaluated"] == 0
        assert result["matches"] == []

    def test_missing_file_is_skipped(self, tmp_path):
        entry = build_index_entry(UNMODELED_RULE, rule_id="gone", path="gone.yml")
        assert _candidate_extracted(entry, tmp_path) is None

    def test_entry_without_a_path_is_skipped(self, tmp_path):
        entry = build_index_entry(UNMODELED_RULE, rule_id="nopath", path="")
        assert _candidate_extracted(entry, tmp_path) is None

    def test_unparseable_candidate_file_is_skipped(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "bad.yml").write_text("[not, a, mapping]", encoding="utf-8")
        entry = build_index_entry(UNMODELED_RULE, rule_id="bad", path="bad.yml")
        assert _candidate_extracted(entry, rules_dir) is None

    def test_candidate_that_is_still_unextractable_live_is_skipped(self, tmp_path):
        """Relaxing the class requirement does not rescue a rule whose *detection*
        is the problem."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        broken = dict(UNMODELED_RULE, detection={"selection": "bare-scalar", "condition": "selection"})
        (rules_dir / "broken.yml").write_text(yaml.safe_dump(broken), encoding="utf-8")
        entry = build_index_entry(broken, rule_id="broken", path="broken.yml")
        assert _candidate_extracted(entry, rules_dir) is None

    def test_stored_atoms_win_over_live_extraction(self, tmp_path):
        """When atoms are already stored, disk is never consulted — so a corpus stays
        usable even if the original rule files have moved."""
        entry = build_index_entry(make_rule(), rule_id="stored", path="does-not-exist.yml")
        assert entry["positive_atoms"] is not None
        live = _candidate_extracted(entry, tmp_path / "nowhere")
        assert live is not None
        assert live.positive_atoms == tuple(entry["positive_atoms"])


# ---------------------------------------------------------------------------
# Index-time skip reasons
# ---------------------------------------------------------------------------


class TestDnfExpansionSkipReason:
    def test_expansion_limit_is_recorded_not_raised(self):
        """65 OR'd selections blow the 64-branch cap. Index-time this must degrade to
        a skip reason, keeping the rule in the corpus with null atoms."""
        detection = {"condition": " or ".join(f"sel{i}" for i in range(65))}
        for i in range(65):
            detection[f"sel{i}"] = {"Image": f"x{i}.exe"}
        rule = make_rule(id="explode", detection=detection)

        extracted = extract_rule(rule)
        assert extracted.skip_reason == "dnf_expansion_limit"
        assert extracted.positive_atoms is None
        # The class resolved fine; only the detection was too broad.
        assert extracted.canonical_class == "windows.process_creation"

        entry = build_index_entry(rule, rule_id="explode", path="explode.yml")
        assert entry["skip_reason"] == "dnf_expansion_limit"
        assert entry["exact_hash"] is None


# ---------------------------------------------------------------------------
# assess_rule result contract
# ---------------------------------------------------------------------------


def _synthetic_entry(rule_id: str, atoms: list[str], surface: int = 4) -> dict:
    return {
        "rule_id": rule_id,
        "title": f"Corpus {rule_id}",
        "canonical_class": "windows.process_creation",
        "logsource_key": "windows|process_creation",
        "positive_atoms": atoms,
        "negative_atoms": [],
        "surface_score": surface,
        "exact_hash": f"hash-{rule_id}",
        "skip_reason": None,
    }


class TestAssessResultContract:
    @pytest.fixture
    def proposed_four_atoms(self) -> dict:
        return make_rule(
            id="proposed",
            detection={
                "selection": {"CommandLine|contains": ["aa", "bb", "cc", "dd"]},
                "condition": "selection",
            },
        )

    def test_matches_are_capped_at_ten(self, proposed_four_atoms):
        entries = [
            _synthetic_entry(f"c{i:02d}", [f"process.command_line|contains|{v}" for v in ("aa", "bb", "cc")])
            for i in range(25)
        ]
        result = assess_rule(proposed_four_atoms, index_of(*entries))
        assert result["candidates_evaluated"] == 25
        assert len(result["matches"]) == 10

    def test_tied_matches_are_ordered_deterministically_by_rule_id(self, proposed_four_atoms):
        """Equal similarities must not depend on index order."""
        atoms = [f"process.command_line|contains|{v}" for v in ("aa", "bb", "cc")]
        entries = [_synthetic_entry(f"c{i:02d}", list(atoms)) for i in range(6)]

        forward = assess_rule(proposed_four_atoms, index_of(*entries))
        reverse = assess_rule(proposed_four_atoms, index_of(*reversed(entries)))

        ids = [m["rule_id"] for m in forward["matches"]]
        assert ids == sorted(ids)
        assert ids == [m["rule_id"] for m in reverse["matches"]]
        assert len({m["similarity"] for m in forward["matches"]}) == 1

    def test_floats_are_rounded_to_four_places(self, proposed_four_atoms):
        """Spec §9: the assess shape carries Huntable's serializer precision."""
        entry = _synthetic_entry(
            "c1", [f"process.command_line|contains|{v}" for v in ("aa", "bb", "cc", "dd", "ee", "ff", "gg")], surface=7
        )
        result = assess_rule(proposed_four_atoms, index_of(entry))
        match = result["matches"][0]
        # 4/7 is a repeating decimal, so rounding is observable.
        assert match["jaccard"] == pytest.approx(0.5714, abs=1e-9)
        for field in ("similarity", "jaccard", "containment", "containment_factor", "overlap_ratio_a"):
            assert len(str(match[field]).split(".")[-1]) <= 4, field
        assert result["max_similarity"] == round(result["max_similarity"], 4)

    def test_surface_scores_are_emitted_as_ints(self, proposed_four_atoms):
        result = assess_rule(proposed_four_atoms, index_of(_synthetic_entry("c1", ["process.command_line|contains|aa"])))
        match = result["matches"][0]
        assert isinstance(match["surface_score_a"], int)
        assert isinstance(match["surface_score_b"], int)

    def test_result_is_json_serializable(self, proposed_four_atoms):
        result = assess_rule(proposed_four_atoms, index_of(_synthetic_entry("c1", ["process.command_line|contains|aa"])))
        assert json.loads(json.dumps(result, sort_keys=True)) == result


class TestFilterPenaltyThroughNoveltyPath:
    def test_divergent_filters_reduce_similarity_and_are_reported(self):
        """Filters never enter positive Jaccard and can only ever subtract."""
        shared = ("f||1", "f||2", "f||3", "f||4")
        without = compare_precomputed(
            ExtractedRule(positive_atoms=shared, negative_atoms=(), surface_score=1.0),
            ExtractedRule(positive_atoms=shared, negative_atoms=(), surface_score=1.0),
        )
        with_filters = compare_precomputed(
            ExtractedRule(positive_atoms=shared, negative_atoms=("f||excl_a",), surface_score=1.0),
            ExtractedRule(positive_atoms=shared, negative_atoms=("f||excl_b",), surface_score=1.0),
        )
        assert without["filter_penalty"] == 0.0
        assert with_filters["filter_penalty"] == pytest.approx(0.5)
        assert with_filters["similarity"] < without["similarity"]
        assert with_filters["jaccard"] == without["jaccard"]  # filters stay out of Jaccard
        assert with_filters["filter_differences"] == ["f||excl_a", "f||excl_b"]

    def test_identical_filters_incur_no_penalty(self):
        shared = ("f||1", "f||2")
        scored = compare_precomputed(
            ExtractedRule(positive_atoms=shared, negative_atoms=("f||same",), surface_score=1.0),
            ExtractedRule(positive_atoms=shared, negative_atoms=("f||same",), surface_score=1.0),
        )
        assert scored["filter_penalty"] == 0.0
        assert scored["filter_differences"] == []


# ---------------------------------------------------------------------------
# Malformed-input guards
# ---------------------------------------------------------------------------


class TestMalformedIdentityGuards:
    @pytest.mark.parametrize("atom_id", ["", "justafield", "field|value"])
    def test_extract_exe_value_rejects_non_three_slot_identities(self, atom_id):
        assert _extract_exe_value(atom_id) is None

    def test_soft_exe_with_empty_union_is_zero(self):
        assert soft_exe_jaccard(set(), set(), set()) == 0.0

    @pytest.mark.parametrize("atom_id", ["", "justafield"])
    def test_display_passes_through_degenerate_identities(self, atom_id):
        assert atom_identity_to_display(atom_id) == atom_id
