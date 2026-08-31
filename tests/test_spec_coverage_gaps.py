"""Spec §12 behaviors not covered by the ported Huntable corpus.

Covers: list-of-maps selections (#6), the remaining condition grammar (#9),
and full registry resolvability (#14).
"""

from __future__ import annotations

import pytest

from sigma_similarity.ast_builder import build_ast
from sigma_similarity.atom_extractor import extract_negative_atoms, extract_positive_atoms
from sigma_similarity.canonical_logsource import CANONICAL_CLASS_REGISTRY, resolve_canonical_class
from sigma_similarity.detection_normalizer import normalize_detection
from sigma_similarity.dnf_normalizer import ast_to_dnf
from sigma_similarity.errors import UnsupportedSigmaFeatureError

pytestmark = pytest.mark.unit


def dnf_of(detection: dict):
    return ast_to_dnf(build_ast(normalize_detection(detection)))


def atoms_of(detection: dict) -> set[str]:
    return extract_positive_atoms(dnf_of(detection))


# ---------------------------------------------------------------------------
# 6. List-of-maps selections
# ---------------------------------------------------------------------------


class TestListOfMapsSelection:
    """A list of maps is an OR of blocks, not one merged block.

    Mishandling this shape caused the exact-hash false-duplicate flood — 84 unrelated
    rules on a single hash — so the branch structure is asserted, not just the atoms.
    """

    def test_list_of_maps_produces_one_branch_per_map(self):
        detection = {
            "selection": [
                {"Image|endswith": "\\cmd.exe"},
                {"Image|endswith": "\\powershell.exe"},
            ],
            "condition": "selection",
        }
        branches = dnf_of(detection)
        assert len(branches) == 2
        assert atoms_of(detection) == {
            "process.image|endswith|/cmd.exe",
            "process.image|endswith|/powershell.exe",
        }

    def test_list_of_maps_is_not_merged_into_one_and_block(self):
        """If the maps were merged, the two fields would land in a single AND branch."""
        or_form = {
            "selection": [{"Image|endswith": "\\cmd.exe"}, {"CommandLine|contains": "whoami"}],
            "condition": "selection",
        }
        and_form = {
            "selection": {"Image|endswith": "\\cmd.exe", "CommandLine|contains": "whoami"},
            "condition": "selection",
        }
        assert atoms_of(or_form) == atoms_of(and_form)  # same atoms...
        assert len(dnf_of(or_form)) == 2  # ...but different logical shape
        assert len(dnf_of(and_form)) == 1

    def test_multi_key_maps_in_a_list_keep_their_and_grouping(self):
        detection = {
            "selection": [
                {"Image|endswith": "\\cmd.exe", "CommandLine|contains": "whoami"},
                {"Image|endswith": "\\powershell.exe"},
            ],
            "condition": "selection",
        }
        branches = dnf_of(detection)
        assert len(branches) == 2
        assert sorted(len(b) for b in branches) == [1, 2]

    def test_surface_score_differs_between_or_and_and_forms(self):
        """Surface is the rule's logical breadth; the two shapes must not tie."""
        from sigma_similarity.surface_estimator import surface_score_from_dnf

        or_form = surface_score_from_dnf(
            dnf_of({"selection": [{"Image": "a.exe"}, {"Image": "b.exe"}], "condition": "selection"})
        )
        and_form = surface_score_from_dnf(
            dnf_of({"selection": {"Image": "a.exe", "CommandLine": "b"}, "condition": "selection"})
        )
        assert or_form == 2.0
        assert and_form == 1.0


# ---------------------------------------------------------------------------
# 9. Condition grammar
# ---------------------------------------------------------------------------


class TestConditionGrammar:
    def test_one_of_wildcard_is_an_or(self):
        detection = {
            "selection_a": {"Image|endswith": "\\a.exe"},
            "selection_b": {"Image|endswith": "\\b.exe"},
            "condition": "1 of selection_*",
        }
        assert len(dnf_of(detection)) == 2
        assert atoms_of(detection) == {"process.image|endswith|/a.exe", "process.image|endswith|/b.exe"}

    def test_all_of_wildcard_is_an_and(self):
        detection = {
            "selection_a": {"Image|endswith": "\\a.exe"},
            "selection_b": {"CommandLine|contains": "whoami"},
            "condition": "all of selection_*",
        }
        branches = dnf_of(detection)
        assert len(branches) == 1
        assert len(branches[0]) == 2

    def test_parentheses_group_against_precedence(self):
        """(a or b) and c must expand to two branches, not bind as a or (b and c)."""
        detection = {
            "a": {"Image|endswith": "\\a.exe"},
            "b": {"Image|endswith": "\\b.exe"},
            "c": {"CommandLine|contains": "whoami"},
            "condition": "(a or b) and c",
        }
        branches = dnf_of(detection)
        assert len(branches) == 2
        assert all(len(branch) == 2 for branch in branches)

    def test_not_of_a_conjunction_becomes_two_branches(self):
        """NOT(AND(a,b)) -> OR(NOT a, NOT b)."""
        detection = {
            "sel": {"Image|endswith": "\\cmd.exe"},
            "filter": {"CommandLine|contains": "safe", "ParentImage|endswith": "\\explorer.exe"},
            "condition": "sel and not filter",
        }
        branches = dnf_of(detection)
        assert len(branches) == 2
        negatives = extract_negative_atoms(branches)
        assert negatives == {
            "process.command_line|contains|safe",
            "process.parent_image|endswith|/explorer.exe",
        }

    def test_not_over_a_nested_group_is_parsed(self):
        """NOT(OR(b,c)) -> AND(NOT b, NOT c): one branch, both filters negated."""
        detection = {
            "sel": {"Image|endswith": "\\cmd.exe"},
            "b": {"CommandLine|contains": "x"},
            "c": {"CommandLine|contains": "y"},
            "condition": "sel and not (b or c)",
        }
        branches = dnf_of(detection)
        assert len(branches) == 1
        assert extract_positive_atoms(branches) == {"process.image|endswith|/cmd.exe"}
        assert extract_negative_atoms(branches) == {
            "process.command_line|contains|x",
            "process.command_line|contains|y",
        }

    def test_double_negation_is_unsupported_but_fails_loudly(self):
        """KNOWN LIMITATION, faithful to the Huntable engine: the DNF normalizer
        handles NOT(atom), NOT(AND) and NOT(OR) but not NOT(NOT(...)), which
        collapses the branch list to empty.

        This is safe because it fails loudly rather than silently scoring against a
        truncated atom set: the empty-DNF guard raises, and the novelty layer turns
        that into skip_reason='unsupported_sigma_feature' -> NEEDS_REVIEW.
        """
        from sigma_similarity.novelty import extract_rule
        from sigma_similarity.surface_estimator import surface_score_from_dnf

        detection = {
            "sel": {"Image|endswith": "\\cmd.exe"},
            "filter": {"CommandLine|contains": "safe"},
            "condition": "sel and not (not filter)",
        }
        assert dnf_of(detection) == []
        with pytest.raises(UnsupportedSigmaFeatureError):
            surface_score_from_dnf(dnf_of(detection))

        extracted = extract_rule(
            {
                "logsource": {"product": "windows", "category": "process_creation"},
                "detection": detection,
            }
        )
        assert extracted.skip_reason == "unsupported_sigma_feature"
        assert extracted.positive_atoms is None

    def test_polarity_comes_from_the_ast_not_the_selection_name(self):
        """A 'filter'-named selection referenced positively is positive."""
        detection = {
            "selection": {"Image|endswith": "\\cmd.exe"},
            "filter": {"CommandLine|contains": "whoami"},
            "condition": "selection and filter",
        }
        branches = dnf_of(detection)
        assert extract_negative_atoms(branches) == set()
        assert "process.command_line|contains|whoami" in extract_positive_atoms(branches)

    def test_all_not_branch_contributes_nothing(self):
        """The engine cannot reason about a naked NOT under OR."""
        detection = {"filter": {"Image|endswith": "\\cmd.exe"}, "condition": "not filter"}
        branches = dnf_of(detection)
        assert extract_positive_atoms(branches) == set()
        assert extract_negative_atoms(branches) == set()

    def test_unknown_selection_reference_raises(self):
        with pytest.raises(UnsupportedSigmaFeatureError):
            normalize_detection({"selection": {"Image": "x"}, "condition": "nonexistent"})

    def test_unresolvable_wildcard_raises(self):
        with pytest.raises(UnsupportedSigmaFeatureError):
            normalize_detection({"selection": {"Image": "x"}, "condition": "all of nomatch_*"})

    @pytest.mark.parametrize(
        "condition",
        [
            "selection | count() > 5",
            "selection near selection2",
            "temporal(selection, selection2)",
            "selection | aggregation",
            "sequence of selection",
        ],
    )
    def test_rejected_features_raise(self, condition):
        with pytest.raises(UnsupportedSigmaFeatureError):
            normalize_detection({"selection": {"Image": "x"}, "selection2": {"Image": "y"}, "condition": condition})

    def test_missing_condition_raises(self):
        with pytest.raises(UnsupportedSigmaFeatureError):
            normalize_detection({"selection": {"Image": "x"}})

    def test_list_valued_condition_raises(self):
        with pytest.raises(UnsupportedSigmaFeatureError):
            normalize_detection({"selection": {"Image": "x"}, "condition": ["selection", "selection"]})

    def test_trailing_tokens_raise(self):
        with pytest.raises(UnsupportedSigmaFeatureError):
            normalize_detection({"selection": {"Image": "x"}, "condition": "selection selection"})


# ---------------------------------------------------------------------------
# 14. Registry resolvability
# ---------------------------------------------------------------------------


def _rule_from_tuple(product, category, service, event_id) -> dict:
    logsource = {}
    if product is not None:
        logsource["product"] = product
    if category is not None:
        logsource["category"] = category
    if service is not None:
        logsource["service"] = service
    selection = {"Image": "x.exe"}
    if event_id is not None:
        selection["EventID"] = event_id
    return {"logsource": logsource, "detection": {"selection": selection, "condition": "selection"}}


class TestRegistryResolvability:
    @pytest.mark.parametrize(
        "class_name, source_tuple",
        [(name, t) for name, tuples in CANONICAL_CLASS_REGISTRY.items() for t in sorted(tuples, key=str)],
    )
    def test_every_registry_tuple_resolves_to_its_own_class(self, class_name, source_tuple):
        assert resolve_canonical_class(_rule_from_tuple(*source_tuple)) == class_name

    def test_event_code_resolves_like_event_id(self):
        """Splunk-backend rules emit EventCode rather than EventID."""
        by_id = {
            "logsource": {"product": "windows", "service": "sysmon"},
            "detection": {"selection": {"EventID": 22, "Image": "x"}, "condition": "selection"},
        }
        by_code = {
            "logsource": {"product": "windows", "service": "sysmon"},
            "detection": {"selection": {"EventCode": 22, "Image": "x"}, "condition": "selection"},
        }
        assert resolve_canonical_class(by_id) == resolve_canonical_class(by_code) == "windows.dns_query"

    def test_registry_categories_are_consolidated_into_one_class(self):
        """registry_set / _add / _delete share Sysmon EIDs 12-14 and the TargetObject
        field, so they are deliberately ONE class."""
        classes = {
            resolve_canonical_class(
                {
                    "logsource": {"product": "windows", "category": category},
                    "detection": {"selection": {"TargetObject": "x"}, "condition": "selection"},
                }
            )
            for category in ("registry_event", "registry_set", "registry_add", "registry_delete")
        }
        assert classes == {"windows.registry_event"}

    def test_powershell_channels_stay_split(self):
        """4104 / 4103 / 400 differ in EID *and* field, so they must not merge."""
        classes = {
            resolve_canonical_class(
                {
                    "logsource": {"product": "windows", "service": service},
                    "detection": {"selection": {"EventID": eid, "Image": "x"}, "condition": "selection"},
                }
            )
            for service, eid in (("powershell", 4104), ("powershell", 4103), ("powershell-classic", 400))
        }
        assert classes == {"windows.ps_script", "windows.ps_module", "windows.ps_classic_start"}
