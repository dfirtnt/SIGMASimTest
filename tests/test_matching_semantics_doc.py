"""Executable contract for docs/matching-semantics.md.

That page makes promises to detection engineers about what the engine will and will not
merge — specifically that attacker misspellings, homoglyphs and case-anomaly hunts survive
as distinct atoms. Those promises are load-bearing: a future "helpful" normalization (fuzzy
matching, stemming, character folding) would silently invalidate the page while every other
test still passed.

Each assertion here corresponds to a row or claim in that document. If one fails, the
document is wrong and must be updated with the code.
"""

from __future__ import annotations

import pytest

from sigma_similarity.novelty import extract_rule

pytestmark = [pytest.mark.unit, pytest.mark.regression]


def atom(selection: dict) -> str:
    """The single atom identity produced by a one-predicate process_creation rule."""
    rule = {
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": selection, "condition": "selection"},
    }
    atoms = extract_rule(rule).positive_atoms
    assert len(atoms) == 1, atoms
    return atoms[0]


# ---------------------------------------------------------------------------
# "Nothing is fuzzy"
# ---------------------------------------------------------------------------


class TestNothingIsFuzzy:
    """Attacker-introduced string variation is signal and must never be normalized away."""

    def test_misspelling_stays_distinct(self):
        assert atom({"CommandLine|contains": "Invoke-WebRequst"}) != atom(
            {"CommandLine|contains": "Invoke-WebRequest"}
        )

    def test_homoglyph_binary_stays_distinct(self):
        """rund1l32.exe (digit one) vs rundll32.exe (letter L)."""
        assert atom({"Image|endswith": "\\rund1l32.exe"}) != atom({"Image|endswith": "\\rundll32.exe"})

    @pytest.mark.parametrize(
        "a, b",
        [
            ("powershell.exe", "powershel.exe"),  # dropped character
            ("powershell.exe", "powershelll.exe"),  # doubled character
            ("powershell.exe", "poweshell.exe"),  # transposition
            ("svchost.exe", "svch0st.exe"),  # digit substitution
            ("lsass.exe", "1sass.exe"),  # leading substitution
        ],
    )
    def test_near_miss_values_are_never_merged(self, a, b):
        """One edit apart is exactly where a fuzzy matcher would wrongly collapse them."""
        assert atom({"Image|endswith": f"\\{a}"}) != atom({"Image|endswith": f"\\{b}"})

    def test_substring_is_not_equality(self):
        assert atom({"CommandLine|contains": "mimikatz"}) != atom({"CommandLine|contains": "mimikatz.exe"})

    def test_word_order_is_not_normalized(self):
        assert atom({"CommandLine|contains": "delete shadows"}) != atom(
            {"CommandLine|contains": "shadows delete"}
        )


# ---------------------------------------------------------------------------
# "Case: folded only where the matcher already ignores it"
# ---------------------------------------------------------------------------


class TestCaseFolding:
    @pytest.mark.parametrize("op", ["contains", "endswith", "startswith"])
    def test_default_operators_fold_because_sigma_matches_case_insensitively(self, op):
        """Both spellings deploy to the same matcher behavior, so they are true duplicates."""
        assert atom({f"CommandLine|{op}": "Mimikatz"}) == atom({f"CommandLine|{op}": "mimikatz"})

    def test_bare_eq_folds(self):
        assert atom({"CommandLine": "Mimikatz"}) == atom({"CommandLine": "mimikatz"})

    def test_cased_preserves_case_anomaly_hunts(self):
        assert atom({"CommandLine|contains|cased": "MiMiKaTz"}) != atom(
            {"CommandLine|contains|cased": "mimikatz"}
        )

    def test_cased_never_collapses_into_its_case_insensitive_sibling(self):
        """The headline claim: hunting ONE capitalization is a narrower hunt than
        accepting any capitalization, even for an identical literal."""
        cased = atom({"CommandLine|contains|cased": "Mimikatz"})
        uncased = atom({"CommandLine|contains": "Mimikatz"})
        assert cased != uncased
        assert cased == "process.command_line|contains|cased|Mimikatz"
        assert uncased == "process.command_line|contains|mimikatz"

    def test_regex_always_preserves_case(self):
        assert atom({"CommandLine|re": "Invoke-[Ww]eb"}) == "process.command_line|re|Invoke-[Ww]eb"
        assert atom({"CommandLine|re": "Invoke-[Ww]eb"}) != atom({"CommandLine|re": "invoke-[ww]eb"})


# ---------------------------------------------------------------------------
# Normalization inventory — the documented table, row by row
# ---------------------------------------------------------------------------


class TestDocumentedNormalizationInventory:
    def test_path_separator_is_canonicalized(self):
        assert atom({"Image|endswith": "\\powershell.exe"}) == atom({"Image|endswith": "/powershell.exe"})

    def test_edge_wildcard_folds_to_the_equivalent_modifier(self):
        assert atom({"CommandLine": "*foo*"}) == atom({"CommandLine|contains": "foo"})

    def test_internal_wildcards_are_left_alone(self):
        assert atom({"CommandLine": "foo*bar"}) != atom({"CommandLine|contains": "foobar"})

    def test_field_aliases_are_a_lookup_not_an_inference(self):
        canonical = atom({"CommandLine|contains": "whoami"})
        assert atom({"ProcessCommandLine|contains": "whoami"}) == canonical
        assert atom({"command_line|contains": "whoami"}) == canonical
        # An unknown field lowercases as-is rather than being guessed at.
        assert atom({"TotallyUnknownField|contains": "whoami"}) == "totallyunknownfield|contains|whoami"

    def test_a_basename_is_not_treated_as_a_path(self):
        """Documented explicitly as NOT normalized: no semantic field/value equivalence."""
        assert atom({"Image": "powershell.exe"}) != atom({"Image|endswith": "\\powershell.exe"})

    def test_whitespace_is_stripped(self):
        assert atom({"CommandLine|contains": "  whoami  "}) == atom({"CommandLine|contains": "whoami"})
