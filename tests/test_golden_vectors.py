"""Golden acceptance vectors (spec §10) and the determinism contract (§12 item 20).

The expected strings below were produced by the live Huntable engine on 2026-08-31.
They are byte-compared, not recomputed — if the engine drifts, these fail.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples"

pytestmark = pytest.mark.unit

RULE1_VS_RULE3 = (
    '{"canonical_class":"windows.process_creation","containment_factor":1.0,'
    '"explanation":{"overlap_ratio_a":1.0,"overlap_ratio_b":1.0,"reason_flags":[]},'
    '"filter_penalty":0.0,"jaccard":1.0,"similarity":1.0,'
    '"surface_score_a":8.0,"surface_score_b":8.0}'
)

RULE1_VS_RULE2 = (
    '{"canonical_class":"windows.process_creation","containment_factor":0.65,'
    '"explanation":{"overlap_ratio_a":0.5,"overlap_ratio_b":0.5,"reason_flags":[]},'
    '"filter_penalty":0.3333333333333333,"jaccard":0.3333333333333333,"similarity":0.0,'
    '"surface_score_a":8.0,"surface_score_b":8.0}'
)

# rule2 vs rule3 is byte-identical to rule1 vs rule2.
RULE2_VS_RULE3 = RULE1_VS_RULE2


def run_cli(*args: str, env: dict[str, str] | None = None) -> str:
    """Invoke the CLI in a subprocess and return stdout."""
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "cli.py"), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={**os.environ, **(env or {})},
        check=True,
    )
    return proc.stdout.strip()


@pytest.mark.parametrize(
    "rule_a, rule_b, expected",
    [
        ("rule1.yaml", "rule3.yaml", RULE1_VS_RULE3),
        ("rule1.yaml", "rule2.yaml", RULE1_VS_RULE2),
        ("rule2.yaml", "rule3.yaml", RULE2_VS_RULE3),
    ],
)
def test_golden_vectors_byte_for_byte(rule_a, rule_b, expected):
    assert run_cli("compare", str(EXAMPLES / rule_a), str(EXAMPLES / rule_b)) == expected


@pytest.mark.parametrize(
    "rule_a, rule_b, expected",
    [
        ("rule1.yaml", "rule3.yaml", RULE1_VS_RULE3),
        ("rule1.yaml", "rule2.yaml", RULE1_VS_RULE2),
    ],
)
def test_golden_vectors_parse_equal(rule_a, rule_b, expected):
    """Same assertion after json.loads, so a key-order regression is distinguishable
    from a value regression."""
    actual = json.loads(run_cli("compare", str(EXAMPLES / rule_a), str(EXAMPLES / rule_b)))
    assert actual == json.loads(expected)


def test_bare_two_arg_form_is_back_compatible():
    """`sigma-similarity <a> <b>` with no subcommand still runs compare."""
    assert run_cli(str(EXAMPLES / "rule1.yaml"), str(EXAMPLES / "rule3.yaml")) == RULE1_VS_RULE3


def test_module_entrypoint_matches_cli():
    proc = subprocess.run(
        [sys.executable, "-m", "sigma_similarity", str(EXAMPLES / "rule1.yaml"), str(EXAMPLES / "rule3.yaml")],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=True,
    )
    assert proc.stdout.strip() == RULE1_VS_RULE3


class TestDeterminism:
    def test_repeated_runs_are_identical(self):
        first = run_cli("compare", str(EXAMPLES / "rule1.yaml"), str(EXAMPLES / "rule2.yaml"))
        second = run_cli("compare", str(EXAMPLES / "rule1.yaml"), str(EXAMPLES / "rule2.yaml"))
        assert first == second

    @pytest.mark.parametrize("seed", ["0", "1", "42", "12345"])
    def test_output_is_stable_across_python_hash_seeds(self, seed):
        """Set iteration order must never leak into output."""
        assert (
            run_cli(
                "compare",
                str(EXAMPLES / "rule1.yaml"),
                str(EXAMPLES / "rule2.yaml"),
                env={"PYTHONHASHSEED": seed},
            )
            == RULE1_VS_RULE2
        )

    @pytest.mark.parametrize("seed", ["0", "1", "42"])
    def test_index_is_stable_across_python_hash_seeds(self, seed):
        assert run_cli("index", str(EXAMPLES), env={"PYTHONHASHSEED": seed}) == run_cli(
            "index", str(EXAMPLES), env={"PYTHONHASHSEED": "0"}
        )


class TestIndexAssessRoundTrip:
    def test_round_trip_over_the_examples_corpus(self, tmp_path):
        corpus = tmp_path / "corpus.json"
        run_cli("index", str(EXAMPLES), "-o", str(corpus))
        index = json.loads(corpus.read_text())

        assert index["index_version"] == "1"
        assert len(index["rules"]) == 3
        assert all(r["canonical_class"] == "windows.process_creation" for r in index["rules"])
        assert all(r["skip_reason"] is None for r in index["rules"])

        # rule1 and rule3 are behaviorally identical, so they share an exact hash.
        hashes = {r["rule_id"]: r["exact_hash"] for r in index["rules"]}
        by_path = {r["path"]: r["exact_hash"] for r in index["rules"]}
        assert by_path["rule1.yaml"] == by_path["rule3.yaml"]
        assert by_path["rule1.yaml"] != by_path["rule2.yaml"]
        assert all(h is not None for h in hashes.values())

        out = json.loads(
            run_cli("assess", str(EXAMPLES / "rule1.yaml"), "--corpus", str(corpus), "--rules-dir", str(EXAMPLES))
        )
        # rule1 is itself in the corpus, so it is legitimately a duplicate of itself.
        assert out["verdict"] == "DUPLICATE"
        assert out["matches"][0]["exact_hash_match"] is True

    def test_batch_assess_emits_one_verdict_per_rule(self, tmp_path):
        corpus = tmp_path / "corpus.json"
        run_cli("index", str(EXAMPLES), "-o", str(corpus))
        results = json.loads(
            run_cli("assess", "--batch", str(EXAMPLES), "--corpus", str(corpus), "--rules-dir", str(EXAMPLES))
        )
        assert len(results) == 3
        assert {r["verdict"] for r in results} == {"DUPLICATE"}
        assert len({r["rule_id"] for r in results}) == 3
