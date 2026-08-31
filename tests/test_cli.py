"""CLI contract: argument wiring, flag plumbing, and exit codes.

The golden-vector suite drives the CLI as a subprocess to prove the real entry point;
these run main() in-process so flag plumbing and error branches are actually observable.

Exit codes: 0 structured result; 1 file/parse errors and unrecoverable engine errors;
2 usage. DeterministicExpansionLimitError must never escape as a non-zero exit.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import cli

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples"


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def write_rule(path: Path, rule: dict) -> None:
    path.write_text(yaml.safe_dump(rule), encoding="utf-8")


def process_creation(rule_id: str, *, image: str = "\\cmd.exe", **extra) -> dict:
    rule = {
        "title": f"Rule {rule_id}",
        "id": rule_id,
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"Image|endswith": image}, "condition": "selection"},
    }
    rule.update(extra)
    return rule


@pytest.fixture
def corpus(tmp_path: Path, capsys) -> tuple[Path, Path]:
    """A three-rule corpus plus its written index."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    write_rule(rules_dir / "a.yml", process_creation("corpus-a", image="\\certutil.exe"))
    write_rule(rules_dir / "b.yml", process_creation("corpus-b", image="\\rundll32.exe"))
    write_rule(rules_dir / "c.yml", process_creation("corpus-c", image="\\wmic.exe"))
    index_path = tmp_path / "corpus.json"
    assert run(capsys, "index", str(rules_dir), "-o", str(index_path))[0] == 0
    return rules_dir, index_path


# ---------------------------------------------------------------------------
# Usage and error exits
# ---------------------------------------------------------------------------


class TestExitCodes:
    def test_compare_success_is_zero(self, capsys):
        code, out, _ = run(capsys, "compare", str(EXAMPLES / "rule1.yaml"), str(EXAMPLES / "rule2.yaml"))
        assert code == 0
        assert json.loads(out)["canonical_class"] == "windows.process_creation"

    def test_missing_rule_file_is_one(self, capsys):
        code, _, err = run(capsys, "compare", "nope.yaml", str(EXAMPLES / "rule1.yaml"))
        assert code == 1
        assert "File not found" in err

    def test_unparseable_rule_is_one(self, capsys, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("- not\n- a mapping\n", encoding="utf-8")
        code, _, err = run(capsys, "compare", str(bad), str(EXAMPLES / "rule1.yaml"))
        assert code == 1
        assert "Parse error" in err

    def test_unknown_telemetry_class_is_one(self, capsys, tmp_path):
        unmodeled = tmp_path / "unmodeled.yaml"
        write_rule(unmodeled, {**process_creation("u"), "logsource": {"product": "plan9", "category": "moon"}})
        code, _, err = run(capsys, "compare", str(unmodeled), str(EXAMPLES / "rule1.yaml"))
        assert code == 1
        assert "canonical class" in err.lower()

    def test_dnf_expansion_limit_never_escapes_as_an_error(self, capsys, tmp_path):
        """It must come back as a result carrying the flag, not a non-zero exit."""
        detection = {"condition": " or ".join(f"sel{i}" for i in range(65))}
        for i in range(65):
            detection[f"sel{i}"] = {"Image": f"x{i}.exe"}
        explode = tmp_path / "explode.yaml"
        write_rule(explode, process_creation("explode", detection=detection))

        code, out, _ = run(capsys, "compare", str(explode), str(EXAMPLES / "rule1.yaml"))
        assert code == 0
        assert json.loads(out)["explanation"]["reason_flags"] == ["dnf_expansion_limit"]

    def test_index_of_a_non_directory_is_one(self, capsys):
        code, _, err = run(capsys, "index", str(EXAMPLES / "rule1.yaml"))
        assert code == 1
        assert "Not a directory" in err

    def test_missing_corpus_is_one(self, capsys):
        code, _, err = run(capsys, "assess", str(EXAMPLES / "rule1.yaml"), "--corpus", "nope.json")
        assert code == 1
        assert "Corpus not found" in err

    def test_unparseable_corpus_is_one(self, capsys, tmp_path):
        broken = tmp_path / "corpus.json"
        broken.write_text("{not json", encoding="utf-8")
        code, _, err = run(capsys, "assess", str(EXAMPLES / "rule1.yaml"), "--corpus", str(broken))
        assert code == 1
        assert "Parse error" in err

    def test_assess_of_a_missing_rule_is_one(self, capsys, corpus):
        _, index_path = corpus
        code, _, err = run(capsys, "assess", "nope.yaml", "--corpus", str(index_path))
        assert code == 1
        assert "File not found" in err

    def test_single_assess_of_an_unparseable_rule_is_one(self, capsys, corpus, tmp_path):
        """Unlike batch mode, a single unparseable target is a hard error rather than
        a NEEDS_REVIEW row."""
        _, index_path = corpus
        bad = tmp_path / "bad.yml"
        bad.write_text("- not a mapping\n", encoding="utf-8")
        code, _, err = run(capsys, "assess", str(bad), "--corpus", str(index_path))
        assert code == 1
        assert "Parse error" in err

    def test_no_subcommand_is_usage(self, capsys):
        assert run(capsys, )[0] == 2

    def test_both_rule_and_batch_is_usage(self, capsys, corpus):
        rules_dir, index_path = corpus
        code, _, err = run(
            capsys, "assess", str(rules_dir / "a.yml"), "--batch", str(rules_dir), "--corpus", str(index_path)
        )
        assert code == 2
        assert "exactly one" in err

    def test_neither_rule_nor_batch_is_usage(self, capsys, corpus):
        _, index_path = corpus
        code, _, err = run(capsys, "assess", "--corpus", str(index_path))
        assert code == 2
        assert "exactly one" in err


# ---------------------------------------------------------------------------
# Back-compat
# ---------------------------------------------------------------------------


class TestBackCompat:
    def test_bare_two_paths_run_compare(self, capsys):
        bare = run(capsys, str(EXAMPLES / "rule1.yaml"), str(EXAMPLES / "rule3.yaml"))
        explicit = run(capsys, "compare", str(EXAMPLES / "rule1.yaml"), str(EXAMPLES / "rule3.yaml"))
        assert bare == explicit
        assert bare[0] == 0

    def test_two_arg_subcommand_invocation_is_not_rewritten_to_compare(self, capsys, tmp_path):
        """`index <dir>` is also exactly two tokens. The shim keys off the literal
        subcommand names so a real subcommand still wins."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        write_rule(rules_dir / "ok.yml", process_creation("ok"))

        code, out, _ = run(capsys, "index", str(rules_dir))
        assert code == 0
        assert json.loads(out)["index_version"] == "1"  # an index, not a comparison


# ---------------------------------------------------------------------------
# index
# ---------------------------------------------------------------------------


class TestIndexCommand:
    def test_writes_file_and_reports_counts_on_stderr(self, capsys, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        write_rule(rules_dir / "ok.yml", process_creation("ok"))
        write_rule(
            rules_dir / "unmodeled.yml",
            {**process_creation("u"), "logsource": {"product": "plan9", "category": "moon"}},
        )
        out_path = tmp_path / "corpus.json"

        code, out, err = run(capsys, "index", str(rules_dir), "-o", str(out_path))
        assert code == 0
        assert out == ""  # payload went to the file, not stdout
        assert "Indexed 2 rules (1 skipped)" in err

        index = json.loads(out_path.read_text())
        assert {r["skip_reason"] for r in index["rules"]} == {None, "logsource_unresolved"}

    def test_without_output_flag_payload_goes_to_stdout(self, capsys, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        write_rule(rules_dir / "ok.yml", process_creation("ok"))
        code, out, _ = run(capsys, "index", str(rules_dir))
        assert code == 0
        assert json.loads(out)["index_version"] == "1"

    def test_nested_directories_are_walked_with_relative_paths(self, capsys, tmp_path):
        rules_dir = tmp_path / "rules"
        (rules_dir / "windows" / "process").mkdir(parents=True)
        write_rule(rules_dir / "windows" / "process" / "deep.yml", process_creation("deep"))
        write_rule(rules_dir / "top.yaml", process_creation("top"))

        code, out, _ = run(capsys, "index", str(rules_dir))
        assert code == 0
        paths = [r["path"] for r in json.loads(out)["rules"]]
        assert paths == ["top.yaml", "windows/process/deep.yml"]


# ---------------------------------------------------------------------------
# assess flag plumbing
# ---------------------------------------------------------------------------


class TestAssessFlagPlumbing:
    @pytest.fixture
    def soft_exe_corpus(self, tmp_path: Path, capsys) -> tuple[Path, Path]:
        """A corpus and proposal that share an exe value only ACROSS fields, so the
        strict Jaccard is 0 and only the soft-exe fallback can score them."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        write_rule(
            rules_dir / "by_image.yml",
            {
                "title": "By image",
                "id": "by-image",
                "logsource": {"product": "windows", "category": "process_creation"},
                "detection": {"selection": {"Image|endswith": "/rundll32.exe"}, "condition": "selection"},
            },
        )
        index_path = tmp_path / "corpus.json"
        assert run(capsys, "index", str(rules_dir), "-o", str(index_path))[0] == 0

        proposed = tmp_path / "proposed.yml"
        write_rule(
            proposed,
            {
                "title": "By command line",
                "id": "by-cmdline",
                "logsource": {"product": "windows", "category": "process_creation"},
                "detection": {"selection": {"CommandLine|contains": "/rundll32.exe"}, "condition": "selection"},
            },
        )
        return proposed, index_path

    def test_soft_exe_is_on_by_default(self, capsys, soft_exe_corpus):
        proposed, index_path = soft_exe_corpus
        code, out, _ = run(capsys, "assess", str(proposed), "--corpus", str(index_path))
        assert code == 0
        result = json.loads(out)
        assert result["matches"], "soft-exe fallback should surface a cross-field match"
        assert "soft_exe_match" in result["matches"][0]["reason_flags"]

    def test_no_soft_exe_flag_is_actually_plumbed_through(self, capsys, soft_exe_corpus):
        proposed, index_path = soft_exe_corpus
        code, out, _ = run(capsys, "assess", str(proposed), "--corpus", str(index_path), "--no-soft-exe")
        assert code == 0
        result = json.loads(out)
        assert result["matches"] == []
        assert result["verdict"] == "NEEDS_REVIEW"

    def test_top_k_is_plumbed_to_the_fallback_path(self, capsys, tmp_path):
        """top-k only caps the logsource fallback, so the corpus must live on an
        unmodeled logsource for the cap to be observable."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        for i in range(6):
            write_rule(
                rules_dir / f"r{i}.yml",
                {
                    "title": f"R{i}",
                    "id": f"r{i}",
                    "logsource": {"product": "plan9", "category": "moon"},
                    "detection": {"selection": {"Image|endswith": f"/p{i}.exe"}, "condition": "selection"},
                },
            )
        index_path = tmp_path / "corpus.json"
        assert run(capsys, "index", str(rules_dir), "-o", str(index_path))[0] == 0

        proposed = tmp_path / "proposed.yml"
        write_rule(
            proposed,
            {
                "title": "Proposed",
                "id": "proposed",
                "logsource": {"product": "plan9", "category": "moon"},
                "detection": {"selection": {"Image|endswith": "/p0.exe"}, "condition": "selection"},
            },
        )

        _, wide, _ = run(
            capsys, "assess", str(proposed), "--corpus", str(index_path), "--rules-dir", str(rules_dir)
        )
        _, narrow, _ = run(
            capsys, "assess", str(proposed), "--corpus", str(index_path), "--rules-dir", str(rules_dir), "--top-k", "2"
        )
        assert json.loads(wide)["candidates_evaluated"] == 6
        assert json.loads(narrow)["candidates_evaluated"] == 2

    def test_threshold_is_plumbed_and_inclusive(self, capsys, corpus):
        rules_dir, index_path = corpus
        proposed = rules_dir / "a.yml"  # identical to a corpus member -> similarity 1.0

        _, default_out, _ = run(capsys, "assess", str(proposed), "--corpus", str(index_path))
        _, high_out, _ = run(capsys, "assess", str(proposed), "--corpus", str(index_path), "--threshold", "1.0")

        assert json.loads(default_out)["suppressed"] is True
        assert json.loads(high_out)["suppressed"] is True  # 1.0 >= 1.0, boundary inclusive
        assert json.loads(high_out)["threshold"] == 1.0

    def test_rules_dir_defaults_to_the_corpus_directory(self, capsys, tmp_path):
        """Omitting --rules-dir must still resolve stored relative paths, so a
        skipped candidate can be re-extracted live."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        unmodeled = {
            "title": "Unmodeled",
            "id": "unmodeled",
            "logsource": {"product": "plan9", "category": "moon"},
            "detection": {"selection": {"Image|endswith": "/glenda.exe"}, "condition": "selection"},
        }
        write_rule(rules_dir / "u.yml", unmodeled)
        # Index lives NEXT TO the rules, so corpus.parent == rules_dir.
        index_path = rules_dir / "corpus.json"
        assert run(capsys, "index", str(rules_dir), "-o", str(index_path))[0] == 0

        proposed = tmp_path / "proposed.yml"
        write_rule(proposed, dict(unmodeled, id="proposed", title="Proposed"))

        code, out, _ = run(capsys, "assess", str(proposed), "--corpus", str(index_path))
        assert code == 0
        assert json.loads(out)["candidates_evaluated"] == 1


# ---------------------------------------------------------------------------
# assess batch
# ---------------------------------------------------------------------------


class TestAssessBatch:
    def test_batch_emits_one_result_per_rule(self, capsys, corpus, tmp_path):
        rules_dir, index_path = corpus
        proposed_dir = tmp_path / "proposed"
        proposed_dir.mkdir()
        write_rule(proposed_dir / "dup.yml", process_creation("dup", image="\\certutil.exe"))
        write_rule(proposed_dir / "new.yml", process_creation("new", image="\\mshta.exe"))

        code, out, _ = run(
            capsys, "assess", "--batch", str(proposed_dir), "--corpus", str(index_path), "--rules-dir", str(rules_dir)
        )
        assert code == 0
        results = json.loads(out)
        assert isinstance(results, list)
        verdicts = {r["rule_id"]: r["verdict"] for r in results}
        assert verdicts["dup"] == "DUPLICATE"
        # A near-duplicate sibling must not drag the other rule's verdict with it.
        assert verdicts["new"] != "DUPLICATE"

    def test_unparseable_file_does_not_abort_the_batch(self, capsys, corpus, tmp_path):
        rules_dir, index_path = corpus
        proposed_dir = tmp_path / "proposed"
        proposed_dir.mkdir()
        write_rule(proposed_dir / "good.yml", process_creation("good", image="\\certutil.exe"))
        (proposed_dir / "bad.yml").write_text("- not a mapping\n", encoding="utf-8")

        code, out, _ = run(
            capsys, "assess", "--batch", str(proposed_dir), "--corpus", str(index_path), "--rules-dir", str(rules_dir)
        )
        assert code == 0
        results = {r["rule_id"]: r for r in json.loads(out)}
        assert results["good"]["verdict"] == "DUPLICATE"
        # The bad file is reported, never assigned a verdict it did not earn.
        assert results["bad.yml"]["verdict"] == "NEEDS_REVIEW"
        assert "error" in results["bad.yml"]

    def test_batch_of_a_non_directory_is_one(self, capsys, corpus):
        rules_dir, index_path = corpus
        code, _, err = run(capsys, "assess", "--batch", str(rules_dir / "a.yml"), "--corpus", str(index_path))
        assert code == 1
        assert "Not a directory" in err

    def test_single_assess_output_is_an_object_not_a_list(self, capsys, corpus):
        rules_dir, index_path = corpus
        _, out, _ = run(capsys, "assess", str(rules_dir / "a.yml"), "--corpus", str(index_path))
        assert isinstance(json.loads(out), dict)
