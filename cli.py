"""
CLI for the Sigma similarity + novelty engine.

    sigma-similarity compare <a.yaml> <b.yaml>
    sigma-similarity index <rules_dir> [-o corpus.json]
    sigma-similarity assess <rule.yaml> --corpus corpus.json [options]
    sigma-similarity assess --batch <dir> --corpus corpus.json [options]

Back-compat: a bare ``sigma-similarity <a.yaml> <b.yaml>`` still runs ``compare``.

Exit codes: 0 structured result; 1 file/parse errors, UnknownTelemetryClassError,
UnsupportedSigmaFeatureError; 2 usage. DeterministicExpansionLimitError never escapes —
the engine converts it into a result carrying the ``dnf_expansion_limit`` flag.
"""

import argparse
import json
import sys
from pathlib import Path

import yaml

from sigma_similarity.errors import (
    UnknownTelemetryClassError,
    UnsupportedSigmaFeatureError,
)
from sigma_similarity.novelty import (
    DEFAULT_SUPPRESSION_THRESHOLD,
    assess_rule,
    build_index,
    iter_rule_paths,
    load_rule_file,
)
from sigma_similarity.similarity_engine import compare_rules


def _load_rule(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid rule YAML: {path}")
    return data


def _dump_compact(payload: object) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def cmd_compare(args: argparse.Namespace) -> int:
    path_a, path_b = Path(args.rule_a), Path(args.rule_b)
    for path in (path_a, path_b):
        if not path.exists():
            print(f"File not found: {path}", file=sys.stderr)
            return 1
    try:
        rule_a = _load_rule(path_a)
        rule_b = _load_rule(path_b)
    except Exception as exc:
        print(f"Parse error: {exc}", file=sys.stderr)
        return 1
    try:
        result = compare_rules(rule_a, rule_b)
    except (UnknownTelemetryClassError, UnsupportedSigmaFeatureError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    _dump_compact(result.to_dict())
    return 0


def cmd_index(args: argparse.Namespace) -> int:
    rules_dir = Path(args.rules_dir)
    if not rules_dir.is_dir():
        print(f"Not a directory: {rules_dir}", file=sys.stderr)
        return 1
    index = build_index(rules_dir)
    payload = json.dumps(index, sort_keys=True, separators=(",", ":"))
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
        skipped = sum(1 for r in index["rules"] if r["skip_reason"])
        print(
            f"Indexed {len(index['rules'])} rules ({skipped} skipped) -> {args.output}",
            file=sys.stderr,
        )
    else:
        print(payload)
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    if bool(args.rule) == bool(args.batch):
        print("Provide exactly one of <rule.yaml> or --batch <dir>", file=sys.stderr)
        return 2

    corpus_path = Path(args.corpus)
    if not corpus_path.is_file():
        print(f"Corpus not found: {corpus_path}", file=sys.stderr)
        return 1
    try:
        index = json.loads(corpus_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Parse error: {exc}", file=sys.stderr)
        return 1

    # Live re-extraction of skipped candidates resolves their stored relative paths
    # against the rules dir; default to the corpus file's own directory.
    base_dir = Path(args.rules_dir) if args.rules_dir else corpus_path.parent

    if args.batch:
        batch_dir = Path(args.batch)
        if not batch_dir.is_dir():
            print(f"Not a directory: {batch_dir}", file=sys.stderr)
            return 1
        targets = [(p, p.relative_to(batch_dir).as_posix()) for p in iter_rule_paths(batch_dir)]
    else:
        rule_path = Path(args.rule)
        if not rule_path.is_file():
            print(f"File not found: {rule_path}", file=sys.stderr)
            return 1
        targets = [(rule_path, rule_path.name)]

    results = []
    for path, label in targets:
        try:
            rule = load_rule_file(path)
        except Exception as exc:
            if not args.batch:
                print(f"Parse error: {exc}", file=sys.stderr)
                return 1
            # One unparseable file must not abort a batch, and must not be reported
            # as a verdict it never earned.
            results.append({"rule_id": label, "verdict": "NEEDS_REVIEW", "error": str(exc)})
            continue
        # Verdicts are computed per rule; one near-duplicate never suppresses siblings.
        results.append(
            assess_rule(
                rule,
                index,
                rule_id=str(rule.get("id") or label),
                top_k=args.top_k,
                threshold=args.threshold,
                enable_soft_exe=not args.no_soft_exe,
                base_dir=base_dir,
            )
        )

    payload = results if args.batch else results[0]
    print(json.dumps(payload, sort_keys=True, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigma-similarity",
        description="Deterministic Sigma rule similarity and novelty assessment.",
    )
    sub = parser.add_subparsers(dest="command")

    compare = sub.add_parser("compare", help="Pairwise similarity between two rules")
    compare.add_argument("rule_a")
    compare.add_argument("rule_b")
    compare.set_defaults(func=cmd_compare)

    index = sub.add_parser("index", help="Build a corpus index from a directory of rules")
    index.add_argument("rules_dir")
    index.add_argument("-o", "--output", help="Write index here instead of stdout")
    index.set_defaults(func=cmd_index)

    assess = sub.add_parser("assess", help="Assess rule novelty against a corpus index")
    assess.add_argument("rule", nargs="?", help="Rule to assess")
    assess.add_argument("--batch", help="Assess every rule in this directory")
    assess.add_argument("--corpus", required=True, help="Corpus index JSON")
    assess.add_argument("--rules-dir", help="Base dir for the corpus's rule paths")
    assess.add_argument("--top-k", type=int, default=20, help="Fallback-path candidate cap")
    assess.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_SUPPRESSION_THRESHOLD,
        help="Suppression threshold (inclusive)",
    )
    assess.add_argument(
        "--no-soft-exe",
        action="store_true",
        help="Disable the cross-field executable-name fallback",
    )
    assess.set_defaults(func=cmd_assess)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Back-compat: a bare pair of rule paths means `compare`.
    if len(argv) == 2 and not argv[0].startswith("-") and argv[0] not in ("compare", "index", "assess"):
        argv = ["compare", *argv]

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_usage(sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
