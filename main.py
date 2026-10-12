"""Suggest CWEs for a vulnerability description using Jev.

    uv run python main.py "The login form builds its SQL query from user input."
    uv run python main.py --file advisory.md
    cat advisory.md | uv run python main.py --json

Walks the CWE hierarchy (research view 1000) with beam search, asking Jev at
each step which refinement fits best, and prints the most likely CWEs with
their path probabilities. Requires TYPESAFE_API_KEY in the environment or in
a gitignored .env file. The text is sent to the configured Jev service.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from classification import CWEGraph, select_classify
from experiment.jev_selector import create_rich_parent_selector


ROOT = Path(__file__).resolve().parent
CATALOG = ROOT / "data" / "all.csv"
ENV_FILES = (ROOT / ".env", ROOT / "experiment" / ".env")
TESTED_MODEL = "jev-1.13.0"
BEAM_WIDTH = 3

# From experiment/experiments.ipynb (500 GitHub-reviewed advisories, jev-1.13.0).
ACCURACY_NOTE = (
    "Suggestions only. On held-out GitHub advisories the first suggestion was "
    "correct 45% of the time, and the right CWE was among the top 5 77% of the time."
)


def main(argv=None):
    args = parse_args(argv)
    text = read_text(args)
    if not text:
        sys.exit("error: no vulnerability text given (pass it as an argument, --file, or stdin)")
    load_env_files()
    if not os.environ.get("TYPESAFE_API_KEY"):
        sys.exit("error: set TYPESAFE_API_KEY in your environment or in .env")

    graph = CWEGraph(CATALOG)
    model = args.model or os.environ.get("TYPESAFE_DEFAULT_MODEL") or TESTED_MODEL
    selector = create_rich_parent_selector(graph.labels, model=model)
    try:
        result = select_classify(text, graph, selector, beam_width=BEAM_WIDTH, top_k=args.top_k)
    except Exception as error:
        sys.exit(f"error: Jev request failed ({type(error).__name__}: {error})")

    suggestions = [
        {"cwe": f"CWE-{label}", "name": graph.labels[label]["Name"],
         "score": round(score, 4), "path": [f"CWE-{node}" for node in path]}
        for label, score, path in zip(result.predictions, result.scores, result.paths)
    ]
    if args.json:
        print(json.dumps({"model": selector.resolved_model, "suggestions": suggestions}, indent=2))
    else:
        print_suggestions(suggestions, selector.resolved_model, result)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Suggest CWEs for a vulnerability description using Jev.")
    parser.add_argument("text", nargs="*", help="vulnerability description (default: stdin)")
    parser.add_argument("--file", type=Path, help="read the description from a file")
    parser.add_argument("--top-k", type=int, default=5, help="number of suggestions (default: 5)")
    parser.add_argument("--model", help=f"Jev model version (default: {TESTED_MODEL})")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = parser.parse_args(argv)
    if args.top_k < 1:
        parser.error("--top-k must be at least 1")
    if args.file and args.text:
        parser.error("give the description as text or --file, not both")
    return args


def read_text(args):
    if args.file:
        return args.file.read_text(encoding="utf-8").strip()
    if args.text:
        return " ".join(args.text).strip()
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return ""


def load_env_files():
    """Read KEY=VALUE lines from .env files without overriding the environment."""
    for path in ENV_FILES:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.strip().partition("=")
            if separator and key and not key.startswith("#"):
                os.environ.setdefault(key.removeprefix("export ").strip(),
                                      value.strip().strip("\"'"))


def print_suggestions(suggestions, model, result):
    print(f"Suggested CWEs ({model}, {result.calls} Jev calls, "
          f"{result.latency_seconds:.1f}s):\n")
    for rank, suggestion in enumerate(suggestions, 1):
        print(f"{rank:2}. {suggestion['cwe']:<9} {suggestion['score']:>4.0%}  {suggestion['name']}")
        print(f"    {' > '.join(suggestion['path'])}")
    print(f"\n{ACCURACY_NOTE}")


if __name__ == "__main__":
    main()
