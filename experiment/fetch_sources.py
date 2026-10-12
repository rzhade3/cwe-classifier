"""Download a pinned GitHub-reviewed advisory snapshot and build the benchmark."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from classification import CWEGraph
from . import fingerprint, write_jsonl
from .ghsa import build_benchmark, load_advisories, snapshot_sha256
from .jev_selector import FREQUENCIES, write_frequencies


_REPOSITORY = "https://github.com/github/advisory-database.git"
_REVIEWED = "advisories/github-reviewed"


def _fetch_advisories(raw):
    repository = raw / "advisory-database"
    subprocess.run([
        "git", "clone", "--depth=1", "--filter=blob:none", "--sparse",
        _REPOSITORY, str(repository),
    ], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "sparse-checkout", "set", _REVIEWED],
        check=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    snapshot = repository / _REVIEWED
    if not snapshot.is_dir():
        raise ValueError(f"Missing {_REVIEWED} in the advisory database clone")
    print(f"Downloaded GitHub-reviewed advisories at {revision}")
    return snapshot, revision


def prepare(snapshot, catalog, output, *, revision, seed=0, dev_fraction=0.2):
    """Build ``benchmark.jsonl`` and ``dataset-report.json`` from a snapshot."""
    output = Path(output)
    advisories, exclusions = load_advisories(snapshot)
    benchmark, audit = build_benchmark(
        advisories, CWEGraph(catalog).labels, seed=seed, dev_fraction=dev_fraction
    )
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "benchmark.jsonl", benchmark)
    report = {
        "source": {
            "repository": _REPOSITORY,
            "path": _REVIEWED,
            "revision": revision,
            "sha256": snapshot_sha256(snapshot),
        },
        "advisory_exclusions": exclusions,
        "benchmark": {**audit, "sha256": fingerprint(benchmark)},
        "label_policy": (
            "Labels are GitHub curators' cwe_ids on reviewed advisories, "
            "restricted to CWEs in the catalog. Not independently adjudicated."
        ),
    }
    (output / "dataset-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return benchmark, report


def fetch_and_prepare(output, catalog, *, seed=0, dev_fraction=0.2):
    output = Path(output).expanduser().resolve()
    catalog = Path(catalog).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"Output already exists: {output}")
    if not catalog.is_file():
        raise FileNotFoundError(f"CWE catalog not found: {catalog}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=output.parent, prefix=f".{output.name}-"))
    try:
        raw = staging / "raw"
        raw.mkdir()
        snapshot, revision = _fetch_advisories(raw)
        prepare(snapshot, catalog, staging / "prepared", revision=revision,
                seed=seed, dev_fraction=dev_fraction)
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(f"Prepared benchmark: {output / 'prepared' / 'benchmark.jsonl'}")
    print(f"Dataset report: {output / 'prepared' / 'dataset-report.json'}")
    return output


def main():
    repository = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=repository / "experiment" / "data")
    parser.add_argument("--catalog", type=Path, default=repository / "data" / "all.csv")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--dev-fraction", type=float, default=0.2)
    args = parser.parse_args()
    if not 0 <= args.dev_fraction < 1:
        parser.error("--dev-fraction must be in [0, 1)")
    output = fetch_and_prepare(args.output, args.catalog, seed=args.seed,
                               dev_fraction=args.dev_fraction)
    write_frequencies(output / "prepared" / "benchmark.jsonl", FREQUENCIES)
    print(f"CWE label frequencies (dev split): {FREQUENCIES}")


if __name__ == "__main__":
    main()
