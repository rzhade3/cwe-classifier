"""Build the CWE benchmark from GitHub-reviewed security advisories (GHSA).

Gold labels are the ``database_specific.cwe_ids`` that GitHub curators assign
to reviewed advisories. They are curated, consistently sourced labels, not an
independent expert adjudication. No other vulnerability source supplies text
or labels.

The pipeline is deterministic for a fixed snapshot, catalog, and seed:

1. ``load_advisories`` parses every advisory JSON file and records why
   advisories are unusable (withdrawn, unreviewed, missing text or CWEs).
2. ``build_benchmark`` drops labels absent from the CWE catalog, excludes
   advisories cited in the catalog's Observed Examples (catalog leakage),
   groups advisories that share an alias or identical CWE-stripped text, and
   excludes groups whose members disagree on labels.
3. Groups are split into ``dev``/``test`` stratified by their exact label set,
   using seeded hashes so assignment never depends on file order.
"""

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

from classification import normalize_label


_CWE_ID = re.compile(r"(?i)^CWE-(\d+)$")
_CWE_MENTION = re.compile(r"\bCWE[\s-]*\d+\b", re.IGNORECASE)
_OBSERVED_CVE = re.compile(
    r"::REFERENCE:\s*(CVE-\d{4}-\d+)\s*:DESCRIPTION:", re.IGNORECASE
)
_IGNORED_DIRS = {"node_modules", "__pycache__"}


def _json_files(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"Snapshot symlinks are not supported: {path}")
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise ValueError(f"Snapshot does not exist: {path}")
    files = []
    for child in sorted(path.rglob("*.json")):
        relative = child.relative_to(path).parts
        if any(part.startswith(".") or part in _IGNORED_DIRS for part in relative):
            continue
        if child.is_symlink():
            raise ValueError(f"Snapshot symlinks are not supported: {child}")
        if child.is_file():
            files.append(child)
    return sorted(files, key=lambda file: file.relative_to(path).as_posix())


def snapshot_sha256(path):
    """Hash a JSON file, or every JSON file in a directory with framed paths."""
    path = Path(path)
    files = _json_files(path)
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256()
    for file in files:
        relative = file.relative_to(path).as_posix().encode("utf-8")
        content = file.read_bytes()
        digest.update(len(relative).to_bytes(8, "big") + relative)
        digest.update(len(content).to_bytes(8, "big") + content)
    return digest.hexdigest()


def strip_cwe_mentions(text):
    """Remove explicit CWE identifiers so inputs cannot leak their labels."""
    return " ".join(_CWE_MENTION.sub("", text).split())


def _advisory(entry):
    if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
        return None, "malformed"
    if entry.get("withdrawn"):
        return None, "withdrawn"
    specific = entry.get("database_specific") or {}
    if specific.get("github_reviewed") is not True:
        return None, "unreviewed"
    text = "\n\n".join(
        part.strip() for part in (entry.get("summary"), entry.get("details"))
        if isinstance(part, str) and part.strip()
    )
    if not text:
        return None, "missing_text"
    labels, invalid = [], []
    for value in specific.get("cwe_ids") or []:
        match = _CWE_ID.match(str(value).strip())
        if match and int(match[1]) > 0:
            label = f"CWE-{int(match[1])}"
            if label not in labels:
                labels.append(label)
        else:
            invalid.append(str(value))
    if not labels:
        return None, "no_cwe"
    ecosystems = sorted({
        affected["package"]["ecosystem"]
        for affected in entry.get("affected") or []
        if isinstance(affected, dict)
        and isinstance(affected.get("package"), dict)
        and isinstance(affected["package"].get("ecosystem"), str)
        and affected["package"]["ecosystem"]
    })
    identifier = entry["id"].strip().upper()
    aliases = sorted({identifier} | {
        alias.strip().upper() for alias in entry.get("aliases") or []
        if isinstance(alias, str) and alias.strip()
    })
    return {
        "id": identifier,
        "aliases": aliases,
        "text": text,
        "labels": sorted(labels, key=lambda label: int(label[4:])),
        "invalid_labels": invalid,
        "ecosystems": ecosystems,
        "severity": specific.get("severity"),
        "published": str(entry.get("published") or "")[:10],
    }, None


def load_advisories(snapshot):
    """Return ``(advisories, exclusions)`` for reviewed advisories with CWEs."""
    advisories, exclusions = [], Counter()
    for file in _json_files(snapshot):
        try:
            entry = json.loads(file.read_text(encoding="utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            exclusions["malformed"] += 1
            continue
        advisory, reason = _advisory(entry)
        if advisory is None:
            exclusions[reason] += 1
        else:
            advisories.append(advisory)
    advisories.sort(key=lambda advisory: advisory["id"])
    return advisories, dict(sorted(exclusions.items()))


def _unit(seed, purpose, identifier):
    digest = hashlib.sha256(
        json.dumps([seed, purpose, identifier]).encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def _groups(advisories):
    parent = list(range(len(advisories)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    owners = {}
    for index, advisory in enumerate(advisories):
        keys = [("alias", alias) for alias in advisory["aliases"]]
        keys.append(("text", strip_cwe_mentions(advisory["text"]).casefold()))
        for key in keys:
            if key in owners:
                left, right = find(index), find(owners[key])
                parent[max(left, right)] = min(left, right)
            else:
                owners[key] = index
    groups = defaultdict(list)
    for index, advisory in enumerate(advisories):
        groups[find(index)].append(advisory)
    return list(groups.values())


def stratified_split(groups, seed=0, dev_fraction=0.2):
    """Assign each group to dev/test, stratified by exact label set.

    Each label-set stratum sends ``n * dev_fraction`` groups to dev, rounding
    the fractional remainder stochastically with a seeded hash. Rare label sets
    therefore appear in dev at the requested rate in expectation instead of
    always landing in test.
    """
    if not 0 <= dev_fraction <= 1:
        raise ValueError("dev_fraction must be in [0, 1]")
    strata = defaultdict(list)
    for group in groups:
        strata[tuple(group["labels"])].append(group)
    splits = {}
    for labels, members in sorted(strata.items()):
        members.sort(key=lambda group: (_unit(seed, "order", group["id"]), group["id"]))
        expected = len(members) * dev_fraction
        dev_count = math.floor(expected) + (
            _unit(seed, "round", "|".join(labels)) < expected - math.floor(expected)
        )
        for index, group in enumerate(members):
            splits[group["id"]] = "dev" if index < dev_count else "test"
    return splits


def build_benchmark(advisories, catalog, *, seed=0, dev_fraction=0.2):
    """Return ``(benchmark_records, audit)`` from loaded advisories."""
    eligible = {f"CWE-{normalize_label(label)}" for label in catalog}
    observed = set()
    for row in catalog.values():
        observed.update(
            cve.upper() for cve in _OBSERVED_CVE.findall(row.get("Observed Examples") or "")
        )
    audit = Counter()
    ineligible_labels = Counter()
    usable = []
    for advisory in advisories:
        labels = [label for label in advisory["labels"] if label in eligible]
        ineligible_labels.update(
            label for label in advisory["labels"] if label not in eligible
        )
        if not labels:
            audit["no_catalog_cwe"] += 1
            continue
        if observed.intersection(advisory["aliases"]):
            audit["catalog_leakage"] += 1
            continue
        if not strip_cwe_mentions(advisory["text"]):
            audit["empty_after_cwe_stripping"] += 1
            continue
        usable.append({**advisory, "labels": labels})

    groups = []
    for members in _groups(usable):
        members.sort(key=lambda advisory: advisory["id"])
        if len({tuple(member["labels"]) for member in members}) > 1:
            audit["conflicting_duplicate_labels"] += len(members)
            continue
        audit["merged_duplicates"] += len(members) - 1
        canonical = members[0]
        groups.append({
            "id": canonical["id"],
            "text": strip_cwe_mentions(canonical["text"]),
            "labels": canonical["labels"],
            "aliases": sorted({alias for member in members for alias in member["aliases"]}),
            "ecosystems": sorted({
                ecosystem for member in members for ecosystem in member["ecosystems"]
            }),
            "published": max(member["published"] for member in members),
            "source": "ghsa",
        })
    splits = stratified_split(groups, seed, dev_fraction)
    for group in groups:
        group["split"] = splits[group["id"]]
    groups.sort(key=lambda group: group["id"])
    return groups, {
        "advisories_with_cwe": len(advisories),
        "records": len(groups),
        "split_counts": dict(sorted(Counter(group["split"] for group in groups).items())),
        "exclusions": dict(sorted(audit.items())),
        "ineligible_labels": dict(ineligible_labels.most_common()),
        "seed": seed,
        "dev_fraction": dev_fraction,
    }


def describe(records, catalog=None, top=25):
    """Summarize CWE, label-cardinality, ecosystem, and year distributions."""
    labels = Counter(label for record in records for label in record["labels"])
    frequencies = sorted(labels.values(), reverse=True)
    total = sum(frequencies)
    head = sum(frequencies[:10])
    summary = {
        "records": len(records),
        "distinct_cwes": len(labels),
        "top_cwes": labels.most_common(top),
        "top_10_label_share": head / total if total else 0.0,
        "cwes_with_at_most_5_examples": sum(count <= 5 for count in frequencies),
        "labels_per_record": dict(sorted(
            Counter(len(record["labels"]) for record in records).items()
        )),
        "ecosystems": dict(Counter(
            ecosystem for record in records for ecosystem in record["ecosystems"]
        ).most_common()),
        "published_years": dict(sorted(Counter(
            record["published"][:4] for record in records if record["published"]
        ).items())),
    }
    if catalog is not None:
        abstraction = Counter()
        for label, count in labels.items():
            row = catalog.get(normalize_label(label))
            abstraction[(row or {}).get("Weakness Abstraction") or "not in catalog"] += count
        summary["label_abstraction"] = dict(abstraction.most_common())
    return summary
