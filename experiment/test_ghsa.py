import json
import tempfile
import unittest
from pathlib import Path

from experiment.ghsa import (
    build_benchmark,
    describe,
    load_advisories,
    snapshot_sha256,
    stratified_split,
    strip_cwe_mentions,
)

CATALOG = {
    "79": {"Weakness Abstraction": "Base", "Observed Examples": ""},
    "89": {
        "Weakness Abstraction": "Base",
        "Observed Examples": "::REFERENCE:CVE-2020-0001:DESCRIPTION:leak::",
    },
    "20": {"Weakness Abstraction": "Class", "Observed Examples": ""},
}


def advisory(identifier, cwes=("CWE-79",), aliases=(), reviewed=True, **extra):
    value = {
        "id": identifier,
        "aliases": list(aliases),
        "summary": f"Issue {identifier}",
        "details": "Untrusted input (CWE-79) is rendered.",
        "published": "2025-03-16T08:00:00Z",
        "affected": [{"package": {"ecosystem": "npm", "name": "pkg"}}],
        "database_specific": {
            "github_reviewed": reviewed,
            "cwe_ids": list(cwes),
            "severity": "HIGH",
        },
    }
    value.update(extra)
    return value


class GHSATests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, *entries):
        for entry in entries:
            path = self.root / "2025" / f"{entry['id']}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(entry), encoding="utf-8")

    def test_loader_keeps_reviewed_advisories_with_cwes(self):
        self.write(
            advisory("GHSA-1", ("CWE-79", "cwe-020", "NVD-CWE-Other")),
            advisory("GHSA-2", reviewed=False),
            advisory("GHSA-3", withdrawn="2025-04-01T00:00:00Z"),
            advisory("GHSA-4", cwes=()),
            advisory("GHSA-5", summary="", details=""),
        )
        (self.root / "2025" / "bad.json").write_text("{", encoding="utf-8")
        advisories, exclusions = load_advisories(self.root)
        self.assertEqual([a["id"] for a in advisories], ["GHSA-1"])
        self.assertEqual(advisories[0]["labels"], ["CWE-20", "CWE-79"])
        self.assertEqual(advisories[0]["invalid_labels"], ["NVD-CWE-Other"])
        self.assertEqual(advisories[0]["ecosystems"], ["npm"])
        self.assertEqual(
            exclusions,
            {
                "malformed": 1,
                "missing_text": 1,
                "no_cwe": 1,
                "unreviewed": 1,
                "withdrawn": 1,
            },
        )

    def test_benchmark_filters_dedupes_and_strips_labels_from_text(self):
        self.write(
            advisory("GHSA-a", ("CWE-79", "CWE-999"), aliases=["CVE-2025-1"]),
            advisory(
                "GHSA-b",
                aliases=["CVE-2025-1"],
                affected=[{"package": {"ecosystem": "PyPI"}}],
            ),
            advisory("GHSA-c", ("CWE-999",)),
            advisory("GHSA-d", ("CWE-89",), aliases=["CVE-2020-0001"]),
            advisory("GHSA-e", ("CWE-20",), aliases=["CVE-2025-2"]),
            advisory("GHSA-f", ("CWE-89",), aliases=["CVE-2025-2"]),
        )
        records, audit = build_benchmark(load_advisories(self.root)[0], CATALOG)
        self.assertEqual([r["id"] for r in records], ["GHSA-A"])
        record = records[0]
        self.assertEqual(record["labels"], ["CWE-79"])
        self.assertEqual(record["ecosystems"], ["PyPI", "npm"])
        self.assertNotIn("CWE", record["text"])
        self.assertEqual(
            audit["exclusions"],
            {
                "catalog_leakage": 1,
                "conflicting_duplicate_labels": 2,
                "merged_duplicates": 1,
                "no_catalog_cwe": 1,
            },
        )
        self.assertEqual(audit["ineligible_labels"], {"CWE-999": 2})

    def test_stratified_split_is_seeded_order_free_and_proportional(self):
        groups = [{"id": f"G{i}", "labels": ["CWE-79"]} for i in range(100)]
        groups += [{"id": f"R{i}", "labels": ["CWE-20", "CWE-89"]} for i in range(10)]
        first = stratified_split(groups, seed=3, dev_fraction=0.2)
        self.assertEqual(first, stratified_split(list(reversed(groups)), 3, 0.2))
        self.assertEqual(sum(first[f"G{i}"] == "dev" for i in range(100)), 20)
        self.assertEqual(sum(first[f"R{i}"] == "dev" for i in range(10)), 2)
        self.assertNotEqual(first, stratified_split(groups, seed=4, dev_fraction=0.2))

    def test_describe_and_helpers(self):
        records = [
            {"labels": ["CWE-79"], "ecosystems": ["npm"], "published": "2025-01-01"},
            {"labels": ["CWE-79", "CWE-20"], "ecosystems": [], "published": ""},
        ]
        summary = describe(records, CATALOG)
        self.assertEqual(summary["top_cwes"][0], ("CWE-79", 2))
        self.assertEqual(summary["labels_per_record"], {1: 1, 2: 1})
        self.assertEqual(summary["label_abstraction"], {"Base": 2, "Class": 1})
        self.assertEqual(summary["published_years"], {"2025": 1})
        self.assertEqual(strip_cwe_mentions("A CWE-79  b cwe 20"), "A b")
        self.write(advisory("GHSA-1"))
        digest = snapshot_sha256(self.root)
        self.write(advisory("GHSA-1", summary="changed"))
        self.assertNotEqual(digest, snapshot_sha256(self.root))


if __name__ == "__main__":
    unittest.main()
