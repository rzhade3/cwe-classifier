import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_classification
from experiment.fetch_sources import fetch_and_prepare


class FetchSourceTests(unittest.TestCase):
    def setUp(self):
        fixture = test_classification.ClassificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.catalog = fixture.path
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_ghsa_pipeline_writes_benchmark_and_report(self):
        def fake_fetch(raw):
            path = raw / "advisories" / "github-reviewed"
            path.mkdir(parents=True)
            for index, cwe in enumerate(["CWE-1", "CWE-4", "CWE-77"]):
                (path / f"GHSA-{index}.json").write_text(
                    json.dumps(
                        {
                            "id": f"GHSA-{index}",
                            "aliases": [f"CVE-2026-{index}"],
                            "summary": f"Unsafe input {index} allows memory overwrite",
                            "published": "2026-01-01T00:00:00Z",
                            "affected": [{"package": {"ecosystem": "npm"}}],
                            "database_specific": {
                                "github_reviewed": True,
                                "cwe_ids": [cwe],
                            },
                        }
                    )
                )
            return path, "abc123"

        output = self.root / "snapshot"
        with patch(
            "experiment.fetch_sources._fetch_advisories", side_effect=fake_fetch
        ):
            fetch_and_prepare(output, self.catalog, dev_fraction=0)
        benchmark = [
            json.loads(line)
            for line in (output / "prepared" / "benchmark.jsonl")
            .read_text()
            .splitlines()
        ]
        self.assertEqual(
            [record["labels"] for record in benchmark], [["CWE-1"], ["CWE-4"]]
        )
        self.assertTrue(all(record["split"] == "test" for record in benchmark))
        report = json.loads((output / "prepared" / "dataset-report.json").read_text())
        self.assertEqual(report["source"]["revision"], "abc123")
        self.assertEqual(report["benchmark"]["records"], 2)
        self.assertEqual(report["benchmark"]["ineligible_labels"], {"CWE-77": 1})

        try:
            import nbformat
        except ImportError:
            self.skipTest("Install notebook extra for notebook integration")
        notebook = nbformat.read(
            Path(__file__).with_name("dataset_analysis.ipynb"), as_version=4
        )
        notebook.cells.insert(
            4,
            nbformat.v4.new_code_cell(
                f"SNAPSHOT = Path({str(output / 'raw' / 'advisories' / 'github-reviewed')!r})\n"
                f"PREPARED = Path({str(output / 'prepared')!r})\n"
                f"CATALOG = Path({str(self.catalog)!r})\n"
                "SEED, DEV_FRACTION = 0, 0"
            ),
        )
        from experiment.notebook_test_support import execute_notebook

        execute_notebook(notebook, Path.cwd())

    def test_failed_fetch_leaves_no_output(self):
        output = self.root / "snapshot"
        with patch(
            "experiment.fetch_sources._fetch_advisories",
            side_effect=RuntimeError("network"),
        ):
            with self.assertRaises(RuntimeError):
                fetch_and_prepare(output, self.catalog)
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
