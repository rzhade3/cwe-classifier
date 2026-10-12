import json
import tempfile
import unittest
from pathlib import Path

from experiment.benchmark import load_benchmark, metrics


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_loader_excludes_duplicates_across_splits(self):
        path = self.root / "examples.jsonl"
        path.write_text("\n".join(json.dumps(record) for record in [
            {"id": "a", "text": "Same CWE-1 issue", "labels": ["1"], "split": "dev"},
            {"id": "b", "text": "same issue", "labels": ["1"], "split": "test"},
            {"id": "c", "text": "Separate issue", "labels": ["1"], "split": "test"},
        ]))
        self.assertEqual([row["id"] for row in load_benchmark(path)], ["c"])

    def test_metrics_and_accuracy_interval(self):
        records = [
            {"id": "a", "labels": ["1"], "predictions": ["1", "2"],
             "abstained": False},
            {"id": "b", "labels": ["2"], "predictions": [],
             "abstained": True},
        ]
        result = metrics(records)
        self.assertEqual(result["accuracy"], .5)
        self.assertEqual(result["top_k_recall"][3], .5)
        self.assertEqual(result["abstention_rate"], .5)
        low, high = result["accuracy_95ci"]
        self.assertLess(low, .5)
        self.assertGreater(high, .5)
        self.assertEqual(metrics([records[0]])["accuracy_95ci"][1], 1.0)

if __name__ == "__main__":
    unittest.main()
