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
        path.write_text(
            "\n".join(
                json.dumps(record)
                for record in [
                    {
                        "id": "a",
                        "text": "Same CWE-1 issue",
                        "labels": ["1"],
                        "split": "dev",
                    },
                    {"id": "b", "text": "same issue", "labels": ["1"], "split": "test"},
                    {
                        "id": "c",
                        "text": "Separate issue",
                        "labels": ["1"],
                        "split": "test",
                    },
                ]
            )
        )
        self.assertEqual([row["id"] for row in load_benchmark(path)], ["c"])

    def test_metrics_and_accuracy_interval(self):
        records = [
            {"id": "a", "labels": ["1"], "predictions": ["1", "2"], "abstained": False},
            {"id": "b", "labels": ["2"], "predictions": [], "abstained": True},
        ]
        result = metrics(records)
        self.assertEqual(result["accuracy"], 0.5)
        self.assertEqual(result["top_k_recall"][3], 0.5)
        self.assertEqual(result["abstention_rate"], 0.5)
        low, high = result["accuracy_95ci"]
        self.assertLess(low, 0.5)
        self.assertGreater(high, 0.5)
        self.assertEqual(metrics([records[0]])["accuracy_95ci"][1], 1.0)

    def test_multilabel_recall_differs_from_hit_rate(self):
        result = metrics([{"labels": ["1", "2"], "predictions": ["1"]}])
        self.assertEqual(result["top_k_hit_rate"][1], 1)
        self.assertEqual(result["top_k_recall"][1], 0.5)
        self.assertAlmostEqual(result["macro_f1_top1"], 0.5)
        wrong = metrics([{"labels": ["1"], "predictions": ["2"]}])
        self.assertEqual(wrong["macro_f1_top1"], 0)

    def test_loader_strips_identifiers_and_rejects_invalid_gold(self):
        path = self.root / "benchmark.jsonl"

        def save(labels):
            path.write_text(
                json.dumps(
                    {
                        "id": "a",
                        "text": "CWE-1 dangerous input",
                        "labels": labels,
                        "split": "dev",
                    }
                )
            )

        save(["1"])
        self.assertEqual(load_benchmark(path, "dev")[0]["text"], "dangerous input")
        for labels in (["0"], ["nonsense"], ["1", "CWE-1"]):
            save(labels)
            with self.assertRaises(ValueError):
                load_benchmark(path, "dev")


if __name__ == "__main__":
    unittest.main()
