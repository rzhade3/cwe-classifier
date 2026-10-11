import json
import tempfile
import unittest
from pathlib import Path

from classification import CWEGraph
from experiment import catalog_fingerprint, export_prompts, fingerprint, load_one_shot
import test_classification


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        fixture = test_classification.ClassificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.graph = CWEGraph(fixture.path)
        self.examples = [{"id": "a", "text": "untrusted input", "labels": ["1"],
                          "split": "test"}]
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "predictions.jsonl"

    def record(self):
        return {
            "id": "a", "text_hash": fingerprint("untrusted input"),
            "catalog_hash": catalog_fingerprint(self.graph), "calls": 1,
            "truncated_labels": [], "predictions": ["CWE-1"],
            "latency_seconds": .1, "model": "external-model",
        }

    def write(self, record):
        self.path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    def test_prompt_budget_does_not_truncate(self):
        with self.assertRaises(ValueError):
            export_prompts(self.examples, self.graph, self.path, 20)
        self.assertFalse(self.path.exists())
        export_prompts(self.examples, self.graph, self.path)
        prompt = json.loads(self.path.read_text())
        self.assertEqual(prompt["truncated_labels"], [])
        self.assertEqual(set(prompt["eligible_labels"]), set(self.graph.labels))

    def test_one_shot_validation(self):
        record = self.record()
        self.write(record)
        results = load_one_shot(self.path, self.examples, self.graph)
        self.assertEqual(results[0]["predictions"], ["1"])
        self.assertIsNone(results[0]["cost"])
        for key, value in [
            ("text_hash", "stale"), ("catalog_hash", "stale"), ("calls", 2),
            ("truncated_labels", ["1"]), ("predictions", ["999"]),
            ("input_tokens", -1), ("latency_seconds", float("nan")),
        ]:
            with self.subTest(key=key):
                self.write({**record, key: value})
                with self.assertRaises(ValueError):
                    load_one_shot(self.path, self.examples, self.graph)


if __name__ == "__main__":
    unittest.main()
