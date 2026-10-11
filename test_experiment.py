import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from classification import CWEGraph
from experiment import catalog_fingerprint, export_prompts, fingerprint, load_one_shot, run_notebook
import test_classification


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        fixture = test_classification.ClassificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.graph = CWEGraph(fixture.path)
        self.graph_path = fixture.path
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

    def test_cli_matched_comparison(self):
        benchmark = Path(self.directory.name) / "benchmark.jsonl"
        benchmark.write_text(json.dumps(self.examples[0]) + "\n", encoding="utf-8")
        output = Path(self.directory.name) / "results"
        record = self.record()
        self.write(record)
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("experiment.py")), "run",
             "--catalog", str(self.graph_path), "--benchmark", str(benchmark),
             "--output", str(output), "--methods", "flat", "greedy", "beam", "one-shot",
             "--one-shot-predictions", str(self.path), "--bootstrap-samples", "20"],
            capture_output=True, text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(len(summary["paired_accuracy_intervals"]), 6)
        self.assertEqual(summary["metrics"]["one-shot"]["mean_hierarchical_distance"], 0)
        self.assertIsNone(summary["metrics"]["flat"]["total_cost"])

    def configuration(self, command="run"):
        benchmark = Path(self.directory.name) / "benchmark.jsonl"
        benchmark.write_text(json.dumps(self.examples[0]) + "\n", encoding="utf-8")
        return {
            "command": command, "demo": False, "catalog": str(self.graph_path),
            "benchmark": str(benchmark), "output": str(Path(self.directory.name) / "results"),
            "view": "1000", "split": "test", "training_ids": None,
            "scorer": "lexical", "methods": ["flat", "greedy", "beam"],
            "one_shot_predictions": None, "beam_width": 2, "top_k": 2,
            "threshold": 0.0, "margin": 0.0, "seed": 0,
            "bootstrap_samples": 20, "max_prompt_chars": None,
        }

    def test_notebook_exports_and_run(self):
        for command in ["prepare", "export-prompts"]:
            config = self.configuration(command)
            config["output"] = str(Path(self.directory.name) / f"{command}.jsonl")
            state = run_notebook(config)
            self.assertIsNone(state["summary"])
            record = json.loads(Path(config["output"]).read_text())
            self.assertEqual(record["id"], "a")
        state = run_notebook(self.configuration())
        self.assertEqual(set(state["results"]), {"flat", "greedy", "beam"})
        self.assertFalse(state["summary"]["synthetic_demo"])
        self.assertIn("lock_hash", state["summary"]["environment"])

    def test_notebook_rejects_invalid_configuration(self):
        for change in [{"methods": ["made-up"]}, {"beam_width": 0},
                       {"demo": True, "scorer": "jev_scorer:create_scorer"},
                       {"methods": ["one-shot"]}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                run_notebook({**self.configuration(), **change})

    def test_cli_workflow_uses_its_own_checkout_root(self):
        source = Path(__file__).parent
        relocated = Path(self.directory.name) / "relocated"
        relocated.mkdir()
        for name in ["experiments.ipynb", "uv.lock"]:
            (relocated / name).write_bytes((source / name).read_bytes())
        with patch("experiment.__file__", str(relocated / "experiment.py")):
            state = run_notebook(self.configuration())
        self.assertEqual(state["ROOT"], relocated)
        self.assertIsNotNone(state["summary"]["workflow_hash"])

    def test_jupyter_executes_same_workflow(self):
        try:
            import nbformat
            from nbclient import NotebookClient
        except ImportError:
            self.skipTest("Install notebook extra for headless Jupyter validation")
        path = Path(__file__).with_name("experiments.ipynb")
        notebook = nbformat.read(path, as_version=4)
        nbformat.validate(notebook)
        config = self.configuration()
        notebook.cells.insert(0, nbformat.v4.new_code_cell(
            "experiment_config = " + repr(config)
        ))
        NotebookClient(notebook, timeout=120, kernel_name="python3",
                       resources={"metadata": {"path": str(path.parent)}}).execute()
        summary = json.loads((Path(config["output"]) / "summary.json").read_text())
        self.assertEqual(set(summary["metrics"]), {"flat", "greedy", "beam"})


if __name__ == "__main__":
    unittest.main()
