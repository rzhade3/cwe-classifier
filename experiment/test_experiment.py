import json
import tempfile
import unittest
from pathlib import Path

import test_classification
from classification import STOP, CWEGraph
from experiment import default_config
from experiment.runner import run_experiment


class UniformSelector:
    def __init__(self, catalog):
        self.calls = 0

    def select(self, text, labels, current=None):
        self.calls += 1
        options = list(labels) + ([STOP] if current is not None else [])
        return {option: 1 / len(options) for option in options}


class LimitedSelector(UniformSelector):
    max_options = 3


class CountingSelector(UniformSelector):
    texts = []
    resolved_model = "v1"

    def select(self, text, labels, current=None):
        CountingSelector.texts.append(text)
        return super().select(text, labels, current)

    @property
    def metadata(self):
        return {"resolved_model": CountingSelector.resolved_model}


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        fixture = test_classification.ClassificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.graph_path = fixture.path
        self.graph = CWEGraph(fixture.path)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.benchmark = self.root / "benchmark.jsonl"
        self.benchmark.write_text(
            "\n".join(
                json.dumps(
                    {
                        "id": f"CVE-2026-{index:04}",
                        "text": text,
                        "labels": [label],
                        "split": "test",
                    }
                )
                for index, (text, label) in enumerate(
                    [
                        ("memory bounds issue", "1"),
                        ("database query issue", "2"),
                    ]
                )
            ),
            encoding="utf-8",
        )

    def config(self, **overrides):
        return {
            **default_config(self.root),
            "catalog": str(self.graph_path),
            "benchmark": str(self.benchmark),
            "output": str(self.root / "results"),
            "max_examples": 10,
            "split": "test",
            "models": {"lexical": "lexical"},
            **overrides,
        }

    def test_core_methods_write_predictions_and_metrics(self):
        summary = run_experiment(self.config())
        self.assertEqual(
            set(summary["systems"]),
            {"lexical/flat", "lexical/greedy", "lexical/beam"},
        )
        for method in ("flat", "greedy", "beam"):
            self.assertTrue(
                (self.root / "results" / f"lexical-{method}.jsonl").is_file()
            )
        saved = json.loads((self.root / "results" / "metrics.json").read_text())
        self.assertEqual(saved["examples"]["evaluated"], 2)
        self.assertIn("accuracy_95ci", saved["systems"]["lexical/flat"])

    def test_selector_models_use_choice_traversal(self):
        summary = run_experiment(
            self.config(
                models={
                    "lexical": "lexical",
                    "uniform": "experiment.test_experiment:UniformSelector",
                }
            )
        )
        self.assertEqual(len(summary["systems"]), 6)
        self.assertEqual(
            summary["models"]["uniform"]["spec"],
            "experiment.test_experiment:UniformSelector",
        )
        records = [
            json.loads(line)
            for line in (self.root / "results" / "uniform-flat.jsonl")
            .read_text()
            .splitlines()
        ]
        self.assertTrue(all(record["calls"] == 1 for record in records))

    def test_flat_is_skipped_when_catalog_exceeds_option_limit(self):
        summary = run_experiment(
            self.config(
                models={
                    "limited": "experiment.test_experiment:LimitedSelector",
                }
            )
        )
        self.assertEqual(set(summary["systems"]), {"limited/greedy", "limited/beam"})
        self.assertIn("limited/flat", summary["skipped"])
        self.assertFalse((self.root / "results" / "limited-flat.jsonl").exists())

    def test_invalid_model_names_fail(self):
        with self.assertRaises(ValueError):
            run_experiment(self.config(models={"a/b": "lexical"}))

    def test_seeded_evaluation_cap_is_stable(self):
        config = self.config(max_examples=1)
        first = run_experiment(config)
        second = run_experiment(config)
        self.assertEqual(first["examples"], second["examples"])
        self.assertEqual(first["examples"]["evaluated"], 1)

    def test_larger_run_reuses_a_smaller_one(self):
        self.benchmark.write_text(
            "\n".join(
                json.dumps(
                    {
                        "id": f"CVE-2026-{index:04}",
                        "text": f"issue number {index}",
                        "labels": ["1"],
                        "split": "test",
                    }
                )
                for index in range(8)
            ),
            encoding="utf-8",
        )
        spec = {"counting": "experiment.test_experiment:CountingSelector"}
        CountingSelector.texts, CountingSelector.resolved_model = [], "v1"
        small = run_experiment(
            self.config(models=spec, max_examples=3, methods=["greedy"])
        )
        first_texts = set(CountingSelector.texts)
        small_records = (self.root / "results" / "counting-greedy.jsonl").read_text()
        CountingSelector.texts = []
        large = run_experiment(
            self.config(models=spec, max_examples=6, methods=["greedy"])
        )
        self.assertEqual(large["reused"], {"counting/greedy": 3})
        self.assertEqual(len(set(CountingSelector.texts)), 3)
        self.assertFalse(first_texts & set(CountingSelector.texts))
        large_records = (self.root / "results" / "counting-greedy.jsonl").read_text()
        for line in small_records.splitlines():
            self.assertIn(line, large_records.splitlines())
        self.assertEqual(large["examples"]["evaluated"], 6)
        self.assertEqual(small["examples"]["evaluated"], 3)

        CountingSelector.resolved_model = "v2"
        with self.assertRaisesRegex(ValueError, "Saved results came from v1"):
            run_experiment(self.config(models=spec, max_examples=8, methods=["greedy"]))

        CountingSelector.texts = []
        changed = run_experiment(
            self.config(
                models=spec,
                max_examples=6,
                methods=["greedy"],
                beam_width=2,
            )
        )
        self.assertEqual(changed["reused"], {"counting/greedy": 0})

    def test_invalid_methods_fail_before_work(self):
        with self.assertRaises(ValueError):
            run_experiment(self.config(methods=["chroma"]))

    def test_notebook_runs_the_core_workflow(self):
        try:
            import nbformat
        except ImportError:
            self.skipTest("Install notebook extra for notebook integration")
        notebook_path = Path(__file__).with_name("experiments.ipynb")
        notebook = nbformat.read(notebook_path, as_version=4)
        notebook.cells.insert(
            4,
            nbformat.v4.new_code_cell(
                "config.update("
                + repr(
                    self.config(
                        models={
                            "lexical": "lexical",
                            "limited": "experiment.test_experiment:LimitedSelector",
                        }
                    )
                )
                + ")"
            ),
        )
        from experiment.notebook_test_support import execute_notebook

        execute_notebook(notebook, Path.cwd())
        saved = json.loads((self.root / "results" / "metrics.json").read_text())
        self.assertEqual(len(saved["systems"]), 5)
        self.assertIn("limited/flat", saved["skipped"])
        errors = [
            output
            for cell in notebook.cells
            for output in cell.get("outputs", [])
            if output.get("output_type") == "error"
        ]
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
