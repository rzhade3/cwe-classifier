import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from classification import CWEGraph
from dataset_sources import snapshot_sha256
from datasets import build_benchmark
from experiment import run_notebook
import test_classification


class DatasetIntegrationTests(unittest.TestCase):
    def setUp(self):
        fixture = test_classification.ClassificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.catalog_path = fixture.path
        self.graph = CWEGraph(fixture.path)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        records = [
            {"id": f"VENDOR-{index}", "aliases": [f"CVE-2026-{1000 + index}"],
             "text": f"Unique issue {index} " + ("database query injection" if index % 2 else "memory write bounds"),
             "labels": ["2" if index % 2 else "4"], "published": "2026-01-01",
             "ecosystems": ["npm"], "vendors": ["example"]}
            for index in range(8)
        ]
        records.append({"id": "VENDOR-unknown", "text": "Unexplained unexpected behavior",
                        "labels": [], "insufficient_information": True,
                        "published": "2026-01-01", "aliases": [], "ecosystems": [],
                        "vendors": []})
        source = self.root / "vendor.jsonl"
        source.write_text("".join(json.dumps(record) + "\n" for record in records))
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"sources": [{
            "kind": "vendor", "path": str(source),
            "sha256": snapshot_sha256(source), "revision": "fixture-2026-01-01"
        }]}))

    def config(self, command="run"):
        return {
            "command": command, "demo": False, "catalog": str(self.catalog_path),
            "benchmark": None, "dataset_manifest": str(self.manifest),
            "dataset_output": str(self.root / "prepared"),
            "output": str(self.root / "results"), "view": "1000", "split": "test",
            "training_ids": None, "scorer": "lexical", "methods": ["flat", "greedy"],
            "one_shot_predictions": None, "beam_width": 2, "top_k": 2,
            "threshold": 0.0, "margin": 0.0, "seed": 0, "dev_fraction": 0,
            "bootstrap_samples": 20, "max_prompt_chars": None, "sample_size": 1,
            "balanced_per_label": 2,
        }

    def test_builder_retains_diagnostics_without_fabricating_gold(self):
        groups, report, queue = build_benchmark(
            self.manifest, self.graph.labels, self.root / "build",
            dev_fraction=0, sample_size=1, balanced_per_label=2
        )
        self.assertTrue(groups)
        self.assertTrue(queue)
        self.assertTrue((self.root / "build" / "dataset-report.json").is_file())
        benchmark = [json.loads(line) for line in
                     (self.root / "build" / "benchmark.jsonl").read_text().splitlines()]
        self.assertTrue(all(record["labels"] for record in benchmark))
        self.assertEqual(sum("natural" in record["slices"] for record in benchmark), 1)
        self.assertIn("provenance", report)
        blind_sample = [json.loads(line) for line in
                        (self.root / "build" / "expert_review_sample.jsonl").read_text().splitlines()]
        self.assertTrue(blind_sample)
        self.assertTrue(all(record["labels"] == [] and not record["expert_reviewed"]
                            for record in blind_sample))

    def test_notebook_primary_excludes_balanced_only_examples(self):
        with redirect_stdout(StringIO()):
            state = run_notebook(self.config())
        summary = state["summary"]
        self.assertEqual(summary["primary_population"], "natural-distribution sampled groups")
        self.assertIn("balanced", summary["slice_metrics"])
        self.assertEqual(len(state["primary_results"]["flat"]), 1)
        self.assertGreaterEqual(len(state["results"]["flat"]), 1)
        self.assertNotIn("insufficient_information", summary["slice_metrics"])
        self.assertTrue(summary["dataset_report"]["provenance"])

    def test_build_only_exports_both_splits_and_does_not_run_model(self):
        with redirect_stdout(StringIO()):
            state = run_notebook(self.config("build-benchmark"))
        self.assertEqual(state["results"], {})
        self.assertIsNone(state["summary"])
        self.assertTrue((self.root / "results" / "review_queue.jsonl").is_file())

    def test_metadata_survives_prepared_jsonl_loading(self):
        from benchmark import load_benchmark
        build_benchmark(self.manifest, self.graph.labels, self.root / "build",
                        dev_fraction=0, sample_size=1)
        examples, _ = load_benchmark(self.root / "build" / "benchmark.jsonl",
                                     list(self.graph.labels))
        self.assertTrue(all("slices" in record and "aliases" in record for record in examples))

    def test_cli_build_without_legacy_benchmark_argument(self):
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("experiment.py")),
             "build-benchmark", "--catalog", str(self.catalog_path),
             "--dataset-manifest", str(self.manifest), "--output", str(self.root / "cli"),
             "--dev-fraction", "0"], capture_output=True, text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue((self.root / "cli" / "dataset-report.json").is_file())

    def test_jupyter_multisource_workflow(self):
        try:
            import nbformat
            from nbclient import NotebookClient
        except ImportError:
            self.skipTest("Install notebook extra for Jupyter integration")
        path = Path(__file__).with_name("experiments.ipynb")
        notebook = nbformat.read(path, as_version=4)
        config = self.config()
        notebook.cells.insert(0, nbformat.v4.new_code_cell(
            "experiment_config = " + repr(config)
        ))
        NotebookClient(notebook, timeout=120, kernel_name="python3",
                       resources={"metadata": {"path": str(path.parent)}}).execute()
        summary = json.loads((self.root / "results" / "summary.json").read_text())
        self.assertEqual(summary["primary_population"], "natural-distribution sampled groups")
        self.assertIn("balanced", summary["slice_metrics"])

    def test_prepared_metadata_validation(self):
        from benchmark import load_benchmark
        source = self.root / "invalid.jsonl"
        for field, value in [("slices", "natural"), ("aliases", [1]), ("kev", "yes")]:
            source.write_text(json.dumps({
                "id": "x", "text": "description", "labels": ["2"], "split": "test",
                field: value,
            }) + "\n")
            with self.subTest(field=field), self.assertRaises(ValueError):
                load_benchmark(source, list(self.graph.labels))

    def test_evaluation_caps_are_deterministic_and_budget_precedes_model_loading(self):
        config = {**self.config(), "max_eval_examples": 1}
        with redirect_stdout(StringIO()):
            first = run_notebook(config)
            second = run_notebook(config)
        self.assertEqual(len(first["examples"]), 1)
        self.assertEqual(first["examples"], second["examples"])
        self.assertEqual(first["summary"]["evaluation_sampling"]["selected_count"], 1)
        with redirect_stdout(StringIO()), self.assertRaisesRegex(ValueError, "budget exceeded"):
            run_notebook({
                **self.config(), "scorer": "uninstalled_paid_model:create",
                "max_live_examples": 1, "max_candidate_evaluations": 1,
            })

    def test_family_slice_preserves_multi_parent_membership(self):
        with redirect_stdout(StringIO()):
            state = run_notebook(self.config())
        self.assertIn("family:CWE-1", state["summary"]["slice_metrics"])
        self.assertIn("source:vendor", state["summary"]["slice_metrics"])

    def test_prepared_aliases_are_checked_for_training_and_catalog_overlap(self):
        from benchmark import load_benchmark
        source = self.root / "aliases.jsonl"
        source.write_text(json.dumps({
            "id": "CVE-2026-1234", "aliases": ["GHSA-abcd-abcd-abcd", "CVE-2026-9999"],
            "text": "Independent description", "labels": ["2"], "split": "test",
            "slices": ["natural"],
        }) + "\n")
        examples, audit = load_benchmark(
            source, list(self.graph.labels), training_ids=["ghsa-ABCD-ABCD-ABCD"]
        )
        self.assertEqual(examples, [])
        self.assertEqual(audit["training_overlap"], 1)
        examples, audit = load_benchmark(
            source, list(self.graph.labels), catalog={"2": {
                "Observed Examples": "::REFERENCE:CVE-2026-9999:DESCRIPTION:Example:LINK:x::"
            }}
        )
        self.assertEqual(examples, [])
        self.assertEqual(audit["catalog_overlap"], 1)


if __name__ == "__main__":
    unittest.main()
