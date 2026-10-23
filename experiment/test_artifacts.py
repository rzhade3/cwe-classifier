import json
import unittest
from pathlib import Path
from unittest.mock import patch

from experiment import test_experiment as fixtures
from experiment.artifacts import append_checkpoint, load_checkpoint, output_lock
from experiment.runner import run_experiment


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ExperimentTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root

    def test_torn_final_line_is_recovered_but_complete_corruption_fails(self):
        path = self.root / "journal.jsonl"
        append_checkpoint(path, {"id": "one"}, {})
        with path.open("ab") as stream:
            stream.write(b'{"record":')
        self.assertEqual(list(load_checkpoint(path)), ["one"])
        append_checkpoint(path, {"id": "two"}, {})
        self.assertEqual(list(load_checkpoint(path)), ["one", "two"])
        path.write_text("not json\n")
        with self.assertRaises(json.JSONDecodeError):
            load_checkpoint(path)

    def test_output_writer_lock_is_exclusive_and_released_on_failure(self):
        with self.assertRaisesRegex(RuntimeError, "failure"):
            with output_lock(self.root):
                with self.assertRaisesRegex(RuntimeError, "Another run"):
                    with output_lock(self.root):
                        pass
                raise RuntimeError("failure")
        with output_lock(self.root):
            pass

    def test_catalog_change_invalidates_cache_and_shrink_preserves_it(self):
        config = self.fixture.config(methods=["flat"])
        run_experiment(config)
        smaller = run_experiment({**config, "max_examples": 1})
        self.assertEqual(smaller["reused"]["lexical/flat"], 1)
        larger = run_experiment(config)
        self.assertEqual(larger["reused"]["lexical/flat"], 2)
        path = self.fixture.graph_path
        path.write_text(path.read_text().replace("Stable", "Draft"))
        self.assertEqual(run_experiment(config)["reused"]["lexical/flat"], 0)

    def test_interruption_retains_completed_records(self):
        config = self.fixture.config(methods=["flat"])
        from classification import LexicalScorer

        original = LexicalScorer.score
        calls = 0

        def flaky(scorer, text, labels):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("simulated outage")
            return original(scorer, text, labels)

        with patch.object(LexicalScorer, "score", flaky):
            with self.assertRaisesRegex(RuntimeError, "simulated outage"):
                run_experiment(config)
        self.assertFalse((Path(config["output"]) / "metrics.json").exists())
        self.assertEqual(run_experiment(config)["reused"]["lexical/flat"], 1)

    def test_typos_and_unsafe_names_fail(self):
        for changes in (
            {"max_example": 3},
            {"models": {"../oops": "lexical"}},
            {"model_options": {"lexical": {"api_key": "do-not-persist"}}},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                run_experiment(self.fixture.config(**changes))
