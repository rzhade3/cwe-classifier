import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import main
from classification import STOP


class FakeSelector:
    resolved_model = "jev-test"

    def select(self, text, labels, current=None):
        # Prefer the lowest-numbered option; stop once at a leaf-ish depth.
        options = sorted(labels, key=int)
        weights = {label: 1.0 / (rank + 1) for rank, label in enumerate(options)}
        if current is not None:
            weights[STOP] = 0.5
        total = sum(weights.values())
        return {label: weight / total for label, weight in weights.items()}


class MainTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(main, "ENV_FILES", ()).start()
        patch.dict("os.environ", {"TYPESAFE_API_KEY": "test"}).start()
        self.factory = patch.object(
            main, "create_rich_parent_selector", return_value=FakeSelector()
        ).start()

    def run_main(self, *argv):
        output = io.StringIO()
        with redirect_stdout(output):
            main.main(["--provider", "jev", *argv])
        return output.getvalue()

    def test_json_output_lists_ranked_suggestions_with_paths(self):
        data = json.loads(self.run_main("--json", "--top-k", "3", "SQL", "injection"))
        self.assertEqual(data["model"], "jev-test")
        suggestions = data["suggestions"]
        self.assertTrue(1 <= len(suggestions) <= 3)
        scores = [suggestion["score"] for suggestion in suggestions]
        self.assertEqual(scores, sorted(scores, reverse=True))
        for suggestion in suggestions:
            self.assertTrue(suggestion["cwe"].startswith("CWE-"))
            self.assertEqual(suggestion["path"][-1], suggestion["cwe"])
            self.assertTrue(suggestion["name"])
        self.assertEqual(self.factory.call_args.kwargs["model"], main.TESTED_MODEL)

    def test_text_output_includes_accuracy_note(self):
        output = self.run_main("--model", "jev-other", "buffer overflow")
        self.assertIn("Suggested CWEs (jev-test", output)
        self.assertIn(main.ACCURACY_NOTE, output)
        self.assertEqual(self.factory.call_args.kwargs["model"], "jev-other")

    def test_openai_is_the_default_without_a_typesafe_key(self):
        with (
            patch.dict(
                "os.environ", {"OPENAI_API_KEY": "test", "TYPESAFE_API_KEY": ""}
            ),
            patch.object(
                main, "create_decisions_selector", return_value=FakeSelector()
            ) as factory,
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                main.main(["--json", "SQL injection"])
            self.assertTrue(json.loads(output.getvalue())["suggestions"])
            self.assertEqual(factory.call_args.kwargs["model"], "gpt-6-luna")
            self.factory.assert_not_called()

    def test_requires_api_key_and_text(self):
        with patch.dict("os.environ", {"TYPESAFE_API_KEY": ""}):
            with self.assertRaisesRegex(SystemExit, "TYPESAFE_API_KEY"):
                main.main(["--provider", "jev", "text"])
        with patch("sys.stdin", io.StringIO("")):
            with self.assertRaisesRegex(SystemExit, "no vulnerability text"):
                main.main([])
        self.factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
