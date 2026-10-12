import importlib
import json
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from classification import STOP, load_scorer, select_classify
from experiment.jev_selector import JevSelector


class JevSelectorTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            str(index): {"Name": f"Weakness {index}", "Description": f"Definition {index}"}
            for index in range(1, 6)
        }
        self.client = Mock()
        self.sdk = SimpleNamespace(
            Choice=lambda **kwargs: SimpleNamespace(**kwargs),
            RetryPolicy=Mock(side_effect=lambda **kwargs: SimpleNamespace(**kwargs)),
            TypeSafeClient=Mock(return_value=self.client),
            __version__="0.7.4",
        )
        self.addCleanup(patch.stopall)
        patch.dict(sys.modules, {"typesafe_sdk": self.sdk}).start()
        patch.dict("os.environ", {"TYPESAFE_DEFAULT_MODEL": "", "TYPESAFE_BASE_URL": ""}).start()
        self.model = "test-model-version"
        self.client.system_one.side_effect = self.respond

    def respond(self, *, state, questions):
        criteria = questions["cwe"].criteria
        weights = {key: (1 if key == STOP else int(key[4:])) for key in criteria}
        total = sum(weights.values())
        return SimpleNamespace(
            choices={"cwe": SimpleNamespace(
                probabilities={key: weight / total for key, weight in weights.items()}
            )},
            model=self.model,
            usage=SimpleNamespace(input_tokens=10, output_tokens=2),
        )

    def test_one_choice_question_over_offered_cwes(self):
        selector = load_scorer("experiment.jev_selector:create_selector", self.catalog)
        values = selector.select("report", ["2", "3"])
        self.assertEqual(values, {"2": .4, "3": .6})
        call = self.client.system_one.call_args.kwargs
        self.assertEqual(call["state"], {"document": "report"})
        question = call["questions"]["cwe"]
        self.assertEqual(question.criteria, {
            "CWE-2": "Weakness 2: Definition 2", "CWE-3": "Weakness 3: Definition 3",
        })
        self.assertNotIn(STOP, question.instructions)
        self.assertEqual(selector.last_usage, {
            "input_tokens": 10, "output_tokens": 2, "cost": None, "requests": 1,
        })
        kwargs = self.sdk.TypeSafeClient.call_args.kwargs
        self.assertEqual(kwargs["retry"].max_retries, 0)
        self.assertEqual(selector.metadata["resolved_model"], "test-model-version")

    def test_rejects_more_options_than_jev_accepts(self):
        selector = JevSelector(self.catalog)
        self.assertEqual(selector.max_options, 255)
        selector.max_options = 2
        with self.assertRaisesRegex(ValueError, "at most 2"):
            selector.select("report", ["2", "3"], current="1")
        self.client.system_one.assert_not_called()

    def test_traversal_offers_stop_for_current_cwe(self):
        selector = JevSelector(self.catalog)
        values = selector.select("report", ["4"], current="2")
        self.assertEqual(values, {"4": .8, STOP: .2})
        question = self.client.system_one.call_args.kwargs["questions"]["cwe"]
        self.assertIn("CWE-2 (Weakness 2)", question.criteria[STOP])
        self.assertIn("refines CWE-2", question.instructions)

    def test_parent_style_offers_current_cwe_as_an_option(self):
        selector = load_scorer(
            "experiment.jev_selector:create_parent_selector", self.catalog
        )
        values = selector.select("report", ["4"], current="2")
        self.assertEqual(values, {"4": 4 / 6, STOP: 2 / 6})
        question = self.client.system_one.call_args.kwargs["questions"]["cwe"]
        self.assertEqual(question.criteria, {
            "CWE-2": "Weakness 2: Definition 2", "CWE-4": "Weakness 4: Definition 4",
        })
        self.assertIn("most specific option", question.instructions)
        self.assertEqual(selector.metadata["stop_style"], "parent")
        self.assertEqual(selector.select("report", ["2", "3"]), {"2": .4, "3": .6})
        with self.assertRaises(ValueError):
            selector.select("report", ["2"], current="2")
        with self.assertRaises(ValueError):
            JevSelector(self.catalog, stop_style="none")

    def test_runs_flat_greedy_and_beam(self):
        graph = SimpleNamespace(
            labels=self.catalog, roots=["1", "2"],
            children={"1": {"3", "4"}, "2": {"5"}, "3": set(), "4": set(), "5": set()},
        )
        selector = JevSelector(self.catalog)
        flat = select_classify("report", graph, selector, top_k=2)
        self.assertEqual((flat.predictions, flat.calls, flat.candidates_scored),
                         (["5", "4"], 1, 5))
        greedy = select_classify("report", graph, selector, beam_width=1)
        self.assertEqual(greedy.paths, [["2", "5"]])
        beam = select_classify("report", graph, selector, beam_width=2, top_k=5)
        self.assertEqual(beam.predictions[0], "5")
        self.assertEqual(beam.input_tokens, beam.calls * 10)

    def test_rejects_bad_responses_and_settings(self):
        selector = JevSelector(self.catalog)
        self.client.system_one.side_effect = lambda **_: SimpleNamespace(
            choices={"cwe": SimpleNamespace(probabilities={"CWE-1": .5})},
            model="test-model-version", usage=SimpleNamespace(),
        )
        with self.assertRaisesRegex(ValueError, "every offered option"):
            selector.select("report", ["1", "2"])
        self.client.system_one.side_effect = self.respond
        selector.select("report", ["1"])
        self.model = "other-version"
        with self.assertRaisesRegex(ValueError, "model changed"):
            selector.select("report", ["1"])
        with self.assertRaisesRegex(ValueError, "Unknown CWE"):
            selector.select("report", ["99"])
        for url in ("ftp://host", "http://remote.example", "https://u:p@host"):
            with self.assertRaises(ValueError):
                JevSelector(self.catalog, base_url=url)

    def test_missing_dependency(self):
        with patch.dict(sys.modules, {"typesafe_sdk": None}):
            importlib.reload(importlib.import_module("experiment.jev_selector"))
            with self.assertRaisesRegex(ImportError, "typesafe-sdk==0.7.4"):
                load_scorer("experiment.jev_selector:create_selector", self.catalog)


class InstalledSDKContractTests(unittest.TestCase):
    def test_real_sdk_choice_request_and_response_with_mock_transport(self):
        try:
            import httpx2
            import typesafe_sdk
        except ModuleNotFoundError as error:
            if error.name != "typesafe_sdk":
                raise
            self.skipTest("Optional typesafe-sdk is not installed")
        importlib.reload(importlib.import_module("experiment.jev_selector"))
        from experiment.jev_selector import JevSelector as Selector

        real_client = typesafe_sdk.TypeSafeClient
        sent = []

        def handler(request):
            self.assertEqual(str(request.url), "https://jev.example.invalid/api/v1/systemone")
            payload = json.loads(request.content)
            sent.append(payload)
            options = list(payload["questions"]["cwe"]["criteria"])
            return httpx2.Response(200, json={
                "model": "test-resolved-version",
                "answers": {"cwe": {
                    "type": "choice", "choice": options[0], "confidence": .75,
                    "probabilities": {option: (.75 if i == 0 else .25)
                                      for i, option in enumerate(options)},
                }},
                "usage": {"input_tokens": 12, "output_tokens": 3},
            })

        catalog = {
            "79": {"Name": "XSS", "Description": "Improper output neutralization"},
            "80": {"Name": "Basic XSS", "Description": "Script tags"},
        }
        with (
            patch.dict("os.environ", {
                "TYPESAFE_API_KEY": "unit-test-not-a-credential",
                "TYPESAFE_DEFAULT_MODEL": "test-requested-version",
            }),
            patch.object(typesafe_sdk, "TypeSafeClient", side_effect=lambda **kwargs: real_client(
                **kwargs, transport=httpx2.MockTransport(handler))),
        ):
            selector = Selector(catalog, base_url="https://jev.example.invalid/api")
            self.assertEqual(selector.select("report", ["80"], current="79"),
                             {"80": .75, STOP: .25})
            question = sent[0]["questions"]["cwe"]
            self.assertEqual(sent[0]["model"], "test-requested-version")
            self.assertEqual(sent[0]["state"], {"document": "report"})
            self.assertEqual(question["type"], "choice")
            self.assertEqual(set(question["criteria"]), {"CWE-80", STOP})
            self.assertEqual(selector.metadata["resolved_model"], "test-resolved-version")


if __name__ == "__main__":
    unittest.main()
