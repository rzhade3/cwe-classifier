import importlib
import json
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from classification import classify, load_scorer
from jev_scorer import JevScorer


class JevScorerTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            str(index): {"Name": f"Weakness {index}", "Description": f"Definition {index}"}
            for index in range(65)
        }
        self.client = Mock()
        self.sdk = SimpleNamespace(
            Noul=lambda **kwargs: SimpleNamespace(**kwargs),
            RetryPolicy=Mock(side_effect=lambda **kwargs: SimpleNamespace(**kwargs)),
            TypeSafeClient=Mock(return_value=self.client),
            __version__="0.7.4",
        )
        self.addCleanup(patch.stopall)
        patch.dict(sys.modules, {"typesafe_sdk": self.sdk}).start()
        patch.dict("os.environ", {"TYPESAFE_DEFAULT_MODEL": "", "TYPESAFE_BASE_URL": ""}).start()
        self.client.system_one.side_effect = self.respond

    @staticmethod
    def respond(*, state, questions):
        return SimpleNamespace(
            nouls={label: SimpleNamespace(noul=int(label) / 100) for label in questions},
            model="test-model-version",
            usage=SimpleNamespace(input_tokens=10, output_tokens=2),
        )

    def test_factory_batches_usage_and_environment_credentials(self):
        scorer = load_scorer("jev_scorer:create_scorer", self.catalog)
        labels = list(self.catalog)
        scores = scorer.score("vulnerability report", labels)
        self.assertEqual(scores, {label: int(label) / 100 for label in labels})
        self.assertEqual(
            [len(call.kwargs["questions"]) for call in self.client.system_one.call_args_list],
            [32, 32, 1],
        )
        for call in self.client.system_one.call_args_list:
            self.assertEqual(call.kwargs["state"], {"document": "vulnerability report"})
            self.assertEqual(set(call.kwargs), {"state", "questions"})
        self.assertEqual(scorer.last_usage, {
            "input_tokens": 30, "output_tokens": 6, "cost": None, "requests": 3
        })
        kwargs = self.sdk.TypeSafeClient.call_args.kwargs
        self.assertEqual(set(kwargs), {"model", "retry"})
        self.assertIsNone(kwargs["model"])
        self.assertEqual(kwargs["retry"].max_retries, 0)
        self.assertEqual(scorer.sdk_version, "0.7.4")
        self.assertEqual(scorer.resolved_model, "test-model-version")

    def test_fixed_independent_questions_and_comparable_scores(self):
        self.catalog["1"]["Extended Description"] = "More detail"
        scorer = JevScorer(self.catalog, batch_size=1)
        alone = scorer.score("report", ["1"])
        first_question = self.client.system_one.call_args.kwargs["questions"]["1"]
        together = scorer.score("report", ["1", "2", "1"])
        self.assertEqual(alone["1"], together["1"])
        self.assertEqual(scorer.last_usage["requests"], 2)
        self.assertIs(first_question, scorer._questions["1"])
        self.assertIn("CWE-1: Weakness 1", first_question.instructions)
        self.assertIn("More detail", first_question.instructions)
        self.assertEqual(set(first_question.criteria), {"true", "false"})

    def test_classifier_call_accounting_is_not_request_accounting(self):
        scorer = JevScorer(self.catalog)
        before = scorer.requests
        result = classify("report", SimpleNamespace(labels=self.catalog), scorer, top_k=2)
        self.assertEqual(result.predictions, ["64", "63"])
        self.assertEqual(result.calls, 1)
        self.assertEqual(scorer.last_usage["requests"], 3)
        self.assertEqual(scorer.requests - before, 3)
        self.assertEqual(result.input_tokens, 30)
        self.assertEqual(result.output_tokens, 6)
        self.assertIsNone(result.cost)
        self.client.system_one.side_effect = self.respond
        scorer.score("report", ["1"])
        self.assertEqual(scorer.last_usage["requests"], 1)
        self.assertEqual(scorer.requests, 4)
        self.assertEqual(scorer.last_usage["input_tokens"], 10)

    def test_metadata_snapshots_before_and_after_scoring(self):
        scorer = JevScorer(self.catalog)
        before = scorer.metadata
        self.assertEqual(before, {
            "base_url": None,
            "requested_model": None,
            "resolved_model": None,
            "sdk_version": "0.7.4",
            "batch_size": 32,
            "question": "Fixed independent per-CWE Noul yes/no question; score is P(yes).",
            "calibration": (
                "No candidate-set normalization; cross-label/batch comparability "
                "and thresholds require validation on development data."
            ),
        })
        self.assertEqual(scorer.requests, 0)
        scorer.score("private report", ["1"])
        self.assertIsNone(before["resolved_model"])
        self.assertEqual(scorer.metadata["resolved_model"], "test-model-version")
        before["batch_size"] = 999
        self.assertEqual(scorer.metadata["batch_size"], 32)
        self.assertNotIn("private report", json.dumps(scorer.metadata))

    def test_optional_pin_and_model_drift(self):
        with patch.dict("os.environ", {"TYPESAFE_DEFAULT_MODEL": " test-version "}):
            scorer = JevScorer(self.catalog)
        self.assertEqual(scorer.requested_model, "test-version")
        self.assertEqual(self.sdk.TypeSafeClient.call_args.kwargs["model"], "test-version")
        scorer.score("report", ["1"])
        response = self.respond(state={}, questions={"2": None})
        response.model = "different-version"
        self.client.system_one.side_effect = None
        self.client.system_one.return_value = response
        with self.assertRaisesRegex(ValueError, "model changed"):
            scorer.score("report", ["2"])

    def test_endpoint_environment_and_explicit_overrides(self):
        with patch.dict("os.environ", {
            "TYPESAFE_BASE_URL": " https://jev.example.invalid/api/ ",
            "TYPESAFE_DEFAULT_MODEL": "environment-model",
        }):
            scorer = JevScorer(self.catalog)
            self.assertEqual(scorer.metadata["base_url"], "https://jev.example.invalid/api")
            self.assertEqual(self.sdk.TypeSafeClient.call_args.kwargs["base_url"],
                             "https://jev.example.invalid/api")
            scorer = JevScorer(self.catalog, base_url="http://localhost:8080/v1/",
                               model="explicit-model", timeout=5)
            options = self.sdk.TypeSafeClient.call_args.kwargs
            self.assertEqual(options["base_url"], "http://localhost:8080/v1")
            self.assertEqual(options["model"], "explicit-model")
            self.assertEqual(options["timeout"], 5)
            self.assertEqual(options["retry"].max_retries, 0)
            self.assertEqual(scorer.metadata["requested_model"], "explicit-model")
            self.assertNotIn("api_key", options)

    def test_invalid_endpoint_and_options_fail_before_client_creation(self):
        for endpoint in ("", "ftp://localhost", "******example.invalid",
                         "https://example.invalid?token=secret", "https://example.invalid/#x",
                         "http://example.invalid", "https://bad host", 123,
                         "https://example.invalid:bad", "https://example.invalid:0",
                         "https://example.invalid/\x00"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                JevScorer(self.catalog, base_url=endpoint)
        for timeout in (0, -1, True, float("nan"), float("inf"), "5"):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                JevScorer(self.catalog, timeout=timeout)
        for model in ("", " ", 123):
            with self.subTest(model=model), self.assertRaises(ValueError):
                JevScorer(self.catalog, model=model)
        self.sdk.TypeSafeClient.assert_not_called()

    def test_missing_usage_stays_unknown_across_batches(self):
        scorer = JevScorer(self.catalog, batch_size=1)
        responses = [self.respond(state={}, questions={label: None}) for label in ("1", "2")]
        responses[0].usage.input_tokens = None
        responses[1].usage.output_tokens = None
        self.client.system_one.side_effect = responses
        scorer.score("report", ["1", "2"])
        self.assertIsNone(scorer.last_usage["input_tokens"])
        self.assertIsNone(scorer.last_usage["output_tokens"])
        self.assertIsNone(scorer.last_usage["cost"])

    def test_error_propagation_no_retry_and_partial_usage_unknown(self):
        scorer = JevScorer(self.catalog, batch_size=1)
        self.client.system_one.side_effect = [
            self.respond(state={}, questions={"1": None}), RuntimeError("network failure")
        ]
        with self.assertRaisesRegex(RuntimeError, "network failure"):
            scorer.score("report", ["1", "2", "3"])
        self.assertEqual(self.client.system_one.call_count, 2)
        self.assertEqual(scorer.requests, 2)
        self.assertEqual(scorer.last_usage["requests"], 2)
        self.assertIsNone(scorer.last_usage["input_tokens"])

    def test_invalid_likelihoods_answers_and_usage(self):
        scorer = JevScorer(self.catalog)
        for value in (True, float("nan"), float("inf"), -0.1, 1.1, "0.5"):
            with self.subTest(value=value):
                response = self.respond(state={}, questions={"1": None})
                response.nouls["1"].noul = value
                self.client.system_one.side_effect = None
                self.client.system_one.return_value = response
                with self.assertRaisesRegex(ValueError, "likelihood"):
                    scorer.score("report", ["1"])
        for answers in ({}, {"2": SimpleNamespace(noul=0.2)}):
            self.client.system_one.return_value = SimpleNamespace(
                nouls=answers, model="test-model-version",
                usage=SimpleNamespace(input_tokens=1, output_tokens=1),
            )
            with self.assertRaisesRegex(ValueError, "requested Noul"):
                scorer.score("report", ["1"])
        for value in (-1, True, 1.5, float("nan")):
            response = self.respond(state={}, questions={"1": None})
            response.usage.input_tokens = value
            self.client.system_one.return_value = response
            with self.assertRaisesRegex(ValueError, "usage"):
                scorer.score("report", ["1"])

    def test_empty_unknown_closed_and_invalid_batch_size(self):
        scorer = JevScorer(self.catalog)
        self.assertEqual(scorer.score("report", []), {})
        self.assertEqual(scorer.last_usage["requests"], 0)
        self.assertEqual(scorer.requests, 0)
        with self.assertRaisesRegex(ValueError, "Unknown CWE"):
            scorer.score("report", ["1", "999"])
        self.client.system_one.assert_not_called()
        self.assertEqual(scorer.requests, 0)
        scorer.close()
        scorer.close()
        self.client.close.assert_called_once_with()
        with self.assertRaisesRegex(RuntimeError, "closed"):
            scorer.score("report", ["1"])
        for size in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                JevScorer(self.catalog, batch_size=size)

    def test_lazy_import_and_missing_dependency(self):
        with patch.dict(sys.modules, {"typesafe_sdk": None}):
            importlib.reload(importlib.import_module("jev_scorer"))
            with self.assertRaisesRegex(ImportError, "typesafe-sdk==0.7.4"):
                load_scorer("jev_scorer:create_scorer", self.catalog)


class InstalledSDKContractTests(unittest.TestCase):
    def test_real_sdk_questions_request_and_response_with_mock_transport(self):
        try:
            import typesafe_sdk
            import httpx2
        except ModuleNotFoundError as error:
            if error.name != "typesafe_sdk":
                raise
            self.skipTest("Optional typesafe-sdk is not installed")

        real_client = typesafe_sdk.TypeSafeClient
        sent = []

        def handler(request):
            self.assertEqual(str(request.url), "https://jev.example.invalid/api/v1/systemone")
            payload = json.loads(request.content)
            sent.append(payload)
            return httpx2.Response(200, json={
                "model": "test-resolved-version",
                "answers": {
                    label: {"type": "noul", "noul": 0.75}
                    for label in payload["questions"]
                },
                "usage": {"input_tokens": 12, "output_tokens": 3},
            })

        def create_client(**kwargs):
            return real_client(
                **kwargs, transport=httpx2.MockTransport(handler),
            )

        catalog = {"79": {"Name": "XSS", "Description": "Improper output neutralization"}}
        with (
            patch.dict("os.environ", {
                "TYPESAFE_API_KEY": "unit-test-not-a-credential",
                "TYPESAFE_DEFAULT_MODEL": "test-requested-version",
            }),
            patch.object(typesafe_sdk, "TypeSafeClient", side_effect=create_client),
        ):
            scorer = JevScorer(catalog, base_url="https://jev.example.invalid/api")
            try:
                self.assertIsInstance(scorer._questions["79"], typesafe_sdk.Noul)
                self.assertEqual(scorer.score("test report", ["79"]), {"79": 0.75})
                self.assertEqual(len(sent), 1)
                self.assertEqual(sent[0]["model"], "test-requested-version")
                self.assertEqual(sent[0]["state"], {"document": "test report"})
                self.assertEqual(sent[0]["questions"]["79"]["type"], "noul")
                self.assertEqual(
                    set(sent[0]["questions"]["79"]["criteria"]), {"true", "false"}
                )
                self.assertEqual(scorer.metadata["resolved_model"], "test-resolved-version")
                self.assertEqual(scorer.requests, 1)
                self.assertEqual(scorer.last_usage, {
                    "input_tokens": 12, "output_tokens": 3, "cost": None, "requests": 1,
                })
            finally:
                scorer.close()


if __name__ == "__main__":
    unittest.main()
