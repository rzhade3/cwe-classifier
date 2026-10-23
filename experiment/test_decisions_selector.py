"""Exercise the installed SDK's real serialization and parsing, without credentials."""

import json
import unittest
from unittest.mock import patch

import httpx2
from openai import OpenAI

from classification import STOP, CWEGraph, select_classify
from experiment.decisions_selector import DecisionsSelector


class DecisionsTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            str(i): {"Name": f"name {i}", "Description": f"definition {i}"}
            for i in range(1, 4)
        }
        self.seen = []
        self.change = lambda payload: payload

        def respond(request):
            body = json.loads(request.content)
            self.seen.append((request.url.path, body))
            question = body["questions"][0]
            choices = question["choices"]
            payload = {
                "model": "gpt-6-luna-test",
                "usage": {"input_tokens": 24, "output_tokens": 0},
                "answers": [
                    {
                        "name": "cwe",
                        "type": "choice",
                        "choice": choices[0]["value"],
                        "confidence": 1 / len(choices),
                        "probabilities": [
                            {"value": c["value"], "probability": 1 / len(choices)}
                            for c in choices
                        ],
                    }
                ],
            }
            return httpx2.Response(200, json=self.change(payload))

        self.http = httpx2.Client(
            transport=httpx2.MockTransport(respond), trust_env=False
        )
        self.client = OpenAI(
            api_key="test-not-a-credential", http_client=self.http, max_retries=0
        )
        self.addCleanup(self.client.close)

    def selector(self, **options):
        return DecisionsSelector(self.catalog, client=self.client, **options)

    def test_real_sdk_request_distribution_stop_and_usage(self):
        selector = self.selector()
        self.assertEqual(
            selector.select("document", ["2", "3"], "1"),
            {"2": 1 / 3, "3": 1 / 3, STOP: 1 / 3},
        )
        path, request = self.seen[0]
        self.assertEqual(path, "/v1/decisions")
        self.assertEqual(request["model"], "gpt-6-luna")
        self.assertEqual(request["input"], "document")
        self.assertEqual(request["questions"][0]["type"], "choice")
        self.assertEqual(
            {c["value"] for c in request["questions"][0]["choices"]},
            {"CWE-1", "CWE-2", "CWE-3"},
        )
        self.assertEqual(selector.last_usage["input_tokens"], 24)
        self.assertEqual(selector.requests, 1)
        self.assertEqual(selector.metadata["resolved_model"], "gpt-6-luna-test")

    def test_stop_style_and_singleton_have_no_fake_request(self):
        selector = self.selector(stop_style="stop")
        self.assertEqual(selector.select("text", ["1"]), {"1": 1})
        self.assertEqual(selector.requests, 0)
        selector.select("text", ["2"], "1")
        self.assertIn(
            STOP, {c["value"] for c in self.seen[0][1]["questions"][0]["choices"]}
        )

    def test_refusal_missing_duplicate_and_unnormalized_probabilities(self):
        def refusal(p):
            p["answers"] = [{"type": "refusal", "name": "cwe"}]
            return p

        def duplicate(p):
            p["answers"][0]["probabilities"] *= 2
            return p

        def unnormalized(p):
            p["answers"][0]["probabilities"][0]["probability"] = 0.1
            return p

        def missing(p):
            p["answers"][0]["probabilities"].pop()
            return p

        for change in (refusal, duplicate, unnormalized, missing):
            with self.subTest(change=change.__name__):
                self.change = change
                with self.assertRaises(ValueError):
                    self.selector().select("text", ["1", "2"])

    def test_reject_changed_model_and_invalid_options(self):
        selector = self.selector()
        selector.select("text", ["1", "2"])
        self.change = lambda p: {**p, "model": "changed"}
        with self.assertRaisesRegex(ValueError, "model changed"):
            selector.select("text", ["1", "2"])
        for options in ({"timeout": 0}, {"stop_style": "bad"}, {"model": ""}):
            with self.assertRaises(ValueError):
                self.selector(**options)
        with self.assertRaises(ValueError):
            selector.select("text", ["1", "1"])

    def test_flat_greedy_and_beam_use_sdk_without_typesafe(self):
        graph = CWEGraph.from_rows(
            [
                {
                    "CWE-ID": key,
                    "Status": "Stable",
                    **row,
                    "Related Weaknesses": "::NATURE:ChildOf:CWE ID:1:VIEW ID:1000::"
                    if key != "1"
                    else "",
                }
                for key, row in self.catalog.items()
            ]
        )
        with patch.dict("sys.modules", {"typesafe_sdk": None}):
            for width in (None, 1, 2):
                result = select_classify(
                    "text", graph, self.selector(), beam_width=width
                )
                self.assertTrue(result.predictions)
                self.assertGreater(result.requests, 0)
                self.assertTrue(all("depth" in step for step in result.steps))
