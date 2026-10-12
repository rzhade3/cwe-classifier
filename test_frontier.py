import contextlib
import io
import json
import os
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

import experiment
from classification import CWEGraph, LexicalScorer
import test_classification


ROOT = Path(__file__).parent


class FrontierTests(unittest.TestCase):
    def setUp(self):
        fixture = test_classification.ClassificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.graph = CWEGraph(fixture.path)
        self.graph_path = fixture.path
        self.directory = tempfile.TemporaryDirectory(dir=ROOT, prefix=".frontier-test-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "predictions.jsonl"
        self.examples = [{"id": "a", "text": "untrusted input", "labels": ["1"], "split": "test"}]
        self.config = {
            "one_shot_provider": "openai", "one_shot_model": "requested",
            "one_shot_endpoint": "https://server.example/v1/chat/completions",
            "one_shot_timeout": 9,
        }

    def completion(self, provider="openai"):
        return experiment._completion('{"predictions":["CWE-1"]}', "requested", None,
                                      .1, provider)

    @contextlib.contextmanager
    def mock_server(self, status=200, redirect=None):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append({
                    "path": self.path, "authorization": self.headers.get("Authorization"),
                    "body": json.loads(self.rfile.read(int(self.headers["Content-Length"]))),
                })
                self.send_response(status)
                if redirect:
                    self.send_header("Location", redirect)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                body = {"model": "resolved", "choices": [{"message": {
                    "content": '{"predictions":["CWE-1"]}'}}],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 2}}
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/v1/chat/completions", requests
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

    def test_real_loopback_openai_transport_and_saved_predictions(self):
        with self.mock_server() as (endpoint, requests), patch.dict(
            os.environ, {"TEST_FRONTIER_KEY": "unit-test-key"}
        ):
            helper = experiment.create_one_shot_helper({
                **self.config, "one_shot_endpoint": endpoint,
                "one_shot_api_key_env": "TEST_FRONTIER_KEY"})
            results = experiment.run_one_shot(self.examples, self.graph, self.path, helper)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["path"], "/v1/chat/completions")
        self.assertEqual(requests[0]["authorization"].split(), ["Bearer", "unit-test-key"])
        self.assertEqual(requests[0]["body"]["model"], "requested")
        self.assertNotIn("tools", requests[0]["body"])
        self.assertEqual(results[0]["resolved_model"], "resolved")
        self.assertEqual(results[0]["predictions"], ["1"])
        self.assertEqual(results[0]["input_tokens"], 8)
        self.assertEqual(results[0]["http_requests"], 1)
        self.assertIsNone(results[0]["model_requests"])

    def test_real_loopback_redirect_never_forwards_credentials(self):
        with self.mock_server() as (target, target_requests):
            with self.mock_server(status=307, redirect=target) as (endpoint, requests), patch.dict(
                os.environ, {"TEST_FRONTIER_KEY": "unit-test-key"}
            ):
                helper = experiment.create_one_shot_helper({
                    **self.config, "one_shot_endpoint": endpoint,
                    "one_shot_api_key_env": "TEST_FRONTIER_KEY"})
                with self.assertRaises(RuntimeError):
                    helper("prompt")
            self.assertEqual(len(requests), 1)
            self.assertEqual(target_requests, [])

    def test_real_loopback_http_failure_has_no_retry(self):
        with self.mock_server(status=500) as (endpoint, requests):
            helper = experiment.create_one_shot_helper({
                **self.config, "one_shot_endpoint": endpoint})
            with self.assertRaises(RuntimeError):
                helper("prompt")
        self.assertEqual(len(requests), 1)

    def test_http_single_request_and_usage(self):
        response = io.BytesIO(json.dumps({
            "model": "resolved", "choices": [{"message": {"content": '{"predictions":[]}'}}],
            "usage": {"prompt_tokens": 17, "completion_tokens": 3},
        }).encode())
        opener = Mock()
        opener.open.return_value = response
        with patch.dict(os.environ, {"TEST_FRONTIER_KEY": "secret"}), patch(
            "experiment.urllib.request.build_opener", return_value=opener
        ) as build:
            helper = experiment.create_one_shot_helper({
                **self.config, "one_shot_api_key_env": "TEST_FRONTIER_KEY"})
            result = helper("classify this")
        opener.open.assert_called_once()
        request = opener.open.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(payload, {"model": "requested", "stream": False, "n": 1,
                                  "messages": [{"role": "user", "content": "classify this"}]})
        self.assertEqual(request.get_header("Authorization").split(), ["Bearer", "secret"])
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 9)
        self.assertIsInstance(build.call_args.args[0], experiment._NoRedirects)
        self.assertEqual(result["resolved_model"], "resolved")
        self.assertEqual(result["requested_model"], "requested")
        self.assertEqual(result["input_tokens"], 17)
        self.assertEqual(result["output_tokens"], 3)
        self.assertEqual(result["http_requests"], 1)
        self.assertIsNone(result["calls"])
        self.assertIsNone(result["cost"])

    def test_http_unknown_usage(self):
        opener = Mock()
        opener.open.return_value = io.BytesIO(
            b'{"choices":[{"message":{"content":"{\\"predictions\\":[]}"}}]}')
        with patch("experiment.urllib.request.build_opener", return_value=opener):
            result = experiment.create_one_shot_helper(self.config)("prompt")
        self.assertIsNone(result["resolved_model"])
        self.assertIsNone(result["input_tokens"])
        self.assertIsNone(result["output_tokens"])

    def test_http_malformed_response_is_sanitized(self):
        for body in [
            b"credential-bearing non-JSON response",
            b'{"choices":[]}',
            b'{"choices":[{"message":{"content":null}}]}',
            b'{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":-1}}',
            b'{"choices":[{"message":{"content":"ok"}}],"model":17}',
        ]:
            opener = Mock()
            opener.open.return_value = io.BytesIO(body)
            with patch("experiment.urllib.request.build_opener", return_value=opener):
                with self.subTest(body=body), self.assertRaises(RuntimeError) as caught:
                    experiment.create_one_shot_helper(self.config)("prompt")
            self.assertNotIn("credential-bearing", str(caught.exception))
            opener.open.assert_called_once()

    def test_config_rejects_before_inference(self):
        invalid = [
            {"one_shot_provider": "unknown"}, {"one_shot_model": ""},
            {"one_shot_timeout": 0}, {"one_shot_timeout": float("nan")},
            {"one_shot_timeout": True}, {"one_shot_endpoint": None},
            {"one_shot_endpoint": "******server.example/v1"},
            {"one_shot_endpoint": "https://server.example/v1?key=secret"},
            {"one_shot_endpoint": "https://server.example/v1#secret"},
            {"one_shot_endpoint": "http://remote.example/v1"},
            {"one_shot_endpoint": "https://server.example:bad/v1"},
            {"one_shot_endpoint": "https://server.example/\nfoo"},
            {"one_shot_api_key_env": "secret value"}, {"one_shot_api_key_env": "MISSING_KEY"},
            {"one_shot_provider": "copilot"},
        ]
        with patch("experiment.subprocess.run") as process, patch(
            "experiment.urllib.request.build_opener"
        ) as http:
            for change in invalid:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    experiment.create_one_shot_helper({**self.config, **change})
        process.assert_not_called()
        http.assert_not_called()
        for endpoint in ["http://127.0.0.1:123/v1", "http://[::1]:123/v1"]:
            experiment.validate_one_shot_config({**self.config, "one_shot_endpoint": endpoint})

    def test_redirects_are_disabled(self):
        handler = experiment._NoRedirects()
        self.assertIsNone(handler.redirect_request(None, None, 302, "", {}, "https://evil.example"))

    def test_errors_redact_and_do_not_retry(self):
        for error in [OSError("******"), TimeoutError("key=secret"),
                      ValueError("raw response secret")]:
            opener = Mock()
            opener.open.side_effect = error
            with patch("experiment.urllib.request.build_opener", return_value=opener):
                with self.assertRaises(RuntimeError) as caught:
                    experiment.create_one_shot_helper(self.config)("prompt")
            self.assertNotIn("secret", str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)
            opener.open.assert_called_once()

    def test_copilot_safe_fresh_invocation(self):
        directories = []

        def fake(command, **kwargs):
            cwd = Path(kwargs["cwd"])
            self.assertEqual(list(cwd.iterdir()), [])
            self.assertTrue(cwd.name.startswith("cwe-one-shot-"))
            directories.append(cwd)
            self.assertEqual(command[0], "copilot")
            self.assertEqual(command[command.index("--available-tools") + 1],
                             "--no-custom-instructions")
            for flag in ["--disable-builtin-mcps", "--no-ask-user", "-s", "-p"]:
                self.assertIn(flag, command)
            for flag in ["--allow-all", "--resume", "--continue", "--fleet", "--autopilot"]:
                self.assertNotIn(flag, command)
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertNotIn("GITHUB_COPILOT_PROMPT_MODE_EXTENSIONS", kwargs["env"])
            self.assertEqual(kwargs["timeout"], 9)
            return subprocess.CompletedProcess(command, 0, '{"predictions":[]}', "secret")

        temporary_directory = tempfile.TemporaryDirectory
        with patch("experiment.subprocess.run", side_effect=fake) as run, patch(
            "experiment.tempfile.TemporaryDirectory", wraps=temporary_directory
        ) as temporary:
            helper = experiment.create_one_shot_helper({
                "one_shot_provider": "copilot", "one_shot_model": "requested",
                "one_shot_timeout": 9})
            result = helper("prompt")
            helper("next prompt")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(temporary.call_args.kwargs, {"prefix": "cwe-one-shot-"})
        self.assertNotEqual(directories[0], directories[1])
        self.assertTrue(all(not directory.exists() for directory in directories))
        self.assertEqual(result["prompt_invocations"], 1)
        self.assertEqual(result["http_requests"], 0)
        self.assertIsNone(result["model_requests"])
        self.assertIsNone(result["resolved_model"])

    def test_copilot_error_redaction(self):
        for error in [subprocess.CalledProcessError(1, "copilot", "secret", "token"),
                      subprocess.TimeoutExpired("copilot secret", 1), FileNotFoundError("secret")]:
            with patch("experiment.subprocess.run", side_effect=error) as run:
                with self.assertRaises(RuntimeError) as caught:
                    experiment.copilot_completion("prompt", model="model")
            self.assertNotIn("secret", str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)
            run.assert_called_once()

    def test_replaceable_helper_and_provenance_roundtrip(self):
        for provider in ["copilot", "openai"]:
            helper = Mock(return_value=self.completion(provider))
            result = experiment.run_one_shot(self.examples, self.graph, self.path, helper)
            helper.assert_called_once()
            self.assertIn("Candidates:", helper.call_args.args[0])
            record = json.loads(self.path.read_text())
            self.assertEqual(record["prompt_hash"], experiment.fingerprint(helper.call_args.args[0]))
            self.assertEqual(record["catalog_hash"], experiment.catalog_fingerprint(self.graph))
            self.assertEqual(record["text_hash"], experiment.fingerprint("untrusted input"))
            self.assertEqual(result[0]["predictions"], ["1"])
            self.assertIsNone(result[0]["calls"])
            self.assertEqual(result[0]["prompt_hash"], record["prompt_hash"])
            self.assertNotIn("content", record)
            self.assertNotIn("prompt", record)

    def test_all_prompt_budgets_preflight_and_output_validation(self):
        examples = [*self.examples, {**self.examples[0], "id": "b", "text": "x" * 5000}]
        helper = Mock(return_value=self.completion())
        for kwargs in [{"max_prompt_chars": 2000}, {"max_live_examples": 1},
                       {"max_prompt_chars": -1}, {"max_live_examples": True}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                experiment.run_one_shot(examples, self.graph, self.path, helper, **kwargs)
        helper.assert_not_called()
        for content in ["secret raw response", '{"predictions":["CWE-999"]}',
                        '{"predictions":"CWE-1"}', '{"predictions":[1]}',
                        '{"predictions":["CWE-1","CWE-2"]}']:
            helper.return_value = {**self.completion(), "content": content}
            with self.subTest(content=content), self.assertRaises(ValueError) as caught:
                experiment.run_one_shot(self.examples, self.graph, self.path, helper)
            self.assertNotIn("secret", str(caught.exception))
        self.assertFalse(self.path.exists())

    def test_loader_does_not_accept_invocation_as_inference(self):
        experiment.run_one_shot(self.examples, self.graph, self.path,
                                lambda prompt: self.completion("copilot"))
        record = json.loads(self.path.read_text())
        for change in [{"calls": 1}, {"prompt_invocations": 2},
                       {"prompt_invocations": True}, {"http_requests": 1},
                       {"provider": "unknown"}, {"model_requests": 1}]:
            self.path.write_text(json.dumps({**record, **change}) + "\n")
            with self.subTest(change=change), self.assertRaises(ValueError):
                experiment.load_one_shot(self.path, self.examples, self.graph)

    def notebook_config(self):
        benchmark = Path(self.directory.name) / "benchmark.jsonl"
        experiment.write_jsonl(benchmark, self.examples)
        return {
            **self.config, "command": "run", "demo": False, "catalog": str(self.graph_path),
            "benchmark": str(benchmark), "output": str(Path(self.directory.name) / "results"),
            "view": "1000", "split": "test", "scorer": "lexical", "methods": ["one-shot"],
            "beam_width": 2, "top_k": 2, "threshold": 0., "margin": 0., "seed": 0,
            "bootstrap_samples": 20, "max_prompt_chars": None, "max_live_examples": 1,
        }

    def test_notebook_explicit_provider_uses_shared_helper(self):
        helper = Mock(return_value=self.completion())
        with patch("experiment.create_one_shot_helper", return_value=helper), contextlib.redirect_stdout(io.StringIO()):
            state = experiment.run_notebook(self.notebook_config())
        helper.assert_called_once()
        self.assertIsNone(state["results"]["one-shot"][0]["calls"])
        self.assertEqual(state["evaluation_sampling"]["limit"], 1)
        artifact = Path(state["config"]["output"]) / "one-shot-predictions.jsonl"
        self.assertTrue(artifact.exists())
        self.assertIsNone(state["summary"]["metrics"]["one-shot"]["total_calls"])

    def test_notebook_caps_live_provider_and_matches_other_methods(self):
        config = self.notebook_config()
        config["methods"] = ["flat", "one-shot"]
        experiment.write_jsonl(config["benchmark"], [
            *self.examples, {**self.examples[0], "id": "b", "text": "SQL query is concatenated"},
            {**self.examples[0], "id": "c", "text": "allocated memory overflows"}])
        helper = Mock(return_value=self.completion("copilot"))
        config.update(one_shot_provider="copilot", one_shot_endpoint=None)
        with patch("experiment.create_one_shot_helper", return_value=helper), contextlib.redirect_stdout(io.StringIO()):
            state = experiment.run_notebook(config)
        helper.assert_called_once()
        self.assertEqual(state["evaluation_sampling"]["population_count"], 3)
        self.assertEqual(state["evaluation_sampling"]["selected_count"], 1)
        self.assertEqual([record["id"] for record in state["results"]["flat"]],
                         [record["id"] for record in state["results"]["one-shot"]])

    def test_notebook_dataset_slice_metrics_preserve_unknown_inference(self):
        config = self.notebook_config()
        experiment.write_jsonl(config["benchmark"], [{
            **self.examples[0], "slices": ["natural", "kev"], "sources": ["vendor"]}])
        with patch("experiment.create_one_shot_helper", return_value=lambda prompt: self.completion()):
            with contextlib.redirect_stdout(io.StringIO()):
                state = experiment.run_notebook(config)
        for slice_name in ["natural", "kev", "source:vendor"]:
            metrics = state["summary"]["slice_metrics"][slice_name]["one-shot"]
            self.assertIsNone(metrics["total_calls"])
            self.assertEqual(metrics["unknown_calls_count"], 1)
            self.assertEqual(metrics["total_http_requests"], 1)

    def test_notebook_invalid_config_is_offline(self):
        for change in [{"demo": True}, {"one_shot_timeout": -1}, {"max_prompt_chars": 10},
                       {"one_shot_endpoint": "https://server.example/?key=secret"},
                       {"one_shot_predictions": "import.jsonl"}]:
            with patch("experiment.openai_completion") as http, patch(
                "experiment.copilot_completion"
            ) as cli, contextlib.redirect_stdout(io.StringIO()):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    experiment.run_notebook({**self.notebook_config(), **change})
            http.assert_not_called()
            cli.assert_not_called()

    def test_notebook_passes_jev_options_without_environment_mutation(self):
        config = self.notebook_config()
        for key in list(config):
            if key.startswith("one_shot_"):
                config.pop(key)
        config.update(scorer="jev_scorer:create_scorer", methods=["flat"],
                      jev_base_url="https://jev.example", jev_model="pinned-model")
        before = dict(os.environ)
        with patch("jev_scorer.JevScorer", return_value=LexicalScorer(self.graph.labels)) as factory:
            with contextlib.redirect_stdout(io.StringIO()):
                experiment.run_notebook(config)
        factory.assert_called_once_with(self.graph.labels, base_url="https://jev.example",
                                        model="pinned-model")
        self.assertEqual(dict(os.environ), before)

    def test_invalid_jev_settings_fail_before_frontier_inference(self):
        for change in [{"jev_base_url": "https://jev.example?config=unexpected"},
                       {"jev_model": ""}]:
            config = {**self.notebook_config(), "scorer": "jev_scorer:create_scorer",
                      "methods": ["one-shot", "flat"], **change}
            with patch("experiment.create_one_shot_helper") as factory:
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                    experiment.run_notebook(config)
            factory.assert_not_called()
        with patch("jev_scorer.JevScorer", side_effect=ImportError("SDK missing")), patch(
            "experiment.create_one_shot_helper"
        ) as factory:
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ImportError):
                experiment.run_notebook({
                    **self.notebook_config(), "scorer": "jev_scorer:create_scorer",
                    "methods": ["one-shot", "flat"], "jev_model": "pinned"})
        factory.assert_not_called()

    def test_invalid_custom_scorer_and_candidate_budget_are_preflighted(self):
        config = {**self.notebook_config(), "methods": ["one-shot", "flat"]}
        with patch("classification.load_scorer", side_effect=ValueError("Invalid scorer")), patch(
            "experiment.create_one_shot_helper"
        ) as factory:
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                experiment.run_notebook(config)
        factory.assert_not_called()
        with patch("classification.load_scorer") as scorer, patch(
            "experiment.create_one_shot_helper"
        ) as factory:
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                experiment.run_notebook({**config, "max_candidate_evaluations": 1})
        scorer.assert_not_called()
        factory.assert_not_called()

    def test_scorer_is_constructed_first_and_closed_on_frontier_failure(self):
        scorer = LexicalScorer(self.graph.labels)
        scorer.close = Mock()
        helper = Mock(side_effect=RuntimeError("Transport failed"))
        events = []

        def make_scorer(*args):
            events.append("scorer")
            return scorer

        def make_helper(*args):
            self.assertEqual(events, ["scorer"])
            return helper

        with patch("classification.load_scorer", side_effect=make_scorer), patch(
            "experiment.create_one_shot_helper", side_effect=make_helper
        ):
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
                experiment.run_notebook({
                    **self.notebook_config(), "methods": ["one-shot", "flat"]})
        helper.assert_called_once()
        scorer.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
