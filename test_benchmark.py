"""Tests for the independent, offline benchmark interface."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmark import load_benchmark, metrics, paired_intervals


class Graph:
    def distance(self, a, b):
        if a == b:
            return 0
        return {("CWE-89", "CWE-79"): 2,
                ("CWE-89", "CWE-80"): 1}.get((a, b))


def example(identifier="a", text="Unsafe user input", labels=None, split="test",
            **extra):
    return dict(id=identifier, text=text, labels=labels or ["79"],
                split=split, **extra)


def result(identifier="a", labels=None, predictions=None, **extra):
    record = dict(id=identifier, labels=labels or ["79"],
                  predictions=["79"] if predictions is None else predictions,
                  abstained=False, latency_seconds=0.5, calls=2,
                  input_tokens=10, output_tokens=3, cost=0.01, paths=[])
    record.update(extra)
    return record


class LoaderTests(unittest.TestCase):
    def load(self, records, eligible=None, **kwargs):
        content = "\n".join(json.dumps(record) for record in records)
        with patch.object(Path, "read_text", return_value=content):
            return load_benchmark("offline.jsonl", eligible or ["79"], **kwargs)

    def test_normalization_sanitization_and_gold_preservation(self):
        examples, audit = self.load([
            example(text="A cWe-079 and CWE 80 weakness",
                    labels=["79", "CWE-079", "80"])])
        self.assertEqual(examples, [dict(id="a", text="A and weakness",
                                        labels=["CWE-79", "CWE-80"], split="test")])
        self.assertEqual(audit["unsupported_labels"], {"CWE-80": 1})
        self.assertEqual(audit["accepted"], 1)

    def test_cross_split_dedup_precedes_selection(self):
        examples, audit = self.load([
            example("dev", "Unsafe CWE-79 user input", split="dev"),
            example("test", "  unsafe USER   input  "),
            example("third", "Different input")])
        self.assertEqual([record["id"] for record in examples], ["third"])
        self.assertEqual(audit["duplicate_text"], 1)
        self.assertEqual(audit["wrong_split"], 1)

    def test_ambiguity_overlap_and_unsupported_counts(self):
        examples, audit = self.load([
            example("amb", "Ambiguous", ambiguous=True),
            example("train", "Training example"),
            example("bad", "Unsupported", labels=["89", "CWE-089"]),
            example("empty", "No gold", labels=["89"]),
            example("ok", "Supported", labels=["79", "89"])],
            training_ids=["train"])
        self.assertEqual([record["id"] for record in examples], ["ok"])
        self.assertEqual(audit["ambiguous"], 1)
        self.assertEqual(audit["training_overlap"], 1)
        self.assertEqual(audit["no_eligible_labels"], 2)
        self.assertEqual(audit["unsupported_labels"], {"CWE-89": 3})
        self.assertEqual(sum(audit[key] for key in (
            "accepted", "duplicate_text", "wrong_split", "ambiguous",
            "training_overlap", "no_eligible_labels")), audit["records_total"])

    def test_ambiguous_text_still_prevents_leakage(self):
        examples, audit = self.load([
            example("a", ambiguous=True), example("b")])
        self.assertEqual(examples, [])
        self.assertEqual(audit["duplicate_text"], 1)

    def test_dev_selection_and_no_labels(self):
        examples, audit = self.load([
            example("a", split="dev"),
            dict(id="b", text="Unknown", labels=[], split="dev")], split="dev")
        self.assertEqual(examples[0]["split"], "dev")
        self.assertEqual(audit["no_eligible_labels"], 1)

    def test_duplicate_ids_rejected_even_when_excluded(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.load([example(split="dev"), example(text="Other")])

    def test_invalid_records(self):
        bad_records = [
            {}, [], example(identifier=1), example(text=" "),
            example(labels="79"), example(labels=["not-cwe"]),
            example(labels=[79]), example(labels=["CWE-0"]),
            example(split="train"), example(ambiguous="false"),
            example(text="CWE-79"), example(text=None),
        ]
        missing_split = example()
        del missing_split["split"]
        bad_records.append(missing_split)
        for bad in bad_records:
            with self.subTest(record=bad), self.assertRaises(ValueError):
                self.load([bad])

    def test_invalid_arguments_and_json(self):
        for kwargs in (dict(split="train"), dict(training_ids="a")):
            with self.assertRaises(ValueError):
                self.load([example()], **kwargs)
        for content in ("", "not json", "[1,2]", '{"vulnerabilities":{}}'):
            with patch.object(Path, "read_text", return_value=content):
                with self.assertRaises(ValueError):
                    load_benchmark("data", ["79"])
        for eligible in ([], "79", [79], ["bogus"]):
            with self.assertRaises(ValueError):
                load_benchmark("unused", eligible)

    def test_offline_nvd(self):
        document = {"vulnerabilities": [
            {"cve": {"id": "CVE-2025-1", "descriptions": [
                {"lang": "fr", "value": "Ignore"},
                {"lang": "en", "value": "A CWE-79 weakness"}],
                "weaknesses": [{"description": [
                    {"lang": "en", "value": "CWE-79"},
                    {"lang": "en", "value": "CWE-89"}]}]}},
            {"cve": {"id": "CVE-2025-2", "descriptions": [
                {"lang": "en", "value": "Unknown issue"}],
                "weaknesses": [{"description": [
                    {"lang": "en", "value": "NVD-CWE-noinfo"}]}]}}
        ]}
        with patch.object(Path, "read_text", return_value=json.dumps(document)):
            examples, audit = load_benchmark("nvd.json", ["79"])
        self.assertEqual(examples[0]["text"], "A weakness")
        self.assertEqual(examples[0]["labels"], ["CWE-79", "CWE-89"])
        self.assertEqual(examples[0]["split"], "test")
        self.assertEqual(audit["no_eligible_labels"], 1)

    def test_invalid_nvd(self):
        for cve in ({}, {"descriptions": "bad"}, {
                "id": "x", "descriptions": [{"lang": "en", "value": "text"}],
                "weaknesses": [{"description": [{"lang": "en", "value": 79}]}]}):
            document = {"vulnerabilities": [{"cve": cve}]}
            with patch.object(Path, "read_text", return_value=json.dumps(document)):
                with self.assertRaises(ValueError):
                    load_benchmark("nvd", ["79"])


class MetricsTests(unittest.TestCase):
    def test_accuracy_macro_topk_and_resources(self):
        records = [
            result("a", labels=["79", "80"], predictions=["80"]),
            result("b", predictions=["89", "79"]),
            result("c", abstained=True, predictions=["79"])]
        scores = metrics(records, Graph())
        self.assertAlmostEqual(scores["exact_match_accuracy"], 1 / 3)
        self.assertAlmostEqual(scores["macro_f1"], 1 / 3)
        self.assertEqual(scores["top_k_recall"][1], 1 / 3)
        self.assertEqual(scores["top_k_recall"][3], 2 / 3)
        self.assertEqual(scores["mean_hierarchical_distance"], 1)
        self.assertEqual(scores["hierarchical_distance_count"], 2)
        self.assertEqual(scores["unreachable_count"], 0)
        self.assertEqual(scores["abstention_rate"], 1 / 3)
        self.assertEqual(scores["mean_latency_seconds"], 0.5)
        self.assertEqual(scores["total_calls"], 6)
        self.assertEqual(scores["total_input_tokens"], 30)
        self.assertEqual(scores["total_output_tokens"], 9)
        self.assertAlmostEqual(scores["total_cost"], 0.03)

    def test_alternatives_correct_macro_is_one(self):
        self.assertEqual(metrics([result(labels=["79", "80"],
                                         predictions=["80"])], Graph())["macro_f1"], 1)

    def test_distance_minimum_unreachable_and_empty_prediction(self):
        scores = metrics([
            result("a", labels=["79", "80"], predictions=["89"]),
            result("b", predictions=["999"]),
            result("c", predictions=[])], Graph())
        self.assertEqual(scores["mean_hierarchical_distance"], 1)
        self.assertEqual(scores["unreachable_count"], 1)
        self.assertEqual(scores["hierarchical_distance_count"], 1)

    def test_unknown_usage_is_not_zero(self):
        scores = metrics([
            result("a", input_tokens=None, output_tokens=None, cost=None,
                   candidates_scored=5),
            result("b", candidates_scored=7)], Graph())
        for field in ("input_tokens", "output_tokens", "cost"):
            self.assertIsNone(scores["total_" + field])
            self.assertEqual(scores["unknown_" + field + "_count"], 1)
        self.assertEqual(scores["known_input_tokens"], 10)
        self.assertEqual(scores["total_candidates_scored"], 12)

    def test_empty_dataset(self):
        scores = metrics([], Graph())
        for field in ("exact_match_accuracy", "macro_f1", "abstention_rate",
                      "mean_hierarchical_distance", "mean_latency_seconds"):
            self.assertIsNone(scores[field])
        self.assertEqual(scores["total_calls"], 0)
        self.assertTrue(all(value is None for value in scores["top_k_recall"].values()))

    def test_validation(self):
        changes = [
            dict(latency_seconds=-1), dict(latency_seconds=float("nan")),
            dict(cost=float("inf")), dict(calls=True), dict(calls=1.5),
            dict(input_tokens=-1), dict(output_tokens=1.5),
            dict(abstained=1), dict(paths={}), dict(predictions=["79", "CWE-79"]),
            dict(predictions=["bogus"]), dict(candidates_scored=-1)]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                metrics([result(**change)], Graph())
        record = result()
        del record["input_tokens"]
        with self.assertRaises(ValueError):
            metrics([record], Graph())
        with self.assertRaises(ValueError):
            metrics([result(), result()], Graph())
        with self.assertRaises(ValueError):
            metrics([], object())
        with self.assertRaises(ValueError):
            metrics({}, Graph())
        class InvalidGraph:
            def distance(self, a, b):
                return -1
        with self.assertRaises(ValueError):
            metrics([result()], InvalidGraph())


class PairedTests(unittest.TestCase):
    def test_deterministic_identical_and_extreme_intervals(self):
        a = [result("a"), result("b")]
        b = [result("a", predictions=["89"]), result("b", abstained=True)]
        methods = {"best": a, "worst": b, "same": a}
        first = paired_intervals(methods, seed=7, samples=100)
        self.assertEqual(first, paired_intervals(methods, seed=7, samples=100))
        self.assertEqual(first["best - worst"],
                         dict(difference=1, lower=1, upper=1))
        self.assertEqual(first["best - same"],
                         dict(difference=0, lower=0, upper=0))
        self.assertEqual(first["worst - same"]["difference"], -1)

    def test_nonconstant_paired_distribution(self):
        methods = {"a": [result("a"), result("b", predictions=["89"])],
                   "b": [result("a", predictions=["89"]), result("b")]}
        interval = paired_intervals(methods, samples=200)["a - b"]
        self.assertEqual(interval["difference"], 0)
        self.assertEqual(interval["lower"], -1)
        self.assertEqual(interval["upper"], 1)

    def test_gold_normalization_order_and_minimal_records(self):
        a = dict(id="a", labels=["79", "CWE-80"],
                 predictions=["80"], abstained=False)
        b = dict(a, labels=["80", "CWE-079"])
        self.assertEqual(paired_intervals({"a": [a], "b": [b]})["a - b"]["lower"], 0)

    def test_mismatched_ids_order_and_gold(self):
        a = [result("a"), result("b")]
        for b in ([result("b"), result("a")], [result("a")],
                  [result("a"), result("b", labels=["89"])]):
            with self.assertRaisesRegex(ValueError, "matched"):
                paired_intervals({"a": a, "b": b})

    def test_invalid_arguments(self):
        for methods in ({}, {"a": []}, {"a": [], "b": []},
                        {"": [result()], "b": [result()]}):
            with self.assertRaises(ValueError):
                paired_intervals(methods)
        for kwargs in (dict(samples=0), dict(samples=1.5), dict(samples=True),
                       dict(seed=True), dict(seed="0")):
            with self.assertRaises(ValueError):
                paired_intervals({"a": [result()], "b": [result()]}, **kwargs)


if __name__ == "__main__":
    unittest.main()
