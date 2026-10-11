import csv
import tempfile
import unittest
from pathlib import Path

from classification import CWEGraph, classify


class Scorer:
    def __init__(self, scores):
        self.scores = scores

    def score(self, text, labels):
        return {label: self.scores[label] for label in labels}


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "catalog.csv"
        self.rows = [
            ("1", ""),
            ("2", "::NATURE:ChildOf:CWE ID:1:VIEW ID:1000::"),
            ("3", "::NATURE:ChildOf:CWE ID:1:VIEW ID:1000::"),
            ("4", "::NATURE:ChildOf:CWE ID:2:VIEW ID:1000::"
             "NATURE:ChildOf:CWE ID:3:VIEW ID:1000::"),
            ("5", "::NATURE:ChildOf:CWE ID:4:VIEW ID:999::"),
        ]
        self.write_catalog()

    def write_catalog(self):
        with open(self.path, "w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=[
                "CWE-ID", "Name", "Description", "Status", "Related Weaknesses"
            ])
            writer.writeheader()
            for label, relationships in self.rows:
                writer.writerow({"CWE-ID": label, "Name": label, "Description": label,
                                 "Status": "Stable", "Related Weaknesses": relationships})

    def test_view_multiple_parents_and_distance(self):
        graph = CWEGraph(self.path)
        self.assertEqual(graph.parents["4"], {"2", "3"})
        self.assertEqual(graph.roots, ["1", "5"])
        self.assertEqual(graph.distance("2", "3"), 2)
        self.assertIsNone(graph.distance("1", "5"))

    def test_flat_and_greedy_misroute_beam_recovers(self):
        graph = CWEGraph(self.path)
        scores = Scorer({"1": .1, "2": .5, "3": .6, "4": .9, "5": .2})
        self.assertEqual(classify("", graph, scores).predictions[0], "4")
        # Greedy starts at disconnected root 5; beam preserves root 1 as well.
        self.assertEqual(classify("", graph, scores, 1).predictions, ["5"])
        beam = classify("", graph, scores, 2)
        self.assertEqual(beam.predictions[0], "4")
        self.assertEqual(len(set(beam.predictions)), len(beam.predictions))
        self.assertEqual(beam.candidates_scored, 5)
        self.assertIn(beam.paths[0], [["1", "2", "4"], ["1", "3", "4"]])

    def test_stop_and_abstain(self):
        graph = CWEGraph(self.path)
        scores = Scorer({"1": .8, "2": .7, "3": .6, "4": .9, "5": .2})
        self.assertEqual(classify("", graph, scores, 1).predictions, ["1"])
        self.assertTrue(classify("", graph, scores, threshold=1).abstained)
        self.assertEqual(classify("", graph, scores, 1, margin=.3).predictions, ["1"])

    def test_invalid_scores_and_parameters(self):
        graph = CWEGraph(self.path)
        with self.assertRaises(ValueError):
            classify("", graph, Scorer({label: float("nan") for label in graph.labels}))
        with self.assertRaises(ValueError):
            classify("", graph, Scorer({}), top_k=0)

    def test_usage_aggregation(self):
        graph = CWEGraph(self.path)
        scorer = Scorer({"1": .1, "2": .5, "3": .6, "4": .9, "5": .2})
        scorer.last_usage = {"input_tokens": 10, "output_tokens": 2, "cost": .01}
        result = classify("", graph, scorer, 2)
        self.assertEqual(result.input_tokens, result.calls * 10)
        self.assertAlmostEqual(result.cost, result.calls * .01)
        scorer.last_usage = {"cost": -1}
        with self.assertRaises(ValueError):
            classify("", graph, scorer)

    def test_cycle(self):
        self.rows[0] = ("1", "::NATURE:ChildOf:CWE ID:4:VIEW ID:1000::")
        self.write_catalog()
        with self.assertRaises(ValueError):
            CWEGraph(self.path)


if __name__ == "__main__":
    unittest.main()
