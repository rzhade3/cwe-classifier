import csv
import tempfile
import unittest
from pathlib import Path

from classification import STOP, CWEGraph, classify, select_classify


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
                "CWE-ID", "Name", "Description", "Status", "Related Weaknesses",
                "Weakness Abstraction"
            ])
            writer.writeheader()
            for label, relationships in self.rows:
                writer.writerow({"CWE-ID": label, "Name": label, "Description": label,
                                 "Status": "Stable", "Related Weaknesses": relationships,
                                 "Weakness Abstraction": "Base" if label in {"2", "3", "4", "5"} else "Pillar"})

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
        self.assertEqual(classify("", graph, scores, 1, stop_policy="improvement").predictions, ["1"])
        self.assertEqual(classify("", graph, scores, 1).predictions, ["4"])
        self.assertTrue(classify("", graph, scores, threshold=1).abstained)
        self.assertEqual(classify("", graph, scores, 1, margin=.3).predictions, ["2"])

    def test_leaf_policy_and_threshold_failure(self):
        graph = CWEGraph(self.path)
        scores = Scorer({"1": .9, "2": .8, "3": .7, "4": .6, "5": .1})
        self.assertEqual(classify("", graph, scores, 1).predictions, ["2"])
        self.assertEqual(classify("", graph, scores, 1, stop_policy="leaf").predictions, ["4"])
        self.assertTrue(classify("", graph, scores, 1, threshold=.85).abstained)
        self.assertTrue(classify("", graph, scores, 1, threshold=.75, stop_policy="leaf").abstained)
        with self.assertRaises(ValueError):
            classify("", graph, scores, 1, stop_policy="unknown")

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

    def test_select_flat_greedy_stop_and_beam_path_probability(self):
        graph = CWEGraph(self.path)
        selector = Selector({
            None: {"1": .7, "5": .3},
            "1": {"2": .5, "3": .2, STOP: .3},
            "2": {"4": .45, STOP: .55},
            "3": {"4": .9, STOP: .1},
        }, flat={"1": .1, "2": .2, "3": .3, "4": .35, "5": .05})
        flat = select_classify("", graph, selector, top_k=2)
        self.assertEqual((flat.predictions, flat.calls), (["4", "3"], 1))
        greedy = select_classify("", graph, selector, beam_width=1)
        self.assertEqual((greedy.predictions, greedy.paths), (["2"], [["1", "2"]]))
        self.assertEqual(greedy.steps, [
            {"current": None, "probabilities": {"1": .7, "5": .3}},
            {"current": "1", "probabilities": {"2": .5, "3": .2, STOP: .3}},
            {"current": "2", "probabilities": {"4": .45, STOP: .55}},
        ])
        beam = select_classify("", graph, selector, beam_width=2)
        self.assertEqual(beam.predictions, ["5", "1", "2", "4", "3"])
        self.assertEqual(beam.paths[3], ["1", "2", "4"])
        self.assertEqual(select_classify("", graph, selector, 2, top_k=1).predictions, ["5"])

    def test_select_validation_and_usage(self):
        graph = CWEGraph(self.path)
        selector = Selector({None: {"1": .7, "5": .3}, "1": {"2": .5, "3": .5}})
        with self.assertRaisesRegex(ValueError, "offered options"):
            select_classify("", graph, selector, beam_width=1)
        selector = Selector({None: {"1": 1.5, "5": .3}})
        with self.assertRaisesRegex(ValueError, r"\[0, 1\]"):
            select_classify("", graph, selector, beam_width=1)
        selector = Selector({}, flat={label: .2 for label in graph.labels})
        selector.last_usage = {"input_tokens": 7}
        self.assertEqual(select_classify("", graph, selector).input_tokens, 7)
        selector.max_options = 4
        with self.assertRaisesRegex(ValueError, "limit of 4"):
            select_classify("", graph, selector)
        selector.max_options = True
        with self.assertRaisesRegex(ValueError, "max_options"):
            select_classify("", graph, selector, beam_width=1)


class Selector:
    def __init__(self, tables, flat=None):
        self.tables, self.flat = tables, flat

    def select(self, text, labels, current=None):
        if current is None and len(labels) > 2:
            return dict(self.flat)
        return dict(self.tables[current])


if __name__ == "__main__":
    unittest.main()
