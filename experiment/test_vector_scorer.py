import shutil
import tempfile
import unittest
from pathlib import Path

import chromadb

from experiment.vector_scorer import VectorScorer


class FakeEmbedding:
    def __init__(self):
        self.calls = 0

    def __call__(self, texts):
        self.calls += 1
        return [[1.0, 0.0] if "memory" in text else [0.0, 1.0] for text in texts]


class VectorScorerTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        collection = chromadb.PersistentClient(path=str(self.directory)) \
            .get_or_create_collection("cwe_index")
        collection.add(ids=["1", "2", "3"],
                       embeddings=[[2.0, 0.0], [0.0, 3.0], [1.0, 1.0]],
                       documents=["a", "b", "c"])
        self.catalog = {"1": {}, "2": {}, "3": {}}

    def test_cosine_scores_are_fixed_per_label_and_query_is_cached(self):
        embedding = FakeEmbedding()
        scorer = VectorScorer(self.catalog, self.directory, embedding_function=embedding)
        scores = scorer.score("memory overwrite", ["1", "2", "3"])
        self.assertAlmostEqual(scores["1"], 1.0)
        self.assertAlmostEqual(scores["2"], 0.0)
        self.assertAlmostEqual(scores["3"], 2 ** -.5)
        self.assertEqual(scorer.score("memory overwrite", ["3"])["3"], scores["3"])
        self.assertEqual(embedding.calls, 1)

    def test_missing_index_or_catalog_labels(self):
        with self.assertRaises(FileNotFoundError):
            VectorScorer(self.catalog, self.directory / "missing")
        with self.assertRaisesRegex(ValueError, "lacks 1 catalog CWEs"):
            VectorScorer({**self.catalog, "4": {}}, self.directory,
                         embedding_function=FakeEmbedding())


if __name__ == "__main__":
    unittest.main()
