"""Vector-DB scorer: cosine similarity against the Chroma CWE index.

Use with the ``"vector"`` scorer spec. Reads CWE embeddings from the persisted
``cwe_index`` collection built by ``main.py generate-index`` and embeds the
vulnerability text with the same default embedding function. Flat ranking is
equivalent to the CLI's nearest-neighbour lookup. Similarities depend only on
the text and one CWE, so they are comparable across greedy/beam calls.
"""

from pathlib import Path

import numpy as np

from classification import normalize_label


_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "chroma"


class VectorScorer:
    def __init__(self, catalog, path=None, collection="cwe_index",
                 embedding_function=None):
        import chromadb
        from chromadb.utils import embedding_functions

        path = Path(path or _DEFAULT_PATH)
        if not (path / "chroma.sqlite3").is_file():
            raise FileNotFoundError(
                f"No Chroma index at {path}; run `main.py generate-index data/all.csv`"
            )
        stored = chromadb.PersistentClient(path=str(path)).get_collection(
            collection
        ).get(include=["embeddings"])
        vectors = {
            normalize_label(identifier): np.asarray(embedding, dtype=float)
            for identifier, embedding in zip(stored["ids"], stored["embeddings"])
        }
        missing = sorted(set(catalog) - vectors.keys(), key=int)
        if missing:
            raise ValueError(
                f"Chroma index lacks {len(missing)} catalog CWEs (e.g. CWE-{missing[0]}); "
                "regenerate it from the same catalog"
            )
        self._vectors = {
            label: vectors[label] / np.linalg.norm(vectors[label]) for label in catalog
        }
        self._embed = embedding_function or embedding_functions.DefaultEmbeddingFunction()
        self._query = (None, None)

    def score(self, text, labels):
        if self._query[0] != text:
            vector = np.asarray(self._embed([text])[0], dtype=float)
            self._query = (text, vector / np.linalg.norm(vector))
        query = self._query[1]
        return {label: float(query @ self._vectors[label]) for label in labels}
