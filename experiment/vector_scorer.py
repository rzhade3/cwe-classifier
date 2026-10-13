"""Vector-DB scorer: cosine similarity against the Chroma CWE index.

Use with the ``"vector"`` scorer spec. Reads CWE embeddings from the persisted
``cwe_index`` collection (rebuild it with ``python -m experiment.vector_scorer``)
and embeds the
vulnerability text with the same default embedding function. Flat ranking is
equivalent to the CLI's nearest-neighbour lookup. Similarities depend only on
the text and one CWE, so they are comparable across greedy/beam calls.
"""

import argparse
import csv
from pathlib import Path

import numpy as np

from classification import normalize_label


_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_PATH = _ROOT / "chroma"


class VectorScorer:
    def __init__(self, catalog, path=None, collection="cwe_index",
                 embedding_function=None):
        import chromadb
        from chromadb.utils import embedding_functions

        path = Path(path or _DEFAULT_PATH)
        if not (path / "chroma.sqlite3").is_file():
            raise FileNotFoundError(
                f"No Chroma index at {path}; run `python -m experiment.vector_scorer`"
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


def build_index(catalog, path=_DEFAULT_PATH, collection="cwe_index",
                embedding_function=None):
    """Embed each CWE's description and extended description into Chroma."""
    import chromadb
    from chromadb.utils import embedding_functions

    with open(catalog, encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    documents = [f"{row['Description']}\n{row['Extended Description']}" for row in rows]
    embed = embedding_function or embedding_functions.DefaultEmbeddingFunction()
    chromadb.PersistentClient(path=str(path)).get_or_create_collection(collection).upsert(
        ids=[row["CWE-ID"] for row in rows],
        embeddings=embed(documents),
        documents=documents,
        metadatas=[{"CWE-ID": row["CWE-ID"], "Name": row["Name"]} for row in rows],
    )
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description="Rebuild the Chroma CWE index.")
    parser.add_argument("catalog", nargs="?", type=Path, default=_ROOT / "data" / "all.csv")
    parser.add_argument("--path", type=Path, default=_DEFAULT_PATH)
    args = parser.parse_args()
    count = build_index(args.catalog, args.path)
    print(f"Indexed {count} CWEs into {args.path}")


if __name__ == "__main__":
    main()
