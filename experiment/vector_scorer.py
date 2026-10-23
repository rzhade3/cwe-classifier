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
import hashlib
import math
from pathlib import Path

import numpy as np

from classification import normalize_label

from . import fingerprint

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_PATH = _ROOT / "chroma"


class VectorScorer:
    def __init__(
        self, catalog, path=None, collection="cwe_index", embedding_function=None
    ):
        import chromadb
        from chromadb.utils import embedding_functions

        path = Path(path or _DEFAULT_PATH)
        if not (path / "chroma.sqlite3").is_file():
            raise FileNotFoundError(
                f"No Chroma index at {path}; run `python -m experiment.vector_scorer`"
            )
        index = chromadb.PersistentClient(path=str(path)).get_collection(collection)
        identity = _embedding_identity(embedding_function)
        if (
            embedding_function is None
            and (index.metadata or {}).get("embedding_identity") != identity
        ):
            raise ValueError(
                "Unversioned or incompatible embedding index; rebuild it with experiment.vector_scorer"
            )
        stored = index.get(include=["embeddings", "documents"])
        for identifier, document in zip(stored["ids"], stored["documents"]):
            row = catalog.get(normalize_label(identifier), {})
            if "Description" in row and document != _document(row):
                raise ValueError(
                    "Index documents differ from catalog; rebuild the vector index"
                )
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
        self._vectors = {label: _unit(vectors[label]) for label in catalog}
        self.metadata = {
            "embedding_identity": identity,
            "index_sha256": fingerprint(
                {label: vector.tolist() for label, vector in sorted(vectors.items())}
            ),
        }
        self._embed = (
            embedding_function or embedding_functions.DefaultEmbeddingFunction()
        )
        self._query = (None, None)

    def score(self, text, labels):
        if self._query[0] != text:
            vector = np.asarray(self._embed([text])[0], dtype=float)
            self._query = (text, _unit(vector))
        query = self._query[1]
        return {label: float(query @ self._vectors[label]) for label in labels}


def build_index(
    catalog, path=_DEFAULT_PATH, collection="cwe_index", embedding_function=None
):
    """Embed each CWE's description and extended description into Chroma."""
    import chromadb
    from chromadb.utils import embedding_functions

    with open(catalog, encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    documents = [_document(row) for row in rows]
    embed = embedding_function or embedding_functions.DefaultEmbeddingFunction()
    client = chromadb.PersistentClient(path=str(path))
    # Refuse accidental mutation of an existing experiment artifact.
    index = client.create_collection(
        collection,
        metadata={
            "embedding_identity": _embedding_identity(embedding_function),
            "catalog_sha256": hashlib.sha256(Path(catalog).read_bytes()).hexdigest(),
        },
    )
    index.add(
        ids=[row["CWE-ID"] for row in rows],
        embeddings=embed(documents),
        documents=documents,
        metadatas=[{"CWE-ID": row["CWE-ID"], "Name": row["Name"]} for row in rows],
    )
    return len(rows)


def _embedding_identity(function):
    return (
        f"{type(function).__module__}.{type(function).__qualname__}"
        if function is not None
        else "chroma-default/all-MiniLM-L6-v2"
    )


def _document(row):
    return f"{row['Description']}\n{row.get('Extended Description', '')}"


def _unit(vector):
    norm = np.linalg.norm(vector)
    if (
        vector.ndim != 1
        or not np.isfinite(vector).all()
        or not math.isfinite(norm)
        or norm == 0
    ):
        raise ValueError("Embeddings must be finite nonzero vectors")
    return vector / norm


def main():
    parser = argparse.ArgumentParser(description="Rebuild the Chroma CWE index.")
    parser.add_argument(
        "catalog", nargs="?", type=Path, default=_ROOT / "data" / "all.csv"
    )
    parser.add_argument("--path", type=Path, default=_DEFAULT_PATH)
    args = parser.parse_args()
    count = build_index(args.catalog, args.path)
    print(f"Indexed {count} CWEs into {args.path}")


if __name__ == "__main__":
    main()
