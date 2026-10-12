"""Benchmark loading and metrics for the CWE experiment."""

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

from classification import normalize_label


_CWE = re.compile(r"\bCWE[\s-]*\d+\b", re.IGNORECASE)
_TOP_K = (1, 3, 5)


def load_benchmark(path, split="test"):
    """Load one split from prepared JSONL; exclude cross-split duplicate text."""
    if split not in {"dev", "test"}:
        raise ValueError("split must be dev or test")
    records = [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    text_splits = defaultdict(set)
    seen_ids = set()
    for record in records:
        identifier, text, labels = (
            record.get("id"), record.get("text"), record.get("labels")
        )
        if (not isinstance(identifier, str) or not identifier.strip()
                or not isinstance(text, str) or not text.strip()
                or not isinstance(labels, list) or not labels
                or record.get("split") not in {"dev", "test"}):
            raise ValueError("Benchmark records need an id, text, and labels")
        if identifier.casefold() in seen_ids:
            raise ValueError(f"Duplicate benchmark ID: {identifier}")
        seen_ids.add(identifier.casefold())
        text_splits[" ".join(_CWE.sub("", text).split()).casefold()].add(
            record.get("split")
        )
    return [
        record for record in records
        if record.get("split") == split
        and len(text_splits[" ".join(_CWE.sub("", record["text"]).split()).casefold()]) == 1
    ]


def metrics(records):
    """Return top-1 accuracy (with a 95% Wilson interval), top-k recall, abstention."""
    if not records:
        raise ValueError("Cannot evaluate an empty dataset")
    correct = 0
    hits = Counter()
    abstained = 0
    for record in records:
        labels = {normalize_label(label) for label in record["labels"]}
        predictions = [normalize_label(label) for label in record["predictions"]]
        if record.get("abstained", not predictions):
            abstained += 1
            prediction = None
        else:
            prediction = predictions[0] if predictions else None
        correct += prediction in labels
        for k in _TOP_K:
            hits[k] += bool(
                not record.get("abstained", not predictions)
                and labels.intersection(predictions[:k])
            )
    count = len(records)
    accuracy = correct / count
    # Wilson score interval: how far accuracy could move from sampling alone.
    z = 1.96
    centre = (accuracy + z * z / (2 * count)) / (1 + z * z / count)
    spread = z * math.sqrt(
        accuracy * (1 - accuracy) / count + z * z / (4 * count * count)
    ) / (1 + z * z / count)
    return {
        "examples": count,
        "accuracy": accuracy,
        "accuracy_95ci": [max(0.0, centre - spread), min(1.0, centre + spread)],
        "top_k_recall": {k: hits[k] / count for k in _TOP_K},
        "abstention_rate": abstained / count,
    }

