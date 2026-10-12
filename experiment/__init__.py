"""Small helpers shared by the CWE experiment notebook and data preparation."""

import hashlib
import json
from pathlib import Path


def default_config(root):
    root = Path(root)
    return {
        "catalog": str(root / "data" / "all.csv"),
        "benchmark": str(root / "experiment" / "data" / "prepared" / "benchmark.jsonl"),
        "output": str(root / "experiment" / "results"),
        "view": "1000",
        "split": "test",
        "models": {
            "lexical": "lexical",
            "vector": "vector",
            "jev-parent": "experiment.jev_selector:create_parent_selector",
            "jev-parent-rich": "experiment.jev_selector:create_rich_parent_selector",
        },
        "methods": ["flat", "greedy", "beam"],
        "max_examples": 500,
        "beam_width": 3,
        "top_k": 5,
        "threshold": 0.0,
        "margin": 0.0,
        "stop_policy": "specificity",
        "seed": 0,
    }


def fingerprint(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def write_jsonl(path, records):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
