"""Compare models (lexical, vector, Jev, ...) under flat/greedy/beam methods."""

import hashlib
import json
import math
import random
from dataclasses import asdict
from pathlib import Path

from classification import CWEGraph, classify, load_scorer, select_classify
from . import default_config, write_jsonl
from .benchmark import load_benchmark, metrics


_WIDTHS = {"flat": None, "greedy": 1, "beam": "beam_width"}


def run_experiment(config):
    """Evaluate every model x method system on the same held-out examples.

    ``models`` maps a display name to a scorer/selector spec. Scorers (with
    ``score``) use ``classify`` and its threshold/margin/stop_policy settings;
    selectors (with ``select``) use ``select_classify`` and its explicit STOP.
    Flat is skipped (and listed in ``skipped``) for a selector whose
    ``max_options`` is smaller than the catalog.
    Systems are named ``"<model>/<method>"``.
    """
    root = Path.cwd()
    settings = {**default_config(root), **config}
    models = settings["models"]
    if (not isinstance(models, dict) or not models
            or not all(isinstance(name, str) and name and "/" not in name
                       and isinstance(spec, str) and spec
                       for name, spec in models.items())):
        raise ValueError("models must map names without '/' to scorer specs")
    methods = settings["methods"]
    if (not isinstance(methods, list) or not methods
            or not all(isinstance(method, str) for method in methods)
            or len(set(methods)) != len(methods)
            or not set(methods) <= _WIDTHS.keys()):
        raise ValueError("Choose flat, greedy, and/or beam methods without duplicates")
    for name in ("max_examples", "top_k", "beam_width"):
        value = settings[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    if settings["stop_policy"] not in {"specificity", "improvement", "leaf"}:
        raise ValueError("Unknown traversal stopping policy")
    if (isinstance(settings["seed"], bool)
            or not isinstance(settings["seed"], int)
            or isinstance(settings["threshold"], bool)
            or not isinstance(settings["threshold"], (int, float))
            or not math.isfinite(settings["threshold"])
            or isinstance(settings["margin"], bool)
            or not isinstance(settings["margin"], (int, float))
            or not math.isfinite(settings["margin"])
            or settings["margin"] < 0):
        raise ValueError("Seed, threshold, or margin is invalid")

    graph = CWEGraph(settings["catalog"], settings["view"])
    examples = load_benchmark(settings["benchmark"], settings["split"])
    if not examples:
        raise ValueError("No eligible examples in the selected split")
    population_size = len(examples)
    # One seeded shuffle of the whole split; a run takes its first N examples,
    # so a smaller run is always a subset of a larger one with the same seed.
    order = sorted(examples, key=lambda example: example["id"])
    random.Random(settings["seed"]).shuffle(order)
    examples = sorted(
        order[:settings["max_examples"]], key=lambda example: example["id"]
    )

    output = Path(settings["output"])
    benchmark_sha256 = hashlib.sha256(
        Path(settings["benchmark"]).read_bytes()
    ).hexdigest()
    previous = _previous_run(output, settings, benchmark_sha256)

    results = {}
    reused = {}
    skipped = {}
    model_metadata = {}
    for model, spec in models.items():
        scorer = load_scorer(spec, graph.labels)
        prior_model = previous["models"].get(model, {})
        can_reuse = prior_model.get("spec") == spec
        for method in methods:
            width_setting = _WIDTHS[method]
            width = (
                settings[width_setting]
                if isinstance(width_setting, str) else width_setting
            )
            limit = getattr(scorer, "max_options", None)
            if (method == "flat" and isinstance(limit, int)
                    and len(graph.labels) > limit):
                skipped[f"{model}/{method}"] = (
                    f"{len(graph.labels)} catalog CWEs exceed the "
                    f"{limit}-option limit"
                )
                continue
            if callable(getattr(scorer, "select", None)):
                run = lambda text: select_classify(
                    text, graph, scorer, beam_width=width, top_k=settings["top_k"]
                )
            else:
                run = lambda text: classify(
                    text,
                    graph,
                    scorer,
                    beam_width=width,
                    top_k=settings["top_k"],
                    threshold=settings["threshold"],
                    margin=settings["margin"],
                    stop_policy=settings["stop_policy"],
                )
            system = f"{model}/{method}"
            saved = _saved_records(output, system) if can_reuse else {}
            records = []
            for example in examples:
                prior = saved.get(example["id"])
                if prior is not None and prior.get("text") == example["text"]:
                    records.append(prior)
                else:
                    records.append({**example, **asdict(run(example["text"]))})
            reused[system] = sum(
                saved.get(example["id"]) is records[index]
                for index, example in enumerate(examples)
            )
            metadata = getattr(scorer, "metadata", None) or {}
            before = prior_model.get("resolved_model")
            after = metadata.get("resolved_model")
            if reused[system] and before and after and before != after:
                raise ValueError(
                    f"{model} answered as {after} but saved results came from "
                    f"{before}; set TYPESAFE_DEFAULT_MODEL={before} or use a "
                    "new output directory"
                )
            results[system] = records
            output.mkdir(parents=True, exist_ok=True)
            write_jsonl(output / f"{system.replace('/', '-')}.jsonl", records)
        metadata = getattr(scorer, "metadata", None) or {}
        if metadata.get("resolved_model") is None and prior_model.get("resolved_model"):
            metadata = {**metadata, "resolved_model": prior_model["resolved_model"]}
        model_metadata[model] = {"spec": spec, **metadata}

    summary = {
        "systems": {
            system: metrics(records)
            for system, records in results.items()
        },
        "models": model_metadata,
        "skipped": skipped,
        "reused": reused,
        "examples": {
            "split": settings["split"],
            "population": population_size,
            "evaluated": len(examples),
            "sha256": benchmark_sha256,
        },
        "settings": {
            name: settings[name]
            for name in (
                "view", "split", "models", "methods", "max_examples",
                "beam_width", "top_k", "threshold", "margin", "stop_policy", "seed",
            )
        },
    }
    summary_path = output / "metrics.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


# Settings that change predictions; max_examples, models, and methods may differ.
_REUSE_KEYS = (
    "view", "split", "beam_width", "top_k", "threshold", "margin",
    "stop_policy", "seed",
)


def _previous_run(output, settings, benchmark_sha256):
    """Return the prior run's metadata if its predictions can be reused."""
    empty = {"models": {}}
    path = output / "metrics.json"
    if not path.is_file():
        return empty
    prior = json.loads(path.read_text(encoding="utf-8"))
    if prior.get("examples", {}).get("sha256") != benchmark_sha256:
        return empty
    prior_settings = prior.get("settings", {})
    if any(prior_settings.get(key) != settings[key] for key in _REUSE_KEYS):
        return empty
    return {"models": prior.get("models", {})}


def _saved_records(output, system):
    path = output / f"{system.replace('/', '-')}.jsonl"
    if not path.is_file():
        return {}
    return {
        record["id"]: record
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and (record := json.loads(line))
    }
