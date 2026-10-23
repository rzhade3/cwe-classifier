"""Compare models (lexical, vector, Jev, ...) under flat/greedy/beam methods."""

import hashlib
import json
import math
import random
from dataclasses import asdict
from pathlib import Path

from classification import (
    CWEGraph,
    classify,
    load_scorer,
    normalize_label,
    select_classify,
)

from . import default_config, fingerprint, write_jsonl
from .artifacts import (
    append_checkpoint,
    atomic_json,
    load_checkpoint,
    output_lock,
    provenance,
)
from .benchmark import load_benchmark, metrics

_WIDTHS = {"flat": None, "greedy": 1, "beam": "beam_width"}


def run_experiment(config):
    """Serialize writers; checkpoint each completed prediction before continuing."""
    output = Path(config.get("output", default_config(Path.cwd())["output"]))
    with output_lock(output):
        return _run_experiment(config)


def _run_experiment(config):
    """Evaluate every model x method system on the same held-out examples.

    ``models`` maps a display name to a scorer/selector spec. Scorers (with
    ``score``) use ``classify`` and its threshold/margin/stop_policy settings;
    selectors (with ``select``) use ``select_classify`` and its explicit STOP.
    Flat is skipped (and listed in ``skipped``) for a selector whose
    ``max_options`` is smaller than the catalog.
    Systems are named ``"<model>/<method>"``.
    """
    root = Path.cwd()
    defaults = default_config(root)
    if set(config) - set(defaults):
        raise ValueError(
            f"Unknown experiment settings: {sorted(set(config) - set(defaults))}"
        )
    settings = {**defaults, **config}
    models = settings["models"]
    if (
        not isinstance(models, dict)
        or not models
        or not all(
            isinstance(name, str)
            and name
            and all(c.isalnum() or c in "_-" for c in name)
            and isinstance(spec, str)
            and spec
            for name, spec in models.items()
        )
    ):
        raise ValueError("models must map names without '/' to scorer specs")
    methods = settings["methods"]
    if (
        not isinstance(methods, list)
        or not methods
        or not all(isinstance(method, str) for method in methods)
        or len(set(methods)) != len(methods)
        or not set(methods) <= _WIDTHS.keys()
    ):
        raise ValueError("Choose flat, greedy, and/or beam methods without duplicates")
    for name in ("max_examples", "top_k", "beam_width"):
        value = settings[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    if settings["stop_policy"] not in {"specificity", "improvement", "leaf"}:
        raise ValueError("Unknown traversal stopping policy")
    if (
        isinstance(settings["seed"], bool)
        or not isinstance(settings["seed"], int)
        or isinstance(settings["threshold"], bool)
        or not isinstance(settings["threshold"], (int, float))
        or not math.isfinite(settings["threshold"])
        or isinstance(settings["margin"], bool)
        or not isinstance(settings["margin"], (int, float))
        or not math.isfinite(settings["margin"])
        or settings["margin"] < 0
    ):
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
        order[: settings["max_examples"]], key=lambda example: example["id"]
    )

    output = Path(settings["output"])
    benchmark_sha256 = hashlib.sha256(
        Path(settings["benchmark"]).read_bytes()
    ).hexdigest()
    catalog_sha256 = hashlib.sha256(Path(settings["catalog"]).read_bytes()).hexdigest()
    environment = provenance()
    report_path = Path(settings["benchmark"]).with_name("dataset-report.json")
    dataset_report = (
        json.loads(report_path.read_text()) if report_path.is_file() else None
    )
    if dataset_report is not None:
        for field, actual in (
            ("catalog_sha256", catalog_sha256),
            ("benchmark_file_sha256", benchmark_sha256),
        ):
            if dataset_report.get(field) != actual:
                raise ValueError(
                    f"Dataset report {field} does not match the selected inputs; prepare again"
                )
    options = settings["model_options"]
    if not isinstance(options, dict) or set(options) - set(models):
        raise ValueError("model_options must be keyed by configured model name")
    for value in options.values():
        if not isinstance(value, dict) or any(
            any(
                secret in key.lower()
                for secret in ("api_key", "secret", "password", "token")
            )
            for key in value
        ):
            raise ValueError(
                "Model options must be dictionaries without credentials; use environment variables"
            )
    selected_ids = [example["id"] for example in examples]
    unknown = {
        label
        for example in examples
        for label in example["labels"]
        if normalize_label(label) not in graph.labels
    }
    if unknown:
        raise ValueError(f"Benchmark labels absent from catalog: {sorted(unknown)}")

    (output / "metrics.json").unlink(missing_ok=True)
    checkpoint_keys = {}
    results = {}
    reused = {}
    skipped = {}
    model_metadata = {}
    for model, spec in models.items():
        scorer = load_scorer(spec, graph.labels, **options.get(model, {}))
        prior_resolved = None
        model_resolved = None
        initial_metadata = dict(getattr(scorer, "metadata", None) or {})
        initial_metadata.pop("resolved_model", None)
        for method in methods:
            width_setting = _WIDTHS[method]
            width = (
                settings[width_setting]
                if isinstance(width_setting, str)
                else width_setting
            )
            limit = getattr(scorer, "max_options", None)
            if (
                method == "flat"
                and isinstance(limit, int)
                and len(graph.labels) > limit
            ):
                skipped[f"{model}/{method}"] = (
                    f"{len(graph.labels)} catalog CWEs exceed the {limit}-option limit"
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
            identity = {
                "schema": 2,
                "system": system,
                "spec": spec,
                "options": options.get(model, {}),
                "metadata": initial_metadata,
                "settings": {key: settings[key] for key in _REUSE_KEYS},
                "benchmark_sha256": benchmark_sha256,
                "catalog_sha256": catalog_sha256,
                "environment": {
                    key: value
                    for key, value in environment.items()
                    if key != "revision"
                },
            }
            cache_key = fingerprint(identity)
            checkpoint_keys[system] = cache_key
            cache = output / "checkpoints"
            cache.mkdir(exist_ok=True)
            checkpoint = cache / f"{cache_key}.jsonl"
            atomic_json(cache / f"{cache_key}.manifest.json", identity)
            saved = load_checkpoint(checkpoint)
            resolved = {
                item["metadata"].get("resolved_model") for item in saved.values()
            } - {None}
            if len(resolved) > 1:
                raise ValueError("Checkpoint mixes model versions")
            prior_resolved = next(iter(resolved), None)
            if model_resolved and prior_resolved and model_resolved != prior_resolved:
                raise ValueError(
                    "Model checkpoints mix response versions across methods"
                )
            records = []
            reused[system] = 0
            for example in examples:
                prior = saved.get(example["id"])
                if prior is not None:
                    record = prior["record"]
                    reused[system] += 1
                else:
                    record = {**example, **asdict(run(example["text"]))}
                    metadata = dict(getattr(scorer, "metadata", None) or {})
                    after = metadata.get("resolved_model")
                    before = prior_resolved or model_resolved
                    if before and after and before != after:
                        raise ValueError(
                            f"Saved results came from {before}, received {after}; "
                            "pin the original model or use a new model name"
                        )
                    prior_resolved = after or prior_resolved
                    append_checkpoint(checkpoint, record, metadata)
                records.append(record)
            model_resolved = prior_resolved or model_resolved
            results[system] = records
            # Smaller reports never truncate the content-addressed checkpoint.
            destination = output / f"{system.replace('/', '-')}.jsonl"
            temporary = destination.with_suffix(".jsonl.tmp")
            write_jsonl(temporary, records)
            temporary.replace(destination)
        metadata = dict(getattr(scorer, "metadata", None) or {})
        metadata["resolved_model"] = model_resolved or metadata.get("resolved_model")
        model_metadata[model] = {"spec": spec, **metadata}

    summary = {
        "schema": 2,
        "provenance": environment,
        "dataset_report": dataset_report,
        "catalog_sha256": catalog_sha256,
        "selected_ids": selected_ids,
        "checkpoint_keys": checkpoint_keys,
        "systems": {system: metrics(records) for system, records in results.items()},
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
                "view",
                "split",
                "models",
                "model_options",
                "methods",
                "max_examples",
                "beam_width",
                "top_k",
                "threshold",
                "margin",
                "stop_policy",
                "seed",
            )
        },
    }
    atomic_json(output / "metrics.json", summary)
    return summary


# Settings that change predictions; max_examples, models, and methods may differ.
_REUSE_KEYS = (
    "view",
    "split",
    "beam_width",
    "top_k",
    "threshold",
    "margin",
    "stop_policy",
    "seed",
)
