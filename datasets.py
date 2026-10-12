"""Build auditable CWE benchmarks from pinned local public-data snapshots."""

import json
from pathlib import Path

from dataset_sources import load_sources
from dataset_sampling import prepare_records
from experiment import fingerprint, write_jsonl
from classification import normalize_label


def build_benchmark(manifest, catalog, output, *, review_sample_size=30, **options):
    """Save both splits, diagnostic groups, provenance, and unresolved review work."""
    if (isinstance(review_sample_size, bool) or not isinstance(review_sample_size, int)
            or review_sample_size < 0):
        raise ValueError("review_sample_size must be a nonnegative integer")
    records, provenance = load_sources(manifest)
    groups, audit, review_queue = prepare_records(records, catalog, **options)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    # Ambiguous and no-gold cases remain visible, but cannot enter accuracy metrics.
    eligible = {normalize_label(label) for label in catalog}
    benchmark = [
        record for record in groups
        if set(record["slices"]) & {"natural", "balanced", "rare", "kev", "expert"}
        and record["split"] in {"dev", "test"}
        and eligible.intersection(normalize_label(label) for label in record["labels"])
        and record["labels"] and not record["ambiguous"]
        and not record["insufficient_information"]
    ]
    write_jsonl(output / "benchmark.jsonl", benchmark)
    write_jsonl(output / "diagnostics.jsonl", groups)
    write_jsonl(output / "review_queue.jsonl", review_queue)
    # Blind the gold-standard sample to source CWE labels for independent review.
    review_sample = sorted(
        [record for record in groups if "natural" in record["slices"]],
        key=lambda record: fingerprint([options.get("seed", 0), "expert-review", record["id"]]),
    )[:review_sample_size]
    write_jsonl(output / "expert_review_sample.jsonl", [
        {
            **{key: record[key] for key in
               ("id", "aliases", "text", "published", "ecosystems", "vendors")},
            "labels": [], "expert_reviewed": False, "adjudication_status": "pending",
        }
        for record in review_sample
    ])
    report = {
        "provenance": provenance, "options": options, "audit": audit,
        "catalog_hash": fingerprint(catalog), "benchmark_hash": fingerprint(benchmark),
        "diagnostics_hash": fingerprint(groups),
        "expert_review_status": "Only imported completed expert annotations are gold",
        "expert_review_sample": {
            "requested": review_sample_size, "exported": len(review_sample),
            "method": "seeded blind sample from selected natural groups",
        },
        "notes": [
            "Natural and balanced slices are distinct estimands; report separately.",
            "KEV membership is an exploitation slice, not confirmation of CWE labels.",
            "Near-duplicate grouping is heuristic; inspect unresolved review records.",
            "No data downloads or expert labels are fabricated by this builder.",
        ],
    }
    (output / "dataset-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    return groups, report, review_queue


def evaluation_slices(results, graph, examples):
    """Score labeled subsets only; return counts, not accuracy, for no-gold slices."""
    from benchmark import metrics

    memberships = {}
    for example in examples:
        names = set(example.get("slices", []))
        if "natural" in names:
            names.update("source:" + source for source in example.get("sources", []))
        # Family membership follows every parent path, rather than selecting one
        # arbitrary parent in the multi-parent CWE graph.
        ancestors = [normalize_label(label) for label in example["labels"]]
        visited = set()
        while ancestors:
            label = ancestors.pop()
            if label in visited or label not in graph.labels:
                continue
            visited.add(label)
            if label in graph.roots and "natural" in names:
                names.add("family:CWE-" + label)
            ancestors.extend(graph.parents[label])
        memberships[example["id"]] = names
    slice_names = sorted({name for names in memberships.values() for name in names})
    return {
        name: {
            method: metrics(
                [record for record in records if name in memberships[record["id"]]],
                graph,
            )
            for method, records in results.items()
        }
        for name in slice_names
        if name not in {"ambiguous", "insufficient_information"}
    }
