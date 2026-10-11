"""Offline benchmark loading and evaluation (standard library only).

Gold labels are acceptable alternatives, not simultaneous predictions. For
macro F1, a correct top-1 resolves the singleton target to that prediction;
an incorrect/absent top-1 resolves it to the numerically smallest gold CWE.
Macro F1 averages over the union of resolved targets and emitted top-1 labels.
Abstentions count as incorrect and do not emit a prediction.
"""

import itertools
import json
import math
import random
import re
from collections import Counter
from pathlib import Path


_LABEL = re.compile(r"(?:CWE-)?([0-9]+)", re.IGNORECASE)
_EXPLICIT_CWE = re.compile(r"\bCWE[\s-]*[0-9]+\b", re.IGNORECASE)
_TOP_K = (1, 3, 5, 10)


def _label(value):
    if not isinstance(value, str):
        raise ValueError("CWE labels must be strings")
    match = _LABEL.fullmatch(value.strip())
    if not match or int(match[1]) < 1:
        raise ValueError("Invalid CWE label: {!r}".format(value))
    return "CWE-{}".format(int(match[1]))


def _labels(values, *, allow_empty=False):
    if not isinstance(values, list):
        raise ValueError("labels must be a list")
    result = sorted({_label(value) for value in values},
                    key=lambda value: int(value[4:]))
    if not result and not allow_empty:
        raise ValueError("gold labels must not be empty")
    return result


def _identifier(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("id must be a nonempty string")
    return value.strip()


def _nvd_records(document):
    vulnerabilities = document.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD vulnerabilities must be a list")
    for item in vulnerabilities:
        if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
            raise ValueError("Invalid NVD CVE record")
        cve = item["cve"]
        descriptions = cve.get("descriptions")
        weaknesses = cve.get("weaknesses", [])
        if not isinstance(descriptions, list) or not isinstance(weaknesses, list):
            raise ValueError("Invalid NVD descriptions or weaknesses")
        texts = []
        for description in descriptions:
            if (not isinstance(description, dict)
                    or not isinstance(description.get("lang"), str)
                    or not isinstance(description.get("value"), str)):
                raise ValueError("Invalid NVD description")
            if description["lang"].lower() == "en":
                texts.append(description["value"])
        labels = []
        for weakness in weaknesses:
            if (not isinstance(weakness, dict)
                    or not isinstance(weakness.get("description"), list)):
                raise ValueError("Invalid NVD weakness")
            for description in weakness["description"]:
                if (not isinstance(description, dict)
                        or not isinstance(description.get("lang"), str)
                        or not isinstance(description.get("value"), str)):
                    raise ValueError("Invalid NVD weakness description")
                if description["lang"].lower() == "en":
                    value = description["value"]
                    if value.lower() not in ("nvd-cwe-noinfo", "nvd-cwe-other"):
                        labels.append(value)
        yield {"id": cve.get("id"), "text": " ".join(texts),
               "labels": labels, "split": "test"}


def load_benchmark(path, eligible_labels, split="test", training_ids=None):
    """Load JSONL or an offline NVD JSON dump; return (examples, audit).

    Deduplication uses case-folded, whitespace-normalized, CWE-sanitized text
    across *all* splits before filtering. First occurrence wins. All IDs and
    records are validated even when excluded. Unsupported counts count each
    normalized label once per source record, before any exclusions.
    NVD noinfo/other markers mean no known gold labels.
    """
    if split not in ("test", "dev"):
        raise ValueError("split must be 'test' or 'dev'")
    if not isinstance(eligible_labels, (list, tuple, set, frozenset)):
        raise ValueError("eligible_labels must be a collection of CWE strings")
    eligible = {_label(value) for value in eligible_labels}
    if not eligible:
        raise ValueError("eligible_labels must not be empty")
    if training_ids is not None and not isinstance(training_ids, list):
        raise ValueError("training_ids must be a list")
    training = {_identifier(value) for value in (training_ids or [])}
    try:
        content = Path(path).read_text(encoding="utf-8")
    except (TypeError, UnicodeError) as error:
        raise ValueError("Invalid benchmark path or encoding") from error
    if not content.strip():
        raise ValueError("Benchmark input is empty")
    try:
        document = json.loads(content)
    except json.JSONDecodeError:
        document = None
    if isinstance(document, dict) and "vulnerabilities" in document:
        source = _nvd_records(document)
    else:
        source = []
        for number, line in enumerate(content.splitlines(), 1):
            if not line.strip():
                continue
            try:
                source.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError("Invalid JSONL on line {}".format(number)) from error
    audit = {"records_total": 0, "accepted": 0, "duplicate_text": 0,
             "wrong_split": 0, "ambiguous": 0, "training_overlap": 0,
             "no_eligible_labels": 0, "unsupported_labels": {}}
    unsupported = Counter()
    seen_ids, seen_text = set(), set()
    examples = []
    for record in source:
        if not isinstance(record, dict):
            raise ValueError("Each benchmark record must be an object")
        identifier = _identifier(record.get("id"))
        if identifier in seen_ids:
            raise ValueError("Duplicate benchmark id: {}".format(identifier))
        seen_ids.add(identifier)
        text = record.get("text")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("text must be a nonempty string")
        gold = _labels(record.get("labels"), allow_empty=True)
        record_split = record.get("split")
        if record_split not in ("test", "dev"):
            raise ValueError("Each JSONL record requires an explicit test/dev split")
        ambiguous = record.get("ambiguous", False)
        if not isinstance(ambiguous, bool):
            raise ValueError("ambiguous must be a bool")
        text = " ".join(_EXPLICIT_CWE.sub("", text).split())
        if not text:
            raise ValueError("text is empty after CWE sanitization")
        audit["records_total"] += 1
        unsupported.update(label for label in gold if label not in eligible)
        normalized = text.casefold()
        duplicate = normalized in seen_text
        seen_text.add(normalized)
        # Exclusion counters are mutually exclusive, in this priority order.
        if duplicate:
            audit["duplicate_text"] += 1
        elif ambiguous:
            audit["ambiguous"] += 1
        elif identifier in training:
            audit["training_overlap"] += 1
        elif record_split != split:
            audit["wrong_split"] += 1
        elif not eligible.intersection(gold):
            audit["no_eligible_labels"] += 1
        else:
            examples.append({"id": identifier, "text": text,
                             "labels": gold, "split": record_split})
    audit["accepted"] = len(examples)
    audit["unsupported_labels"] = dict(sorted(unsupported.items()))
    return examples, audit


def _number(value, field, *, integer=False, nullable=False):
    if value is None and nullable:
        return None
    kind = int if integer else (int, float)
    if (isinstance(value, bool) or not isinstance(value, kind)
            or value < 0 or (not integer and not math.isfinite(value))):
        raise ValueError("{} must be a nonnegative {}{}".format(
            field, "integer" if integer else "finite number",
            " or None" if nullable else ""))
    return value


def _validated_records(records, *, resources):
    if not isinstance(records, list):
        raise ValueError("records must be a list")
    seen = set()
    result = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Each result must be an object")
        identifier = _identifier(record.get("id"))
        if identifier in seen:
            raise ValueError("Duplicate result id: {}".format(identifier))
        seen.add(identifier)
        gold = _labels(record.get("labels"))
        predictions = record.get("predictions")
        if not isinstance(predictions, list):
            raise ValueError("predictions must be a ranked list")
        predictions = [_label(value) for value in predictions]
        if len(set(predictions)) != len(predictions):
            raise ValueError("Ranked predictions must not contain duplicates")
        if not isinstance(record.get("abstained"), bool):
            raise ValueError("abstained must be a bool")
        validated = dict(record, id=identifier, labels=gold,
                         predictions=predictions)
        if resources:
            for field in ("latency_seconds", "calls", "input_tokens",
                          "output_tokens", "cost"):
                if field not in record:
                    raise ValueError("Missing result field: {}".format(field))
                _number(record[field], field,
                        integer=field in ("calls", "input_tokens", "output_tokens"),
                        nullable=field in ("input_tokens", "output_tokens", "cost"))
            if not isinstance(record.get("paths"), list):
                raise ValueError("paths must be a list")
            if "candidates_scored" in record:
                _number(record["candidates_scored"], "candidates_scored", integer=True)
        result.append(validated)
    return result


def _top1(record):
    return (record["predictions"][0]
            if record["predictions"] and not record["abstained"] else None)


def metrics(records, graph):
    """Evaluate results; top-k recall is the fraction with any acceptable hit.

    Empty datasets have undefined rates/means (None). Resource totals are None
    if any record has unknown usage, with known subtotals reported separately.
    Distance is minimum top-1-to-gold distance; abstentions/empty predictions
    are excluded, and unreachable predictions are counted, not averaged.
    """
    records = _validated_records(records, resources=True)
    if not callable(getattr(graph, "distance", None)):
        raise ValueError("graph must provide distance(a, b)")
    count = len(records)
    correct = 0
    tp, fp, fn = Counter(), Counter(), Counter()
    classes = set()
    hits = Counter()
    distances = []
    unreachable = 0
    for record in records:
        prediction = _top1(record)
        valid = prediction in record["labels"]
        correct += valid
        target = prediction if valid else record["labels"][0]
        classes.add(target)
        if prediction is not None:
            classes.add(prediction)
        if valid:
            tp[prediction] += 1
        else:
            fn[target] += 1
            if prediction is not None:
                fp[prediction] += 1
        for k in _TOP_K:
            hits[k] += (not record["abstained"]
                        and bool(set(record["predictions"][:k])
                                 .intersection(record["labels"])))
        if prediction is not None:
            reachable = []
            for gold in record["labels"]:
                distance = graph.distance(prediction, gold)
                if distance is not None:
                    reachable.append(_number(distance, "distance", integer=True))
            if reachable:
                distances.append(min(reachable))
            else:
                unreachable += 1
    result = {
        "exact_match_accuracy": correct / count if count else None,
        "macro_f1": (sum(2 * tp[label] / (2 * tp[label] + fp[label] + fn[label])
                         for label in classes) / len(classes) if classes else None),
        "top_k_recall": {k: hits[k] / count if count else None for k in _TOP_K},
        "mean_hierarchical_distance": (sum(distances) / len(distances)
                                       if distances else None),
        "unreachable_count": unreachable,
        "hierarchical_distance_count": len(distances),
        "abstention_rate": (sum(r["abstained"] for r in records) / count
                            if count else None),
        "mean_latency_seconds": (sum(r["latency_seconds"] for r in records) / count
                                 if count else None),
        "total_calls": sum(r["calls"] for r in records),
    }
    for field in ("input_tokens", "output_tokens", "cost"):
        known = [r[field] for r in records if r[field] is not None]
        result["total_" + field] = sum(known) if len(known) == count else None
        result["known_" + field] = sum(known)
        result["unknown_" + field + "_count"] = count - len(known)
    if any("candidates_scored" in r for r in records):
        result["total_candidates_scored"] = sum(r.get("candidates_scored", 0)
                                                 for r in records)
    return result


def paired_intervals(results_by_method, seed=0, samples=2000):
    """Paired percentile-bootstrap 95% CIs for every method pair's accuracy.

    Returns {"A - B": {"difference": float, "lower": float, "upper": float}}.
    Method order follows mapping insertion order. Gold order is immaterial;
    normalized gold sets and ordered IDs must match. Only accuracy fields are
    required on records. Empty datasets are rejected.
    """
    if not isinstance(results_by_method, dict) or len(results_by_method) < 2:
        raise ValueError("At least two methods are required")
    if any(not isinstance(name, str) or not name.strip()
           for name in results_by_method):
        raise ValueError("Method names must be nonempty strings")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    if isinstance(samples, bool) or not isinstance(samples, int) or samples < 1:
        raise ValueError("samples must be a positive integer")
    methods = {name: _validated_records(records, resources=False)
               for name, records in results_by_method.items()}
    reference = next(iter(methods.values()))
    if not reference:
        raise ValueError("Paired datasets must not be empty")
    identity = [(r["id"], r["labels"]) for r in reference]
    for records in methods.values():
        if [(r["id"], r["labels"]) for r in records] != identity:
            raise ValueError("Methods require matched ordered IDs and gold labels")
    count = len(reference)
    correctness = {name: [int(_top1(r) in r["labels"]) for r in records]
                   for name, records in methods.items()}
    rng = random.Random(seed)
    pairs = list(itertools.combinations(methods, 2))
    distributions = {pair: [] for pair in pairs}
    for _ in range(samples):
        indices = [rng.randrange(count) for _ in range(count)]
        for a, b in pairs:
            distributions[a, b].append(
                sum(correctness[a][i] - correctness[b][i] for i in indices) / count)

    def percentile(values, fraction):
        position = (len(values) - 1) * fraction
        lower = math.floor(position)
        upper = math.ceil(position)
        return values[lower] + (values[upper] - values[lower]) * (position - lower)

    result = {}
    for a, b in pairs:
        values = sorted(distributions[a, b])
        key = "{} - {}".format(a, b)
        if key in result:
            raise ValueError("Method names produce ambiguous pair keys")
        result[key] = {
            "difference": (sum(correctness[a]) - sum(correctness[b])) / count,
            "lower": percentile(values, 0.025),
            "upper": percentile(values, 0.975),
        }
    return result
