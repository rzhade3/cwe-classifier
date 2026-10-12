"""Deterministic, leakage-aware sampling of normalized vulnerability records.

Gold is normalized to CWE-N strings, but unsupported labels are never dropped.
All source views are grouped before exclusions or sampling. Publication means
the latest known source-view date, conservatively including later annotations.
With time holdouts, any missing source-view date quarantines the entire group.

Text grouping strips CWE mentions and uses exact normalized text or token-set
Jaccard with at least eight informative tokens in both views. An inverted index
avoids comparisons of disjoint texts; common boilerplate can still produce
quadratic work. Similarity is only a heuristic: paraphrases can escape grouping,
and transitive chains can merge endpoints below the threshold. Identifier-only
training/catalog inputs cannot detect overlaps absent from the supplied views.
Adding views can change groups; freeze the input snapshot as well as the seed.

Only the natural slice is the primary accuracy population. Balanced sampling,
rare, KEV and expert slices are independent diagnostic populations, subject to
a shared per-split evaluation budget. Expert membership
requires completed, consistent, sufficient adjudicated gold. Empty sanitized
canonical text or invalid completed adjudication quarantines a group.
Completed expert ambiguity/insufficiency is never cleared by weaker sources.
Unresolved/no-gold examples
must not be scored as accuracy; their slices intentionally omit natural and
balanced. Rare frequencies use the complete eligible development population,
before sampling, never test labels.
"""

import datetime
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from collections.abc import Mapping


_CWE = re.compile(r"\bCWE[\s-]*[0-9]+\b", re.I)
_LABEL = re.compile(r"(?:CWE-)?([0-9]+)", re.I)
_CVE = re.compile(r"CVE-\d{4}-\d+", re.I)
# Match references only, not CVEs mentioned in descriptions or URLs.
_REFERENCE = re.compile(
    r"::REFERENCE:\s*(CVE-\d{4}-\d+)\s*:DESCRIPTION:", re.I)
_STOP = frozenset(
    "a an and are as at be been by can for from has have in into is it of on "
    "or that the this to was were with vulnerability vulnerabilities allows "
    "allow attacker attackers".split())
_PRIORITY = {"adjudicated": 0, "vendor": 1, "ghsa": 2, "cve": 3, "nvd": 4}
_SLICE_ORDER = ("natural", "rare", "kev", "expert", "ambiguous",
                "insufficient_information", "balanced")


def _label(value):
    match = _LABEL.fullmatch(str(value).strip())
    if isinstance(value, bool) or not match or int(match[1]) < 1:
        raise ValueError("labels must be positive numeric CWE identifiers")
    return "CWE-{}".format(int(match[1]))


def _labels(values):
    return sorted({_label(v) for v in values}, key=lambda s: int(s[4:]))


def _ident(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("identifiers must be nonempty strings")
    return value.strip().upper()


def _date(value):
    if not isinstance(value, str):
        raise ValueError("published must be YYYY-MM-DD or empty")
    if value:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise ValueError("published must be YYYY-MM-DD or empty")
        datetime.date.fromisoformat(value)
    return value


def _rank(seed, purpose, identifier):
    return hashlib.sha256(
        json.dumps([seed, purpose, identifier], separators=(",", ":"))
        .encode("utf-8")).digest()


def _completed(record):
    return (record["expert_reviewed"]
            and record["adjudication_status"] == "complete")


def _canonical_key(record):
    # A full serialized tie-breaker makes equivalent source views order-free.
    return (0 if _completed(record) else 1,
            (5 if record["source"] == "adjudicated" and not _completed(record)
             else _PRIORITY[record["source"]]), -len(record["text"]),
            record["text"], json.dumps(record, sort_keys=True))


def prepare_records(records, catalog, *, seed=0, dev_fraction=.2,
                    test_after=None, holdout_ecosystems=(), holdout_vendors=(),
                    holdout_sources=(), sample_size=200, balanced_per_label=20,
                    rare_max_count=10, near_duplicate_threshold=.9,
                    training_ids=(), max_examples_per_split=300):
    """Return (examples, audit, review_queue), without modifying input.

    ``catalog`` maps eligible CWE IDs to rows with optional Observed Examples.
    ``sample_size`` is a uniform cap *per split* on the natural population
    (default 200). None fills the finite ``max_examples_per_split`` budget.
    Balanced rows independently obey a strict cap for every gold label, including
    multi-label rows. Holdout configuration assigns matching groups to test and
    all other dated/domain groups to dev; there is no random residual split.
    Excluded leakage groups are counted but never enter examples/review_queue.
    Audit diagnostics retain full selected gold and exclusion reasons; review
    entries retain each original source's labels, text, flags and aliases,
    without a synthesized gold field. Rare/KEV/expert slice membership is
    independent of natural and balanced selection. Natural rows are selected
    first, then a deterministic greedy coverage/deficit sampler adds diagnostic
    rows up to the total budget (default 300 per split). Labels, sources, and
    rare/KEV/expert memberships are coverage features, not natural-sample weights.
    Unresolved diagnostics use leftover capacity only, never scoring slices;
    full diagnostics/review evidence survive in audit/review outputs.
    Incomplete adjudicated-source suggestions are
    review evidence only, never gold, and rank below real source descriptions.
    """
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    for name, value in (("dev_fraction", dev_fraction),
                        ("near_duplicate_threshold", near_duplicate_threshold)):
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or not 0 <= value <= 1):
            raise ValueError(name + " must be in [0, 1]")
    for name, value in (("sample_size", sample_size),
                        ("max_examples_per_split", max_examples_per_split),
                        ("balanced_per_label", balanced_per_label),
                        ("rare_max_count", rare_max_count)):
        if value is None and name == "sample_size":
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(name + " must be a nonnegative integer")
    if sample_size is not None and sample_size > max_examples_per_split:
        raise ValueError("sample_size must not exceed max_examples_per_split")
    if not isinstance(catalog, Mapping):
        raise ValueError("catalog must map eligible labels to rows")
    eligible = {_label(label) for label in catalog}
    observed = set()
    for row in catalog.values():
        if not isinstance(row, Mapping):
            raise ValueError("catalog rows must be mappings")
        value = row.get("Observed Examples", "")
        if not isinstance(value, str):
            raise ValueError("Observed Examples must be a string")
        observed.update(_ident(v) for v in _REFERENCE.findall(value))
    training = {_ident(v) for v in training_ids}
    if test_after is not None:
        if not test_after:
            raise ValueError("test_after must be a date")
        _date(test_after)
    holdouts = [set(str(v).strip().casefold() for v in values)
                for values in (holdout_ecosystems, holdout_vendors,
                               holdout_sources)]
    configured = test_after is not None or any(holdouts)
    views = []
    unsupported = Counter()
    for raw in records:
        record = dict(raw)
        record["id"] = _ident(record["id"])
        record["aliases"] = sorted({_ident(v) for v in record.get("aliases", [])}
                                   | {record["id"]})
        if not isinstance(record["text"], str):
            raise ValueError("text must be a string")
        record["labels"] = _labels(record.get("labels", []))
        unsupported.update(v for v in record["labels"] if v not in eligible)
        record["published"] = _date(record.get("published", ""))
        for field in ("ecosystems", "vendors"):
            record[field] = sorted({str(v).strip().casefold()
                                    for v in record.get(field, [])})
        record["source"] = record["source"].casefold()
        if record["source"] not in _PRIORITY:
            raise ValueError("unknown source")
        for flag in ("expert_reviewed", "ambiguous",
                     "insufficient_information", "kev"):
            record[flag] = record.get(flag, False)
            if not isinstance(record[flag], bool):
                raise ValueError(flag + " must be a boolean")
        record["adjudication_status"] = record.get("adjudication_status", "pending")
        if record["adjudication_status"] not in ("pending", "complete"):
            raise ValueError("unknown adjudication_status")
        views.append(record)
    views.sort(key=_canonical_key)
    parent = list(range(len(views)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[max(a, b)] = min(a, b)

    aliases, exact, postings, token_sets = {}, {}, defaultdict(list), []
    for i, record in enumerate(views):
        for alias in record["aliases"]:
            if alias in aliases:
                union(i, aliases[alias])
            aliases[alias] = i
        words = re.findall(r"[^\W_]+", _CWE.sub("", record["text"]).casefold())
        normalized = " ".join(words)
        if normalized:
            if normalized in exact:
                union(i, exact[normalized])
            exact[normalized] = i
        tokens = frozenset(words) - _STOP
        token_sets.append(tokens)
        if len(tokens) < 8:
            continue
        intersections = Counter()
        for token in tokens:
            intersections.update(postings[token])
        for j, common in intersections.items():
            size = len(token_sets[j])
            if (min(size, len(tokens)) / max(size, len(tokens))
                    >= near_duplicate_threshold
                    and common / (size + len(tokens) - common)
                    >= near_duplicate_threshold):
                union(i, j)
        for token in tokens:
            postings[token].append(i)

    groups = defaultdict(list)
    for i, record in enumerate(views):
        groups[find(i)].append(record)
    audit = {
        "records_total": len(views), "groups_total": len(groups),
        "unsupported_labels": dict(sorted(unsupported.items())),
        "training_overlap": 0, "catalog_overlap": 0, "missing_date": 0,
        "no_gold": 0, "no_eligible_labels": 0, "annotation_conflict": 0,
        "ambiguous": 0, "insufficient_information": 0, "empty_text": 0,
        "invalid_expert": 0,
        "assignments": {}, "excluded": [], "diagnostics": [],
        "algorithm": {
            "near_duplicate_threshold": near_duplicate_threshold,
            "minimum_informative_tokens": 8,
            "near_duplicate_similarity": "token_set_jaccard",
            "candidate_index": "inverted_token_index",
            "grouping": "transitive_dsu_aliases_exact_and_near_duplicate_text",
            "text_normalization": "CWE_stripped_casefolded_alphanumeric_tokens",
            "publication_policy": "latest_source_date_missing_time_quarantine",
            "empty_text_policy": "quarantine_sanitized_empty_canonical_text",
            "expert_policy":
                "completed_consistent_unambiguous_sufficient_nonempty_gold",
            "diagnostic_selection": "greedy_uncovered_then_inverse_count_deficit",
            "natural_selection": "uniform_seeded_sha256_id_rank_first",
            "rare_population": "eligible_dev_before_sampling",
            "rare_max_count": rare_max_count,
            "seed": seed,
        },
    }
    primary, diagnostics, review_queue = [], [], []
    for group in groups.values():
        group.sort(key=_canonical_key)
        all_aliases = sorted({v for r in group for v in r["aliases"]})
        identifier = next((v for v in all_aliases if _CVE.fullmatch(v)),
                          all_aliases[0])
        reasons = []
        if training.intersection(all_aliases):
            audit["training_overlap"] += 1
            reasons.append("training_overlap")
        if observed.intersection(all_aliases):
            audit["catalog_overlap"] += 1
            reasons.append("catalog_overlap")
        if reasons:
            audit["excluded"].append(
                {"id": identifier, "aliases": all_aliases, "reasons": reasons})
            continue
        experts = [r for r in group if _completed(r)]
        gold_views = experts or [
            r for r in group if r["labels"] and r["source"] != "adjudicated"]
        conflict = len({tuple(r["labels"]) for r in gold_views}) > 1
        canonical = (experts or group)[0]
        labels = list(gold_views[0]["labels"]) if gold_views else []
        resolved = bool(experts) and not conflict and all(
            r["labels"] and not r["ambiguous"]
            and not r["insufficient_information"] for r in experts)
        invalid_expert = bool(experts) and not resolved
        ambiguous = conflict or (not resolved and any(r["ambiguous"] for r in group))
        insufficient = (canonical["insufficient_information"] if resolved
                        else any(r["insufficient_information"] for r in group))
        text = " ".join(_CWE.sub("", canonical["text"]).split())
        empty_text = not text
        insufficient = insufficient or empty_text
        published = max(r["published"] for r in group)
        missing_date = test_after is not None and any(
            not r["published"] for r in group)
        fields = {field: sorted({v for r in group for v in r[field]})
                  for field in ("ecosystems", "vendors")}
        sources = sorted({r["source"] for r in group})
        held = ((test_after is not None and published >= test_after)
                or any(values.intersection(target) for values, target in
                       zip(holdouts, (fields["ecosystems"], fields["vendors"],
                                      sources))))
        if missing_date or empty_text or invalid_expert:
            split = "quarantine"
        elif configured:
            split = "test" if held else "dev"
        else:
            split = ("dev" if int.from_bytes(_rank(seed, "split", identifier), "big")
                     < dev_fraction * (1 << 256) else "test")
        audit["assignments"][identifier] = split
        example = dict(
            id=identifier, text=text,
            labels=labels, split=split, aliases=all_aliases, sources=sources,
            published=published, kev=any(r["kev"] for r in group),
            expert_reviewed=resolved and not insufficient,
            ambiguous=ambiguous,
            insufficient_information=insufficient, annotation_conflict=conflict,
            slices=[], **fields)
        for key, condition in (
                ("missing_date", missing_date), ("empty_text", empty_text),
                ("invalid_expert", invalid_expert),
                ("no_gold", not labels),
                ("no_eligible_labels", not eligible.intersection(labels)),
                ("annotation_conflict", conflict), ("ambiguous", ambiguous),
                ("insufficient_information", insufficient)):
            if condition:
                audit[key] += 1
                reasons.append(key)
        if reasons:
            audit["diagnostics"].append(dict(
                id=identifier, labels=labels, split=split, reasons=reasons))
            diagnostics.append(example)
        else:
            primary.append(example)
        unresolved = (ambiguous or insufficient or not labels
                      or any((r["expert_reviewed"] or r["source"] == "adjudicated")
                             and r["adjudication_status"] == "pending" for r in group))
        if unresolved and not (resolved and not insufficient):
            review_queue.append(dict(
                id=identifier, text=example["text"], aliases=all_aliases,
                reasons=reasons or ["pending_adjudication"],
                source_labels=[dict(source=r["source"], labels=list(r["labels"]),
                                    id=r["id"]) for r in group],
                evidence=[dict(r) for r in group]))

    dev_counts = Counter(label for e in primary if e["split"] == "dev"
                         for label in e["labels"])
    audit["dev_label_counts"] = dict(sorted(dev_counts.items()))
    selected = []
    audit["budgets"] = {
        "sample_size": sample_size,
        "max_examples_per_split": max_examples_per_split,
        "balanced_per_label": balanced_per_label,
    }
    audit["population_counts"], audit["budget_selection"] = {}, {}
    audit["distribution"], audit["coverage"] = {}, {}
    audit["natural_counts"], audit["balanced_counts"] = {}, {}
    for split in ("dev", "test", "quarantine"):
        population = [e for e in primary if e["split"] == split]
        natural = sorted(population,
                         key=lambda e: (_rank(seed, "natural", e["id"]), e["id"]))
        natural = natural[:max_examples_per_split if sample_size is None
                          else sample_size]
        natural_ids = {e["id"] for e in natural}
        balanced_ids, counts = set(), Counter()
        for example in sorted(population, key=lambda e: (
                _rank(seed, "balanced", e["id"]), e["id"])):
            if all(counts[label] < balanced_per_label for label in example["labels"]):
                balanced_ids.add(example["id"])
                counts.update(example["labels"])
        for example in population:
            example["slices"] = [
                name for name, ids in (("natural", natural_ids),
                                      ("balanced", balanced_ids))
                if example["id"] in ids]
            if any(dev_counts[label] <= rare_max_count
                   for label in example["labels"]):
                example["slices"].append("rare")
            if example["kev"]:
                example["slices"].append("kev")
            if example["expert_reviewed"]:
                example["slices"].append("expert")
            example["slices"] = [s for s in _SLICE_ORDER
                                 if s in example["slices"]]

        def features(example):
            return ({("label", label) for label in example["labels"]}
                    | {("source", source) for source in example["sources"]}
                    | {("slice", name) for name in example["slices"]
                       if name in ("rare", "kev", "expert", "balanced")})

        coverage = Counter()
        chosen = list(natural)
        for example in chosen:
            coverage.update(features(example))
        candidates = [e for e in population
                      if e["id"] not in natural_ids and e["slices"]]
        candidate_count = len(candidates) + len(natural)
        feature_sets = {e["id"]: features(e) for e in candidates}
        tie_ranks = {e["id"]: _rank(seed, "coverage", e["id"])
                     for e in candidates}
        while candidates and len(chosen) < max_examples_per_split:
            def priority(example):
                fs = feature_sets[example["id"]]
                return (-sum(coverage[f] == 0 for f in fs),
                        -sum(1 / (1 + coverage[f]) for f in sorted(fs)),
                        tie_ranks[example["id"]], example["id"])
            example = min(candidates, key=priority)
            candidates.remove(example)
            chosen.append(example)
            coverage.update(feature_sets[example["id"]])
        split_diagnostics = sorted(
            (e for e in diagnostics if e["split"] == split),
            key=lambda e: (_rank(seed, "diagnostic", e["id"]), e["id"]))
        for example in split_diagnostics:
            example["slices"] = [name for flag, name in (
                ("ambiguous", "ambiguous"),
                ("insufficient_information", "insufficient_information"))
                if example[flag]]
        retained_diagnostics = split_diagnostics[
            :max_examples_per_split - len(chosen)]
        selected.extend(chosen + retained_diagnostics)
        audit["natural_counts"][split] = len(natural)
        audit["balanced_counts"][split] = sum(
            "balanced" in e["slices"] for e in chosen)
        audit["population_counts"][split] = {
            "eligible": len(population), "diagnostic": len(split_diagnostics)}
        audit["budget_selection"][split] = {
            "evaluation_candidates": candidate_count,
            "selected_eligible": len(chosen),
            "selected_diagnostic": len(retained_diagnostics),
            "selected_total": len(chosen) + len(retained_diagnostics),
            "excluded_eligible_due_budget": candidate_count - len(chosen),
            "excluded_diagnostic_due_budget":
                len(split_diagnostics) - len(retained_diagnostics),
            "omitted_without_selected_slice": len(population) - candidate_count,
        }

        def distribution(rows):
            result = {}
            for field in ("labels", "sources", "ecosystems", "vendors", "slices"):
                counts = Counter(value for e in rows for value in e[field])
                result[field] = dict(sorted(counts.items()))
            return result

        audit["distribution"][split] = {
            "eligible_population": distribution(population),
            "selected_eligible": distribution(chosen),
            "selected_natural": distribution(natural),
            "selected_non_natural": distribution(
                [e for e in chosen if e["id"] not in natural_ids])}
        all_features = {f for e in population for f in features(e)}
        audit["coverage"][split] = {
            kind: {
                "available": sorted(value for k, value in all_features if k == kind),
                "selected": sorted(value for k, value in coverage if k == kind),
                "uncovered": sorted(value for k, value in all_features
                                    if k == kind and not coverage.get((k, value))),
            } for kind in ("label", "source", "slice")}
    audit["slice_counts"] = {
        split: {name: sum(name in e["slices"] for e in selected
                         if e["split"] == split)
                for name in _SLICE_ORDER}
        for split in ("dev", "test", "quarantine")
    }
    audit["accepted"] = len(selected)
    audit["primary_eligible"] = len(primary)
    for field in ("excluded", "diagnostics"):
        audit[field].sort(key=lambda r: r["id"])
    audit["assignments"] = dict(sorted(audit["assignments"].items()))
    return (sorted(selected, key=lambda e: e["id"]), audit,
            sorted(review_queue, key=lambda e: e["id"]))
