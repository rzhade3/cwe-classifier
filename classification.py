"""CWE graph traversal and candidate-scoring adapters."""

import csv
import importlib
import math
import re
from collections import deque
from dataclasses import dataclass, field
from time import perf_counter


def normalize_label(value):
    value = str(value).upper().removeprefix("CWE-")
    if not value.isdigit():
        raise ValueError(f"Invalid CWE label: {value}")
    return str(int(value))


class CWEGraph:
    def __init__(self, path, view="1000"):
        with open(path, encoding="utf-8", newline="") as stream:
            self._build(list(csv.DictReader(stream)), view)

    @classmethod
    def from_rows(cls, rows, view="1000"):
        graph = cls.__new__(cls)
        graph._build(list(rows), view)
        return graph

    def _build(self, rows, view):
        self.labels = {
            normalize_label(row["CWE-ID"]): row
            for row in rows if row["Status"] not in {"Deprecated", "Obsolete"}
        }
        self.children = {label: set() for label in self.labels}
        self.parents = {label: set() for label in self.labels}
        for label, row in self.labels.items():
            for relation in row.get("Related Weaknesses", "").split("::"):
                fields = relation.split(":")
                values = dict(zip(fields[::2], fields[1::2]))
                if values.get("NATURE") != "ChildOf" or values.get("VIEW ID") != str(view):
                    continue
                parent = normalize_label(values["CWE ID"])
                if parent in self.labels:
                    self.parents[label].add(parent)
                    self.children[parent].add(label)
        # Kahn's algorithm both validates the DAG and retains disconnected nodes.
        degree = {label: len(parents) for label, parents in self.parents.items()}
        self.roots = sorted(label for label in degree if degree[label] == 0)
        queue = deque(self.roots)
        visited = 0
        while queue:
            label = queue.popleft()
            visited += 1
            for child in sorted(self.children[label]):
                degree[child] -= 1
                if degree[child] == 0:
                    queue.append(child)
        if visited != len(self.labels):
            raise ValueError("CWE ChildOf graph contains a cycle")
        if not self.labels:
            raise ValueError("CWE catalog is empty")

    def distance(self, first, second):
        first, second = normalize_label(first), normalize_label(second)
        if first not in self.labels or second not in self.labels:
            return None
        queue = deque([(first, 0)])
        seen = {first}
        while queue:
            label, distance = queue.popleft()
            if label == second:
                return distance
            for neighbor in self.parents[label] | self.children[label]:
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append((neighbor, distance + 1))
        return None


@dataclass
class Prediction:
    predictions: list = field(default_factory=list)
    paths: list = field(default_factory=list)
    calls: int = 0
    candidates_scored: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost: float | None = None
    latency_seconds: float = 0.0
    abstained: bool = False
    # Selector questions in order: {"current": node or None, "probabilities": {option: p}}.
    steps: list = field(default_factory=list)


class LexicalScorer:
    """Offline reference scorer, NOT a learned classifier."""

    def __init__(self, catalog):
        self.documents = {
            label: self.words(row["Name"] + " " + row["Description"])
            for label, row in catalog.items()
        }

    @staticmethod
    def words(text):
        return set(re.findall(r"[a-z0-9]+", text.lower()))

    def score(self, text, labels):
        query = self.words(text)
        return {
            label: len(query & self.documents[label]) /
            max(1, math.sqrt(len(query) * len(self.documents[label])))
            for label in labels
        }


def load_scorer(spec, catalog):
    """Load ``lexical``, ``vector``, or a ``module:factory`` scorer/selector."""
    if spec == "lexical":
        return LexicalScorer(catalog)
    if spec == "vector":
        spec = "experiment.vector_scorer:VectorScorer"
    module, separator, factory = spec.partition(":")
    if not separator:
        raise ValueError("Scorer must be lexical, vector, or module:factory")
    return getattr(importlib.import_module(module), factory)(catalog)


def _add_usage(result, usage):
    """Accumulate usage after ``result.calls`` is incremented; unknown stays None."""
    for key in ("input_tokens", "output_tokens", "cost"):
        value = usage.get(key)
        if value is not None:
            if (isinstance(value, bool) or not isinstance(value, (int, float)) or
                    not math.isfinite(value) or value < 0 or
                    (key.endswith("_tokens") and not isinstance(value, int))):
                raise ValueError(f"Invalid scorer usage field: {key}")
        previous = getattr(result, key)
        setattr(result, key, (previous or 0) + value if value is not None and
                (result.calls == 1 or previous is not None) else None)


def classify(text, graph, scorer, beam_width=None, top_k=5, threshold=0.0, margin=0.0,
             stop_policy="specificity"):
    """Scores must be comparable across candidate sets and higher is better."""
    if top_k < 1 or (beam_width is not None and beam_width < 1):
        raise ValueError("top_k and beam_width must be positive")
    if not math.isfinite(threshold) or not math.isfinite(margin) or margin < 0:
        raise ValueError("threshold must be finite and margin nonnegative")
    if stop_policy not in {"specificity", "improvement", "leaf"}:
        raise ValueError("Unknown traversal stopping policy")
    result = Prediction()
    start = perf_counter()
    cache = {}

    def score(labels):
        missing = sorted(set(labels) - cache.keys())
        if missing:
            values = scorer.score(text, missing)
            if set(values) != set(missing):
                raise ValueError("Scorer must return exactly the requested label scores")
            for label, value in values.items():
                if not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise ValueError("Classifier scores must be finite numbers")
            cache.update(values)
            result.calls += 1
            result.candidates_scored += len(missing)
            _add_usage(result, getattr(scorer, "last_usage", {}))
        return sorted(labels, key=lambda label: (-cache[label], label))

    if beam_width is None:
        ranked = score(graph.labels)
        result.predictions = [label for label in ranked if cache[label] >= threshold][:top_k]
    else:
        active = [(label, [label]) for label in score(graph.roots)[:beam_width]
                  if cache[label] >= threshold]
        finished = []
        while active:
            candidates = []
            score({child for label, _ in active for child in graph.children[label]})
            for label, path in active:
                can_stop = stop_policy == "improvement" or (
                    stop_policy == "specificity" and
                    graph.labels[label].get("Weakness Abstraction") in {"Base", "Variant"}
                )
                children = [
                    child for child in graph.children[label]
                    if cache[child] >= threshold and
                    (not can_stop or cache[child] > cache[label] + margin)
                ]
                if children:
                    candidates.extend((child, path + [child]) for child in children)
                elif can_stop or not graph.children[label]:
                    finished.append((label, path))
            candidates.sort(key=lambda item: (-cache[item[0]], item[0], item[1]))
            active = []
            seen = set()
            for candidate in candidates:
                if candidate[0] not in seen:
                    active.append(candidate)
                    seen.add(candidate[0])
                if len(active) == beam_width:
                    break
        finished.sort(key=lambda item: (-cache[item[0]], item[0], item[1]))
        for label, path in finished:
            if label not in result.predictions:
                result.predictions.append(label)
                result.paths.append(path)
            if len(result.predictions) == top_k:
                break
    result.latency_seconds = perf_counter() - start
    result.abstained = not result.predictions
    return result


STOP = "STOP"


def select_classify(text, graph, selector, beam_width=None, top_k=5):
    """Classify with a selector that picks among offered options.

    ``selector.select(text, labels, current=None)`` returns a probability for
    each offered label, plus ``STOP`` when ``current`` is given; STOP means
    ``current`` itself fits better than any of its children.

    - Flat (``beam_width=None``) asks one question over every catalog CWE.
      A selector may declare ``max_options``; asking more raises ValueError.
    - Greedy (``beam_width=1``) starts at the roots and follows the most
      probable option at each step, ending at STOP or a leaf.
    - Beam keeps the ``beam_width`` most probable paths, where a path's
      probability is the product of its choices. Probabilities come from one
      question at a time, so no cross-question score calibration is needed.

    Every question and its full probability distribution is kept in
    ``result.steps`` for later analysis (calibration, coverage, step accuracy).
    """
    if top_k < 1 or (beam_width is not None and beam_width < 1):
        raise ValueError("top_k and beam_width must be positive")
    max_options = getattr(selector, "max_options", None)
    if max_options is not None and (
            isinstance(max_options, bool) or not isinstance(max_options, int)
            or max_options < 2):
        raise ValueError("Selector max_options must be an integer of at least 2")
    result = Prediction()
    start = perf_counter()

    def ask(labels, current=None):
        labels = sorted(labels)
        offered = len(labels) + (current is not None)
        if max_options is not None and offered > max_options:
            raise ValueError(
                f"{offered} options exceed the selector limit of {max_options}"
            )
        values = selector.select(text, labels, current)
        expected = set(labels) | ({STOP} if current is not None else set())
        if set(values) != expected:
            raise ValueError("Selector must return exactly the offered options")
        for value in values.values():
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or not 0 <= value <= 1):
                raise ValueError("Selector probabilities must be in [0, 1]")
        result.calls += 1
        result.candidates_scored += len(labels)
        _add_usage(result, getattr(selector, "last_usage", {}))
        result.steps.append({"current": current, "probabilities": dict(values)})
        return values

    def ranked(values):
        return sorted(values.items(), key=lambda item: (-item[1], item[0]))

    if beam_width is None:
        result.predictions = [
            label for label, _ in ranked(ask(graph.labels))[:top_k]
        ]
    elif beam_width == 1:
        path = [ranked(ask(graph.roots))[0][0]]
        while graph.children[path[-1]]:
            choice = ranked(ask(graph.children[path[-1]], path[-1]))[0][0]
            if choice == STOP:
                break
            path.append(choice)
        result.predictions, result.paths = [path[-1]], [path]
    else:
        active = [(p, [label]) for label, p in ranked(ask(graph.roots))[:beam_width]]
        finished = {}

        def finish(probability, path):
            if probability > finished.get(path[-1], (-1, None))[0]:
                finished[path[-1]] = (probability, path)

        while active:
            candidates = {}
            for probability, path in active:
                children = graph.children[path[-1]]
                if not children:
                    finish(probability, path)
                    continue
                values = ask(children, path[-1])
                finish(probability * values[STOP], path)
                for child in children:
                    score = probability * values[child]
                    if score > candidates.get(child, (-1, None))[0]:
                        candidates[child] = (score, path + [child])
            active = sorted(candidates.values(),
                            key=lambda item: (-item[0], item[1]))[:beam_width]
            best = sorted(finished.values(), key=lambda item: (-item[0], item[1]))
            # Path probabilities only shrink, so stop once top_k cannot change.
            if active and len(best) >= top_k and best[top_k - 1][0] >= active[0][0]:
                break
        for _, path in sorted(finished.values(),
                              key=lambda item: (-item[0], item[1]))[:top_k]:
            result.predictions.append(path[-1])
            result.paths.append(path)
    result.latency_seconds = perf_counter() - start
    result.abstained = not result.predictions
    return result
