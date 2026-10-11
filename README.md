# CWE Classifier

A semantic search tool for the Common Weakness Enumeration (CWE) database,
with a reproducible notebook for comparing flat classification, graph traversal,
and naive one-shot classification.

## Overview

The CWE Classifier provides a command-line interface to:
- Build a searchable vector index from CWE CSV data
- Perform semantic similarity searches across CWE entries
- Find the most relevant CWE classifications for vulnerability descriptions

## Features

- **Vector-based Search**: Uses ChromaDB with default embedding functions for semantic similarity
- **Persistent Storage**: Maintains the search index between sessions
- **Flexible Input**: Works with CWE CSV data from the official MITRE database
- **Configurable Results**: Adjustable number of search results (top-k)
- **Command Line Interface**: Easy-to-use CLI for both indexing and searching
- **Experiment Notebook**: Visible benchmark preparation, model comparisons,
  metrics, paired confidence intervals, and routing-error inspection

## Installation

1. Clone the repository:
```bash
git clone https://github.com/rzhade3/cwe-classifier.git
cd cwe-classifier
```

2. Install uv (if you haven't already):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

3. Install dependencies (Python **3.13+**, as required by `pyproject.toml`):
```bash
uv sync
```

Run commands from the checkout using `uv run` so they use the project's
environment. Alternatively, activate its `.venv` before using bare `python`.
The absolute paths below refer to this checkout; substitute your checkout's
path when working elsewhere.

## Data Format

The tool expects CWE data in CSV format with the following columns:
- `CWE-ID`: The CWE identifier
- `Name`: The name of the weakness
- `Description`: Short description of the weakness
- `Extended Description`: Detailed description of the weakness

Hierarchy experiments additionally require `Status` (for eligibility filtering)
and `Related Weaknesses` (MITRE's structured `ChildOf` relationships with view IDs).
The bundled CSV includes these columns.

You can download the official CWE database in CSV format from [MITRE's CWE downloads page](https://cwe.mitre.org/data/downloads.html).

## Usage

### Generate Index

First, build the search index from your CWE CSV data:

```bash
uv run python /home/runner/work/cwe-classifier/cwe-classifier/main.py generate-index /tmp/your-cwe-data.csv
```

Example:
```bash
uv run python /home/runner/work/cwe-classifier/cwe-classifier/main.py generate-index /home/runner/work/cwe-classifier/cwe-classifier/data/all.csv
```

### Search CWEs

Search for relevant CWE entries using natural language queries:

```bash
uv run python /home/runner/work/cwe-classifier/cwe-classifier/main.py search "your search query"
```

#### Search Options

- `--top-k`: Number of results to return (default: 5)

#### Examples

```bash
# Basic search
uv run python /home/runner/work/cwe-classifier/cwe-classifier/main.py search "buffer overflow"

# Search with more results
uv run python /home/runner/work/cwe-classifier/cwe-classifier/main.py search "sql injection" --top-k 10

# Multi-word queries
uv run python /home/runner/work/cwe-classifier/cwe-classifier/main.py search "cross site scripting vulnerabilities"
```

### Sample Output

```
Searching for: 'buffer overflow'

Found 5 results:

1. CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
   Description: The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer, leading to a buffer overflow...

2. CWE-121: Stack-based Buffer Overflow
   Description: A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e., is a local variable or, rarely, a parameter to a function)...

...
```

## Use Cases

- **Security Research**: Quickly find relevant CWE classifications for newly discovered vulnerabilities
- **Code Review**: Identify potential weakness categories during security assessments
- **Compliance**: Map identified issues to standard CWE classifications for reporting
- **Education**: Explore relationships between different types of software weaknesses

## Classification experiments

[`experiments.ipynb`](experiments.ipynb) is the primary experiment workflow:
configuration, benchmark preparation/audit, optional one-shot prompt export,
flat/greedy/beam comparison, metrics, artifact export, and routing-error
inspection are visible in separate cells. Graph/scorer implementations and
metric utilities remain in tested Python modules. `experiment.py` retains artifact
helpers and a compatibility CLI that executes the notebook's code cells; it does
not maintain a second experiment implementation.

Install the locked notebook extra and open the notebook:

```bash
uv sync --extra notebook
uv run --extra notebook jupyter lab /home/runner/work/cwe-classifier/cwe-classifier/experiments.ipynb
```

Choose the project Python kernel and **Restart Kernel and Run All**. The default
configuration runs three explicitly synthetic examples with the lexical scorer
offline, writing artifacts to `/tmp/cwe-notebook-results`. It makes no model API
calls or embedding downloads. It is a pipeline demonstration, not a held-out
accuracy experiment. Set `demo` to false and supply a benchmark for real evaluation;
enable Chroma, Jev, and one-shot explicitly. Paths derive from the notebook's
`ROOT` setting; change it if your checkout is elsewhere.

The notebook compares the existing embedding approach with flat candidate
classification, greedy traversal, beam traversal, and a naive single-call,
zero-shot LLM baseline. The original search index and CLI are unchanged. Chroma experiments
build a separate ephemeral index over the same eligible catalog as the other
methods; initial embedding model downloads may require network access.

The hierarchy uses `ChildOf` edges from a single view (default `1000`), preserves
multiple parents, rejects cycles, and includes disconnected catalog entries as
roots. Deprecated/obsolete entries are excluded. Traversal scores roots, then
children, keeping the best `--beam-width` paths. It stops at a parent unless a
child exceeds its score by `--margin` and meets `--threshold`. Scores are cached
per example, and repeated terminal labels are deduplicated. Beam search may mitigate
early routing errors; this hypothesis requires a real benchmark. Graph distance is shortest
undirected distance in the selected view; disconnected pairs are reported.

### Benchmark inputs

Use independently annotated vulnerability descriptions, not CWE catalog
descriptions. Supply JSONL records with `id`, `text`, `labels` (a list of CWE
identifiers), and an explicit `split` (`dev` or `test`); optional `ambiguous: true`
marks annotations to exclude. Multiple labels represent acceptable answers.
Alternatively, supply a locally downloaded NVD JSON dump with its
`vulnerabilities` array. NVD inputs default to the test split: create a separate,
disjoint development set before tuning. No live per-CVE API requests are made.

Inputs are normalized, explicit CWE identifiers are removed, repeated sanitized
texts are deduplicated, and development/test overlap is excluded when both splits
are present in the input. Keep the combined dev/test source for evaluation; the
loader cannot detect overlap with an unseen separate file. Examples without
eligible gold labels and ambiguous examples are excluded with audit counts.
Known training overlap can be excluded using `--training-ids`, a JSON array of
example IDs. This cannot establish absence of training contamination: record the
model's training provenance and report unknown overlap honestly.

In the notebook, edit `config`: select `command` (`prepare`, `export-prompts`,
or `run`), paths, split, methods, scorer, and traversal settings. Tune on dev and
freeze configuration before test evaluation. The compatibility CLI remains
available for existing automation; replace benchmark and output paths as needed:

```bash
uv run python /home/runner/work/cwe-classifier/cwe-classifier/experiment.py prepare \
  --catalog /home/runner/work/cwe-classifier/cwe-classifier/data/all.csv \
  --benchmark /tmp/nvd-dump.json --output /tmp/pilot.jsonl

# Offline reference comparison; NOT evidence about a learned model.
uv run python /home/runner/work/cwe-classifier/cwe-classifier/experiment.py run \
  --catalog /home/runner/work/cwe-classifier/cwe-classifier/data/all.csv \
  --benchmark /tmp/pilot.jsonl --output /tmp/cwe-results \
  --methods flat greedy beam --scorer lexical
```

### Plugging in a classifier

**Jev is TypeSafe's classifier/decision model**, not the lexical reference scorer.
See [TypeSafe's introduction](https://docs.typesafe.ai/introduction) and the
[official Python SDK](https://github.com/typesafe-ai/typesafe-sdk-python).
The notebook supports an optional adapter, selected with
`scorer: 'jev_scorer:create_scorer'` (CLI: `--scorer jev_scorer:create_scorer`).
Install its pinned SDK with `uv sync --extra notebook --extra jev`; launch Jupyter
with both extras enabled. Supply credentials through `TYPESAFE_API_KEY` in the
launching environment, never in notebook cells, configuration, or saved output.
Selecting this adapter sends input descriptions and candidate definitions to
TypeSafe; use only public or approved benchmark data.

The adapter is verified against SDK **0.7.4**. It asks a fixed independent
`Noul` yes/no question per CWE and uses the returned likelihood, rather than
comparing `Choice` probabilities normalized over different candidate sets.
It batches 32 questions per request, disables SDK retries, and rejects changes
in the response's model identifier within a run. Independent questions avoid
candidate-set normalization but do not establish calibration: validate score
comparability and thresholds on development data.
Broad ancestor definitions may receive higher likelihoods than more specific
children and cause early stopping. Inspect this bias before interpreting Jev
traversal results; the adapter is an experimental integration, not evidence
that the stopping rule is suitable for its scores.

Set `TYPESAFE_DEFAULT_MODEL` in the launching environment to an immutable,
account-supported model identifier for a reproducible run. Without it, the SDK
default/alias is used and is **not** a guaranteed version pin. The notebook saves
requested/resolved model metadata and per-example `model_requests`; scorer
`calls` still counts adapter invocations, not HTTP requests. Token totals come
from response usage where available; monetary cost remains unknown because the
verified SDK response does not provide it. No live Jev results are bundled.

`--scorer module:factory` loads a trusted local Python factory, called with the
eligible catalog mapping. Its object must expose `score(text, labels)`, returning
exactly those label IDs mapped to finite numeric scores (higher is better).
Scores must be comparable across candidate sets, including parents and children;
candidate-relative softmax probabilities do not satisfy this contract. A fixed
label classifier can return a subset of its full-label scores. A candidate scorer
can rank descriptions directly. Unsupported model labels must be resolved before
using the full-catalog comparison.

Adapters may expose `last_usage` after each score call, with `input_tokens`,
`output_tokens`, and `cost` (USD); unknown fields remain null. Calls count scorer
invocations, not an adapter's internal model batches. Report that distinction
when comparing batching strategies. The built-in `lexical` scorer is a
deterministic token-overlap reference only, not a trained classifier.

### Naive one-shot baseline

Export prompts containing the complete label-name list and sanitized input:

```bash
uv run python /home/runner/work/cwe-classifier/cwe-classifier/experiment.py export-prompts \
  --catalog /home/runner/work/cwe-classifier/cwe-classifier/data/all.csv \
  --benchmark /tmp/pilot.jsonl --output /tmp/prompts.jsonl
```

Use background agents or your approved model runner to read these prompts and
write real prediction files, without retrieval, traversal, examples, or retries.
Do not script Copilot CLI calls. Each JSONL output record must retain `id`,
`text_hash`, and `catalog_hash`, and include `model`, `calls: 1`,
`truncated_labels: []`, `predictions` (zero or one eligible CWE),
`latency_seconds`, and optionally `input_tokens`, `output_tokens`, and `cost`.
Hashes guard against accidental input/catalog mismatches; they are not proof
of how an external model was invoked. Save the model revision and generation
settings alongside its outputs.

`--max-prompt-chars` optionally enforces a character budget during export.
Export fails rather than silently truncating labels; verify the full prompt
also fits your model's token budget. A truncated-label run is not a matched
full-catalog comparison. No LLM requests or credentials are handled by this tool.

In the notebook, add `one-shot` to `methods` and set `one_shot_predictions` to
the real output file. Through the CLI, run all methods by adding
`--one-shot-predictions /tmp/one-shot.jsonl` to the
`run` command and omitting `--methods`. For a learned classifier, replace
`--scorer lexical` with your adapter. Tune thresholds, margin, beam width, and
model settings on development data only; freeze them before test evaluation.

### Results and validation

Each method produces per-example JSONL predictions with gold labels, traversal
paths, abstentions, latency, scoring calls, candidate counts, and available
token/cost telemetry. `summary.json` records configuration, input/catalog hashes,
exclusion audit, installed package versions, lockfile hash, scorer metadata,
accuracy, macro-F1, top-k recall, hierarchy distance, and paired
bootstrap accuracy-difference intervals (`--seed`, `--bootstrap-samples`).
Inspect paths for early routing mistakes and report results by gold label and
specificity as well as aggregate scores.

Top-1 accuracy accepts any annotated gold label. Interpret macro-F1 using the
acceptable-target top-1 resolution convention recorded by the evaluator; it is
not standard multilabel macro-F1 and is not interchangeable with
single-label accuracy. One-shot supplies top-1 only, so do not compare its recall
directly with another method's top-5 recall. Per-example latency excludes setup
and index generation. Unknown usage is never presented as zero-cost execution.

Run the standard-library tests from the checkout:

```bash
cd /home/runner/work/cwe-classifier/cwe-classifier
uv run --extra notebook --extra jev python -m unittest discover -v
```

Synthetic smoke tests validate mechanics only. A claim that traversal improves
classification requires a real held-out benchmark, an identified classifier,
and genuine one-shot predictions; the repository does not ship such results.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add your license information here]

## Troubleshooting

### Common Issues

1. **"No results found" or collection errors**: Make sure you've generated the index first using the `generate-index` command.

2. **File not found errors**: Verify the path to your CSV file is correct and the file follows the expected format.

3. **ChromaDB errors**: Delete the `chroma/` directory and regenerate the index if you encounter database corruption issues.

### Getting Help

If you encounter issues:
1. Check that your CSV file has the required columns
2. Ensure ChromaDB is installed with `uv sync` and run commands with `uv run`
3. Verify Python version compatibility (**3.13+**)

## Acknowledgments

- [MITRE Corporation](https://cwe.mitre.org/) for maintaining the CWE database
- [ChromaDB](https://www.trychroma.com/) for the vector database implementation