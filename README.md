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

Run commands from the repository root using `uv run` so they use the project's
environment. Alternatively, activate its `.venv` before using bare `python`.
Set `REPO` to the absolute checkout path for the commands below:

```bash
REPO="$(pwd)"
```

## Data Format

The tool expects CWE data in CSV format with the following columns:
- `CWE-ID`: The CWE identifier
- `Name`: The name of the weakness
- `Description`: Short description of the weakness
- `Extended Description`: Detailed description of the weakness

Hierarchy experiments additionally require `Status` (for eligibility filtering),
`Related Weaknesses` (MITRE's structured `ChildOf` relationships with view IDs),
and `Weakness Abstraction` (for specificity-based stopping). Optional
`Observed Examples` supplies catalog CVE references for leakage exclusion.
The bundled CSV includes these columns.

You can download the official CWE database in CSV format from [MITRE's CWE downloads page](https://cwe.mitre.org/data/downloads.html).

## Usage

### Generate Index

First, build the search index from your CWE CSV data:

```bash
uv run python "$REPO/main.py" generate-index "$REPO/data/your-cwe-data.csv"
```

Example:
```bash
uv run python "$REPO/main.py" generate-index "$REPO/data/all.csv"
```

### Search CWEs

Search for relevant CWE entries using natural language queries:

```bash
uv run python "$REPO/main.py" search "your search query"
```

#### Search Options

- `--top-k`: Number of results to return (default: 5)

#### Examples

```bash
# Basic search
uv run python "$REPO/main.py" search "buffer overflow"

# Search with more results
uv run python "$REPO/main.py" search "sql injection" --top-k 10

# Multi-word queries
uv run python "$REPO/main.py" search "cross site scripting vulnerabilities"
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

[`experiments.ipynb`](experiments.ipynb) is the primary detailed user guide and
experiment protocol: configuration, benchmark preparation/audit, prompt export,
flat/greedy/beam/Chroma/one-shot comparisons, metrics, and routing-error inspection.
`experiment.py` provides a compatibility CLI that executes the notebook's code cells.

### Getting started and configuration

Install the locked notebook extra and open the notebook:

```bash
uv sync --extra notebook
uv run --extra notebook jupyter lab "$REPO/experiments.ipynb"
```

Choose the project Python kernel and **Restart Kernel and Run All**. The default
configuration runs synthetic examples offline with the lexical scorer: no model
API calls or embedding downloads. This demonstrates mechanics, not held-out
accuracy. The notebook detects the repository root automatically. Edit `config`
to set `demo` to false, benchmark/output paths, command (`prepare`,
`export-prompts`, or `run`), split, methods, scorer, and traversal options.
Enable Chroma, Jev, and one-shot explicitly.

Use independently annotated JSONL (`id`, `text`, `labels`, `split: dev|test`) or
a locally downloaded NVD JSON dump, not CWE catalog descriptions. NVD splits use
a stable seeded ID hash: `--dev-fraction` defaults to `0.2`; `--seed` controls
reproducibility. Tune on dev, then freeze settings before test evaluation.
Keep the original combined dev/test benchmark for overlap detection and evaluation,
rather than feeding back a filtered export or an isolated split. Sanitization,
deduplication, eligibility, ambiguity, and overlap exclusions are audited.
Catalog CVE references in `Observed Examples` are excluded by default;
`--include-observed-examples` opts out. `--training-ids` still excludes known
training IDs. These checks cannot establish absence of model training contamination.

### Traversal options

The graph uses one `ChildOf` view (default `1000`), preserves multiple parents,
rejects cycles, and includes disconnected entries as roots; deprecated/obsolete
entries are excluded. `--beam-width` controls retained paths. `--stop-policy` selects:

- `specificity` (default): early stopping is allowed only at Base/Variant nodes;
  broader nodes must descend.
- `improvement`: the previous parent-margin rule, requiring a child to exceed
  its parent by `--margin`.
- `leaf`: always descend to the best eligible children.

`--threshold` gates both roots and children. A non-stoppable parent with no
threshold-passing child abstains; an actual graph leaf can be terminal even if
its abstraction is broad. Scores are cached per example and terminal labels
deduplicated. Chroma uses a separate ephemeral index over the eligible catalog;
embedding downloads may need network access. Index-document enrichment remains
a future experiment; the search baseline and CLI are unchanged.

### Models and one-shot baseline

**Jev is TypeSafe's classifier/decision model**, not the lexical reference scorer.
See [TypeSafe's introduction](https://docs.typesafe.ai/introduction) and the
[official Python SDK](https://github.com/typesafe-ai/typesafe-sdk-python).
Select `scorer: 'jev_scorer:create_scorer'` (CLI:
`--scorer jev_scorer:create_scorer`) and install/launch with both extras:

```bash
uv sync --extra notebook --extra jev
uv run --extra notebook --extra jev jupyter lab "$REPO/experiments.ipynb"
```

Supply `TYPESAFE_API_KEY` through the launching environment, never notebook cells,
configuration, or outputs. Jev sends descriptions and candidate definitions to
TypeSafe: use only public or approved data. The adapter is verified against pinned
SDK **0.7.4**: independent `Noul` yes/no likelihoods, batches of 32 questions,
SDK retries disabled, and response model-identifier changes rejected within a run.
Validate cross-candidate score comparability, thresholds, and ancestor bias on dev;
independent questions do not establish calibration. Trusted custom
`--scorer module:factory` adapters must return finite, comparable scores from
`score(text, labels)`; candidate-relative softmax probabilities do not qualify.

Set `TYPESAFE_DEFAULT_MODEL` to an immutable, account-supported model identifier.
The SDK default/alias is **not** a guaranteed version pin. Requested/resolved model
metadata and `model_requests` are saved; scorer `calls` counts adapter invocations,
not HTTP requests. Tokens are recorded when available; Jev monetary cost is unknown.
The lexical scorer is only a deterministic reference; no live Jev results are bundled.

One-shot requires an **external model runner**: export complete-label prompts,
make one real zero-shot call per input without retrieval, traversal, examples, or
retries, then set `one_shot_predictions` and include `one-shot` in `methods`.
Preserve `id`, `text_hash`, and `catalog_hash`; record model revision/settings,
`calls: 1`, `truncated_labels: []`, zero or one eligible prediction, latency, and
available usage. Export fails rather than truncating labels; check the model's token
budget too. See the notebook for the full record contract and CLI equivalents.

### Results and validation

**Top-1 accuracy** (any acceptable gold label) is the headline metric, with paired
bootstrap accuracy-difference intervals (`--seed`, `--bootstrap-samples`).
Top-k recall is descriptive only: greedy returns at most one prediction and beam
returns a variable number. Report `prediction_count_histogram` and
`mean_prediction_count` alongside it. Graph distance is shortest undirected
top-1-to-gold distance in the selected view, with disconnected pairs reported.
Per-example artifacts include paths, abstentions, latency, calls, candidates, and
available token/cost usage; `summary.json` also records configuration, hashes,
exclusion audit, package versions, and model metadata. Unknown usage is not zero
cost; latency excludes setup/index generation.

Run the standard-library tests from the repository root:

```bash
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