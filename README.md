# CWE Classifier

A semantic search tool for the Common Weakness Enumeration (CWE) database,
with a reproducible notebook for comparing flat classification and graph traversal.

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
- **Experiment Notebook**: Compare flat classification with greedy and beam
  traversal on a held-out GitHub Advisory Database benchmark

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

The notebook compares flat, greedy graph traversal, and beam search on a
held-out benchmark built solely from GitHub-reviewed advisories in the
[GitHub Advisory Database](https://github.com/github/advisory-database).
Prepare a snapshot, study it, then run the experiment:

```bash
uv sync --extra notebook
uv run python -m experiment.fetch_sources
uv run --extra notebook jupyter lab "$REPO/experiment/dataset_analysis.ipynb"
uv run --extra notebook jupyter lab "$REPO/experiment/experiments.ipynb"
```

Choose the project Python kernel and **Restart Kernel and Run All**. The fetch
command shallow-clones only `advisories/github-reviewed`, records the commit and
a SHA-256 of the snapshot, and writes `benchmark.jsonl` plus
`dataset-report.json` under `experiment/data/prepared/`. The clone takes time
and disk space.

Gold labels are the `cwe_ids` GitHub curators assign to reviewed advisories.
Labels absent from the CWE catalog (for example, categories or deprecated
entries) are dropped, and advisories left with no label are excluded.
Advisories cited in the catalog's Observed Examples are excluded to avoid
leakage. Advisories sharing an alias or identical text are merged, and merged
groups with disagreeing labels are excluded. Explicit CWE mentions are removed
from the text. The `dev`/`test` split is seeded and stratified by exact label
set; change it with `--seed` and `--dev-fraction`.

`dataset_analysis.ipynb` covers the advisory funnel, unsupported labels, CWE
long tail, label abstraction levels, ecosystems, publication years, and split
balance. It keeps preprocessing analysis out of the experiment notebook.

The experiment runs every model under every method (flat: consider the whole
catalog at once; greedy: walk the `ChildOf` hierarchy keeping one route; beam:
keep `beam_width` routes) on the same examples:

| Model | Kind | How it ranks CWEs |
|---|---|---|
| `lexical` | scorer | Token overlap (reference baseline) |
| `vector` | scorer | Cosine similarity against the committed Chroma `cwe_index` |
| `jev` | selector | Jev picks among offered CWEs; traversal offers an explicit `STOP` |
| `jev-parent` | selector | Same, but traversal offers the current CWE itself instead of `STOP` |

Selectors are asked one Choice question per step, and beam ranks paths by the
product of choice probabilities, so no cross-question calibration is needed.
Jev accepts at most 255 options per question, so flat (all catalog CWEs) is
skipped for it and listed under `skipped` in `metrics.json`.

The Jev models need `TYPESAFE_API_KEY` in the shell or in `experiment/.env`.
Optionally set `TYPESAFE_BASE_URL` to a Jev-compatible API root and
`TYPESAFE_DEFAULT_MODEL` to an immutable model name. They make several requests
per example; the notebook's cost table reports calls, tokens, and latency.
Credentials are read from the environment and never written to outputs.
Vulnerability text and CWE definitions are sent to the configured service;
confirm that this is appropriate for your data. The notebook shows top-1
accuracy with 95% intervals, hierarchical and macro F1, per-CWE results, cost,
where in the hierarchy each system fails (wrong root, wrong branch, stopped too
early, went past gold), and, from Jev's saved per-step probabilities, step
accuracy, calibration, and accuracy vs. coverage.

Custom models are `module:factory` specs whose factory takes the catalog labels
and returns either a scorer (`score(text, labels)`) or a selector
(`select(text, labels, current=None)` returning probabilities, including `STOP`
when `current` is set). Predictions (`<model>-<method>.jsonl`) and
`metrics.json` are written to `experiment/results/`.

The default run uses 500 seeded `test` examples. Examples come from one seeded
shuffle of the split, so a later, larger run (e.g. `max_examples=2000`) contains
the first 500; saved predictions are reused and only new examples are sent to
the models, provided the benchmark file and prediction settings are unchanged.
Pin `TYPESAFE_DEFAULT_MODEL` (e.g. `jev-1.13.0`) so new answers come from the same
model version; the run stops if it changed. The notebook reads
`experiment/.env` (gitignored) for these variables if they are not already set.

Run the standard-library tests from the repository root:

```bash
uv run --extra notebook python -m unittest discover -v
```

Curator labels are consistently sourced but not independently adjudicated,
and the benchmark covers only open-source package advisories. Treat metric
differences as exploratory beyond that scope.

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