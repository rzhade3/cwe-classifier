# CWE Classifier

A semantic search tool for Common Weakness Enumeration (CWE) database using ChromaDB vector embeddings. This tool allows you to efficiently search and classify software vulnerabilities based on CWE descriptions.

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

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd cwe-classifier
```

2. Install uv (if you haven't already):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

3. Install dependencies:
```bash
uv sync
```

## Data Format

The tool expects CWE data in CSV format with the following columns:
- `CWE-ID`: The CWE identifier
- `Name`: The name of the weakness
- `Description`: Short description of the weakness
- `Extended Description`: Detailed description of the weakness

You can download the official CWE database in CSV format from [MITRE's CWE downloads page](https://cwe.mitre.org/data/downloads.html).

## Usage

### Generate Index

First, build the search index from your CWE CSV data:

```bash
python search_cwes.py generate-index path/to/your/cwe-data.csv
```

Example:
```bash
python search_cwes.py generate-index data/all.csv
```

### Search CWEs

Search for relevant CWE entries using natural language queries:

```bash
python search_cwes.py search "your search query"
```

#### Search Options

- `--top-k`: Number of results to return (default: 5)

#### Examples

```bash
# Basic search
python search_cwes.py search "buffer overflow"

# Search with more results
python search_cwes.py search "sql injection" --top-k 10

# Multi-word queries
python search_cwes.py search "cross site scripting vulnerabilities"
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

`experiment.py` compares the existing embedding approach with flat candidate
classification, greedy traversal, beam traversal, and a naive single-call,
zero-shot LLM baseline. The existing index and CLI are unchanged. Chroma experiments
build a separate ephemeral index over the same eligible catalog as the other
methods; initial embedding model downloads may require network access.

The hierarchy uses `ChildOf` edges from a single view (default `1000`), preserves
multiple parents, rejects cycles, and includes disconnected catalog entries as
roots. Deprecated/obsolete entries are excluded. Traversal scores roots, then
children, keeping the best `--beam-width` paths. It stops at a parent unless a
child exceeds its score by `--margin` and meets `--threshold`. Scores are cached
per example, and repeated terminal labels are deduplicated. Beam search mitigates,
but does not eliminate, early routing errors. Graph distance is shortest
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
texts are deduplicated, and development/test overlap is excluded. Examples without
eligible gold labels and ambiguous examples are excluded with audit counts.
Known training overlap can be excluded using `--training-ids`, a JSON array of
example IDs. This cannot establish absence of training contamination: record the
model's training provenance and report unknown overlap honestly.

Commands below assume this checkout's absolute path; replace benchmark and
output paths with your local files.

```bash
python /home/runner/work/cwe-classifier/cwe-classifier/experiment.py prepare \
  --catalog /home/runner/work/cwe-classifier/cwe-classifier/data/all.csv \
  --benchmark /tmp/nvd-dump.json --output /tmp/pilot.jsonl

# Offline reference comparison; NOT evidence about a learned model.
python /home/runner/work/cwe-classifier/cwe-classifier/experiment.py run \
  --catalog /home/runner/work/cwe-classifier/cwe-classifier/data/all.csv \
  --benchmark /tmp/pilot.jsonl --output /tmp/cwe-results \
  --methods flat greedy beam --scorer lexical
```

### Plugging in a classifier

“jev” has not been identified; no model or supported label set is assumed.
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
python /home/runner/work/cwe-classifier/cwe-classifier/experiment.py export-prompts \
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

Run all methods by adding `--one-shot-predictions /tmp/one-shot.jsonl` to the
`run` command and omitting `--methods`. For a learned classifier, replace
`--scorer lexical` with your adapter. Tune thresholds, margin, beam width, and
model settings on development data only; freeze them before test evaluation.

### Results and validation

Each method produces per-example JSONL predictions with gold labels, traversal
paths, abstentions, latency, scoring calls, candidate counts, and available
token/cost telemetry. `summary.json` records configuration, input/catalog hashes,
exclusion audit, accuracy, macro-F1, top-k recall, hierarchy distance, and paired
bootstrap accuracy-difference intervals (`--seed`, `--bootstrap-samples`).
Inspect paths for early routing mistakes and report results by gold label and
specificity as well as aggregate scores.

Top-1 accuracy accepts any annotated gold label. Interpret macro-F1 using the
multi-label convention recorded by the evaluator; it is not interchangeable with
single-label accuracy. One-shot supplies top-1 only, so do not compare its recall
directly with another method's top-5 recall. Per-example latency excludes setup
and index generation. Unknown usage is never presented as zero-cost execution.

Run the standard-library tests from the checkout:

```bash
cd /home/runner/work/cwe-classifier/cwe-classifier
python -m unittest discover -v
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
2. Ensure ChromaDB is properly installed with `uv sync` or `uv pip install chromadb`
3. Verify Python version compatibility (3.8+)

## Acknowledgments

- [MITRE Corporation](https://cwe.mitre.org/) for maintaining the CWE database
- [ChromaDB](https://www.trychroma.com/) for the vector database implementation