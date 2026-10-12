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

### Multi-source benchmark preparation

The notebook also builds a grouped benchmark from **pinned local snapshots**:
NVD JSON, [CVE List V5](https://github.com/CVEProject/cvelistV5) JSON files,
[GitHub-reviewed advisories](https://github.com/github/advisory-database), vendor
JSONL, completed expert-adjudicated JSONL, and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
membership. Download source dumps/archives once, extract them locally, and record
the source revision/date and checksum. The importer performs no live requests or
archive extraction. KEV annotates existing groups; it is not an independent
benchmark or proof that a CWE annotation is correct.

Supply a JSON manifest with `sources`, each containing `kind` (`nvd`, `cve`,
`ghsa`, `vendor`, `adjudicated`, or `kev`), `path`, `revision`, and `sha256`.
Paths may be absolute or relative to the manifest. For a file, the checksum is
its SHA-256; for a directory of JSON records, use
`dataset_sources.snapshot_sha256` to compute the documented deterministic digest.
Checksum mismatches fail before evaluation. GitHub records must be reviewed and
not withdrawn; CVE records must be published. The report records the manifest
hash, source revisions/checksums, input counts, and exclusions.

```bash
uv run python "$REPO/experiment.py" build-benchmark \
  --catalog "$REPO/data/all.csv" \
  --dataset-manifest /tmp/cwe-snapshots.json --output /tmp/cwe-dataset \
  --seed 0 --dev-fraction 0.2 --sample-size 200 --max-examples-per-split 300
```

In the notebook, set `demo=False` and `dataset_manifest` to the same manifest.
`command='build-benchmark'` writes both splits to `output` without invoking models.
For `run`, `dataset_output` receives preparation artifacts while `output` receives
predictions. Preparation writes `benchmark.jsonl`, `diagnostics.jsonl`,
`review_queue.jsonl`, a blinded `expert_review_sample.jsonl` (default at most 30
selected natural groups, adjustable with `--review-sample-size`), and
`dataset-report.json`. Reuse the pinned manifest/options
for dev and test. Do not confuse a synthetic fixture with a sourced benchmark:
no real corpus or completed human review is bundled.

Aliases (CVE/GHSA/vendor IDs) and conservative near-duplicate descriptions are
grouped **before splitting or sampling**. Each group contributes one deterministic
description, not one example per source. Catalog/training overlap is checked
across every alias. Conflicting source labels are quarantined rather than silently
unioned; completed expert labels can resolve conflicts. Token-based near-duplicate
matching is heuristic, not guaranteed semantic deduplication; inspect the audit
and review queue. Explicit CWE identifiers are removed from input text.

For generalization, use `--test-after YYYY-MM-DD`, `--holdout-ecosystems`,
`--holdout-vendors`, or `--holdout-sources`; their union assigns held-out groups to
test and the remainder to dev. Missing dates are quarantined for time holdouts.
Publication dates are grouped conservatively; source/domain metadata can be
incomplete. Do not infer unseen vendor coverage from an empty vendor field.
Without holdouts, seeded identity hashing assigns dev/test.

`--sample-size` defaults to **200** uniform natural-distribution groups per split.
`--max-examples-per-split` defaults to **300**, bounding the union of natural and
scored diagnostic groups; diagnostic selection uses only the remaining budget.
A separate `--balanced-per-label` subset diagnoses rare classes;
it does not replace or reweight the headline sample. The notebook reports natural
accuracy/paired intervals separately from balanced, KEV, rare, and expert slices.
Rarity uses dev-label counts (`--rare-max-count`), not test performance.
Ambiguous/no-gold/insufficient-information cases remain counted and exported for
review, not treated as incorrect CWE predictions or invented gold labels.

Evaluation is bounded again by `--max-eval-examples` (default 300) for all inputs.
Non-lexical classifier comparisons and live one-shot inference also start with `--max-live-examples 50`,
an initial cost-checking pilot, not a precise population estimate. Selection is
seeded and prioritizes the uniform natural sample; population/selected label
counts are recorded so lost coverage is visible. Raise the limit deliberately
after measuring usage and uncertainty; use the same sampling settings for
one-shot exports and all compared methods. A full-catalog work upper bound is
checked against `--max-candidate-evaluations` (default 1,000,000) **before** creating
models. This caps work, not dollars: unknown token lengths/pricing cannot promise
a monetary budget. Report confidence intervals and slice counts; small or absent
rare-class samples do not support strong class-specific conclusions.

Vendor/adjudication JSONL uses `id`, `aliases`, `text`, `labels`, `published`,
`ecosystems`, and `vendors`, with optional `ambiguous` and
`insufficient_information` flags. Human gold additionally requires
`expert_reviewed=true` and `adjudication_status='complete'`. Review queue entries
are unresolved work, **not** completed adjudications. Reviewers should independently
assess the description, record acceptable labels/status and evidence, and supply
their completed records as a pinned `adjudicated` source. Do not use a test review
to tune model settings.

SARD/Juliet is a future **code-to-CWE** benchmark, not an input to this
description-to-CWE evaluation. CWE catalog text and Observed Examples remain
contaminated smoke diagnostics only.

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
the configured service: use only public or approved data. The adapter is verified against pinned
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

The [pinned SDK](https://github.com/typesafe-ai/typesafe-sdk-python/blob/v0.7.4/src/typesafe_sdk/_core/client/sync/client.py)
supports `TYPESAFE_BASE_URL` for a **Jev-compatible API root**.
Alternatively, set notebook `jev_base_url` / CLI `--jev-base-url`; `jev_model` /
`--jev-model` overrides `TYPESAFE_DEFAULT_MODEL`. Explicit options take precedence.
`JevScorer` also accepts keyword arguments `base_url`, `model`, and `timeout`.
The root must implement the SDK's `/v1/systemone` route, independent Noul answers,
model identity, and usage schema; an OpenAI-compatible chat endpoint alone is
**not** Jev-compatible. Endpoint metadata is saved without API keys. Remote
endpoints require HTTPS; unencrypted HTTP is permitted only on loopback.
URLs must not contain credentials, query parameters, or fragments.

One-shot supports either imported predictions or an **explicitly enabled helper**.
Include `one-shot` in `methods`, disable `demo`, and set `one_shot_provider` to
`openai` or `copilot`, plus `one_shot_model` to an available model identifier.
No new dependencies are needed for the helpers. Supply only approved data to
the selected provider. All full-label prompts and example limits are checked
before inference; labels are never silently truncated. Check the model's token
budget too.

For an **OpenAI-compatible Chat Completions server**, set `one_shot_endpoint` to
the full URL, including `/chat/completions`, and optionally `one_shot_api_key_env`
to the **name** of an environment variable holding its API key. Do not put the
key itself in configuration. `one_shot_timeout` defaults to 120 seconds. The
helper issues one nonstreaming POST per example, without tools, retries, or
redirects. HTTPS is required except for loopback HTTP; URL credentials, query
parameters, and fragments are rejected.

```bash
uv run python "$REPO/experiment.py" run \
  --catalog "$REPO/data/all.csv" --benchmark /tmp/cwe-benchmark.jsonl \
  --output /tmp/cwe-results --methods one-shot \
  --one-shot-provider openai --one-shot-model your-model-id \
  --one-shot-endpoint https://api.openai.com/v1/chat/completions \
  --one-shot-api-key-env OPENAI_API_KEY
```

For **Copilot CLI**, install/authenticate the official `copilot` executable and
choose `one_shot_provider='copilot'` / `--one-shot-provider copilot` instead.
Do not supply an HTTP endpoint or API-key variable for that provider. Each input
uses a fresh temporary working directory, no available tools, no repository
custom instructions, no built-in MCP servers, and no session resumption, fleet,
or autopilot. CLI failures/timeouts are not retried. Copilot's runtime still
adds its own context and may make internal calls; this is **one prompt invocation**,
not a verified single inference request. User-level CLI configuration can still
affect runs; pin the CLI version and control that configuration for reproducibility.

The removable transport boundary is `create_one_shot_helper(config)`: it returns
a callable from prompt to a completion mapping. `run_one_shot` handles the same
full-label prompts, prediction validation, fingerprints, and artifacts for either
transport. Copilot CLI is **not an OpenAI-compatible HTTP server**; the wrapper
does not expose its subscription credentials or use undocumented inference APIs.
The HTTP helper targets the documented
[Chat Completions contract](https://github.com/openai/openai-python#usage);
CLI controls follow the official
[programmatic reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference).

HTTP records count `http_requests`; CLI records count `prompt_invocations`.
Underlying `model_requests` and `calls` remain unknown for these helpers; HTTP
tokens are saved when reported, whereas CLI tokens and resolved model identity
remain unknown. Missing monetary cost remains null, not zero. Per-example
predictions are saved to `one-shot-predictions.jsonl` and normal evaluation outputs.

For an external runner, `export-prompts` and `one_shot_predictions` /
`--one-shot-predictions` remain supported. Preserve `id`, `text_hash`,
`catalog_hash`, `truncated_labels: []`, zero or one eligible prediction, latency,
and model identity. Legacy records declaring `calls: 1` still import; the new
helper format explicitly distinguishes invocations from unknown inference calls.
Choose either imported predictions or a live provider, not both.

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