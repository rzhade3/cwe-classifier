# CWE Classifier

Suggest CWE labels from vulnerability descriptions with the CWE hierarchy,
OpenAI Decisions, and reproducible classification experiments. Suggestions need
human review; routing scores are not calibrated correctness probabilities.
This revision does not establish OpenAI accuracy on a live benchmark.

## Install and classify

Python 3.13+ and [uv](https://docs.astral.sh/uv/) are required.

```bash
uv sync --locked
export OPENAI_API_KEY='your-key'
uv run python main.py "User input is concatenated into a SQL query."
uv run python main.py --file advisory.md --json
cat advisory.md | uv run python main.py --top-k 5
```

The default backend calls `client.decisions.create` with `gpt-6-luna`, a named
choice question, and CWE definitions. A child question also offers its current
parent as a stopping option. Requests use a 30-second timeout and zero SDK
retries. `--model` selects an explicitly supplied provider model identifier.
The API has a 255-choice limit, so full-catalog flat classification is skipped;
hierarchy traversal fits smaller choice sets. Forced single-option edges are
local and make no request.

The JSON response contains the returned model and suggestions with `cwe`,
`name`, `score`, and `path`. Beam width is three; `--top-k` limits returned
suggestions. Scores multiply conditional routing choices and retain the best
path to a DAG node; they are ranking heuristics, not posterior label confidence.

Credentials can also be read from gitignored `.env` files at the repository
root or under `experiment/`. The CLI never overwrites existing environment
variables. The notebook uses environment credentials only. Input descriptions
are sent to the selected provider; saved experiment artifacts include source
text and decision traces.

Legacy Jev remains available without being required by OpenAI:

```bash
uv sync --locked --extra jev
export TYPESAFE_API_KEY='your-key'
uv run --extra jev python main.py --provider jev --model jev-1.13.0 "SQL injection"
```

Jev retains its historical rich-parent factory. Do not assume historical Jev
results transfer to OpenAI or that provider defaults are immutable snapshots.

## Reproduce an experiment

```bash
uv sync --locked --extra notebook
uv run --extra notebook python -m experiment.fetch_sources --revision FULL_40_CHARACTER_COMMIT_SHA
uv run --extra notebook jupyter lab
```

Start Jupyter from the repository root and select the project Python kernel.
The preparation command clones GitHub-reviewed advisories, records the source
commit and snapshot hash, and writes a prepared benchmark and dataset report.
Omit `--revision` only when deliberately acquiring a new snapshot; its resolved
commit is still recorded. Existing output directories are refused. The CWE
catalog (`data/all.csv`) is committed and hashed; source downloads are not
implicitly performed by either analysis notebook.

Read the notebooks in this order:

| Notebook | Purpose |
|---|---|
| `experiment/dataset_analysis.ipynb` | Exclusions, source provenance, duplicate handling, label support and split balance |
| `experiment/experiments.ipynb` | Fixed comparison, metrics, matched uncertainty, cost, routing failures and descriptive calibration |
| `experiment/hypotheses.ipynb` | Unpromoted alternatives: roots, parent vs STOP, option text, path scores and label policy |

The main notebook defaults to a 100-example **dev** run with only the offline
lexical baseline. Set `RUN_REMOTE = True` to add OpenAI. It explicitly configures
model, stop style and timeout through `model_options`; Jev and vector baselines
are opt-in. Study dev failures, freeze choices and the primary comparison, then
use a fresh holdout once. The old test split influenced historical prompt and
beam choices; its previous results are exploratory, not validation.

The benchmark uses GitHub curators' CWE labels, restricted to active catalog
weaknesses. Preparation excludes withdrawn/unreviewed entries, explicit CWE
mentions, catalog-cited CVEs, alias/text duplicates and conflicting duplicate
labels. Splitting is deterministic and stratified by exact label set. These
controls do not eliminate pretraining contamination, near duplicates or
package-family correlation. The dataset report records removed labels and
exclusions; labels are not silently mapped to narrower leaf CWEs.

## Results and recovery

`metrics.json` records the full effective settings, catalog/benchmark hashes,
selected IDs, source revision and hashes (including dirty source content),
installed packages and provider metadata. If available, the matching dataset
report is embedded and checked against the input hashes. The runner records
per-example predictions, paths, routing scores, questions, usage and latency.
Monetary cost stays unknown rather than applying unverified prices.

Content-addressed checkpoints include data, catalog, implementation, environment,
prompt metadata and model options. Each successful example is appended and
flushed before the next starts. Interrupted runs resume without repeating
completed examples; a torn final append is recovered, while complete-line
corruption is rejected. Shrinking the reported sample does not truncate cached
larger runs. Changing prediction inputs creates a new checkpoint. Reports are
published atomically per file; `metrics.json` is the final completion marker.
A lock serializes writers in the same directory. After a process crash, verify
that its PID is gone before manually removing `.run.lock`. Archive complete run
folders before changing configurations; a report and several prediction files
are not a transactional database snapshot for concurrent readers.

Refusals, malformed probabilities and model-version drift fail the run rather
than dropping hard examples from accuracy. Resume only after resolving the
failure; checkpoints retain completed predictions, not partially completed
advisories. Model aliases may drift without changing their returned identifier;
use distinct run names and a new holdout when upgrading them. External custom
factories and mutable embedding functions require their own versioned metadata.

Metric schema 2 distinguishes **hit@k** (any gold label retrieved) from
**recall@k** (mean fraction of gold labels retrieved). It reports top-1 accuracy,
Wilson intervals, macro top-1 F1, coverage and selective accuracy. The main
notebook adds hierarchical similarity and paired bootstrap differences. Existing
schema-1 result folders are not reused. A Wilson interval does not test the
difference between two paired systems.

## Optional vector baseline

The generated Chroma SQLite database is no longer version-controlled. Rebuild
into a new directory after catalog or embedding changes:

```bash
uv run --extra notebook python -m experiment.vector_scorer
```

Index creation refuses an existing collection; remove or archive it deliberately
before rebuilding. Index metadata identifies the embedding function; loading
checks catalog document consistency and records a fingerprint of vector values.
The default Chroma embedding function may download model weights on first use.
It is a baseline, not a substitute for validating retrieval recall or pinning
external model weights.

## Validation

```bash
uv sync --locked --extra notebook --extra jev
uv run --extra notebook --extra jev python -m unittest discover -v
```

Tests cover graph traversal, benchmark preparation and metrics, both installed
SDK contracts with mocked HTTP transports, provider failures, cache invalidation,
interruption recovery, CLI behavior and ordered notebook execution. They do not
send live API requests. In restricted environments that cannot create Jupyter
kernel sockets, use `CWE_NOTEBOOK_TEST_MODE=inprocess` for ordered execution of
every plain Python cell; CI runs the notebooks in fresh kernels. No live OpenAI
key was available during this refactor, so remote quality remains unmeasured.

See [AUDIT.md](AUDIT.md) for findings, priority and acceptance criteria. OpenAI
wire details follow the official [Decisions guide](https://developers.openai.com/api/docs/guides/decisions)
and [API reference](https://developers.openai.com/api/reference/resources/decisions/methods/create),
checked on 2026-10-23.
