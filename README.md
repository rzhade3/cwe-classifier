# CWE Classifier

Suggest [CWE](https://cwe.mitre.org/) classifications for a vulnerability
description. `main.py` walks MITRE's CWE hierarchy (research view 1000) with
beam search, asking Jev (via `typesafe-sdk`) at each step which refinement
fits best, and prints the most likely CWEs with their path probabilities.

Treat the output as **suggestions for a human reviewer**, not final labels: on
held-out GitHub advisories the first suggestion was right 45% of the time and
the right CWE was in the top 5 77% of the time (see
[Results](#results-and-recommendations)).

## Installation

Requires Python **3.13+** and [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/rzhade3/cwe-classifier.git
cd cwe-classifier
uv sync
```

Put your Jev API key in a gitignored `.env` file at the repository root (or
export it in your shell):

```bash
TYPESAFE_API_KEY=...
```

Optional: `TYPESAFE_BASE_URL` for a Jev-compatible API root, and
`TYPESAFE_DEFAULT_MODEL` to override the model. The CLI defaults to
`jev-1.13.0`, the version the accuracy figures below were measured on; other
versions are untested.

## Usage

```bash
# Text as arguments
uv run python main.py "The login form concatenates the username into a SQL query."

# From a file or stdin
uv run python main.py --file advisory.md
cat advisory.md | uv run python main.py --json

# More suggestions / a different model
uv run python main.py --top-k 10 --model jev-1.13.0 "heap overflow in PNG parser"
```

Sample output:

```
Suggested CWEs (jev-1.13.0, 8 Jev calls, 1.4s):

 1. CWE-89     99%  Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    CWE-707 > CWE-74 > CWE-943 > CWE-89
 2. CWE-564     1%  SQL Injection: Hibernate
    CWE-707 > CWE-74 > CWE-943 > CWE-89 > CWE-564
 ...
```

`--json` prints `{"model": ..., "suggestions": [{"cwe", "name", "score",
"path"}, ...]}` for scripting. Scores are path probabilities: low top scores,
or several close ones, mean the model is unsure and a reviewer should look
closely. Each run makes one Jev request per beam step (typically under ten).

**Privacy:** the description you pass is sent to the configured Jev service.
Do not submit text you are not allowed to share with it.

## Results and recommendations

Measured with `experiment/experiments.ipynb` on 500 held-out GitHub-reviewed
advisories (`test` split), `jev-1.13.0`:

| System | Method | Top-1 accuracy (95% CI) | Gold in top 5 |
|---|---|---|---|
| `jev-parent-rich` (used by `main.py`) | beam (width 3) | **44.6%** (40.3–49.0) | **77.2%** |
| `jev-parent-rich` | greedy | 42.4% | – |
| `jev-parent` (plain definitions) | greedy | 21.0% | – |
| `vector` (Chroma, MiniLM embeddings) | flat | 18.4% | 38.2% |
| `lexical` (token overlap) | flat | 12.4% | – |

What we learned:

- **Option text matters most.** Listing each option's common descendants
  ("Includes: SQL Injection; OS Command Injection; ...") and alternate names
  doubled accuracy (21% → 42%). Abstract top-level CWEs such as CWE-707 are
  otherwise hard to recognise; first-step accuracy rose from 50% to 79%.
- **Choosing beats yes/no scoring.** Asking Jev to pick one option per step
  (including "the current CWE" as a way to stop) lets beam search rank paths by
  the product of choice probabilities with no cross-call calibration.
- **Embedding search is a weak baseline** for this task (18% top-1).

Known weaknesses:

- **Going past the right answer** is the most common error (100 of 288
  misses): e.g. XSS refined to *Basic XSS*. When the top suggestion looks too
  specific, consider its parent (shown in the path).
- **Memory-safety bugs** are often routed to *Incorrect Calculation* (CWE-682)
  rather than buffer-overflow CWEs.
- **Rare CWEs** (uncommon in GitHub advisories) are right only about 15% of
  the time.

Caveats: one model version, 500 examples, open-source package advisories only,
and curator labels that were not independently adjudicated. Beam width and the
rich option format were chosen after looking at `test` results, so the figures
may be slightly optimistic. Suggested next steps: tune stopping on the `dev`
split, evaluate 2,000 examples, test on your own (non-GHSA) reports, and
measure agreement with human reviewers.

## Data

`data/all.csv` is MITRE's CWE catalog in CSV form (download updates from
[MITRE's CWE downloads page](https://cwe.mitre.org/data/downloads.html)). The
CLI uses `CWE-ID`, `Name`, `Description`, `Status`, `Related Weaknesses`
(`ChildOf` relationships with view IDs) and `Alternate Terms`. Experiments also
use `Extended Description`, `Weakness Abstraction` and `Observed Examples`.

`data/cwe_frequencies.json` counts how often each CWE labels the benchmark's
`dev` split; it ranks the descendants listed in each option's "Includes" text.
`python -m experiment.fetch_sources` regenerates it. The `test` split is never
used.

## Classification experiments

The notebook compares flat, greedy graph traversal, and beam search on a
held-out benchmark built solely from GitHub-reviewed advisories in the
[GitHub Advisory Database](https://github.com/github/advisory-database).
Prepare a snapshot, study it, then run the experiment:

```bash
uv sync --extra notebook
uv run --extra notebook python -m experiment.fetch_sources
uv run --extra notebook jupyter lab experiment/dataset_analysis.ipynb
uv run --extra notebook jupyter lab experiment/experiments.ipynb
```

Choose the project Python kernel and **Restart Kernel and Run All**. The fetch
command shallow-clones only `advisories/github-reviewed`, records the commit and
a SHA-256 of the snapshot, and writes `benchmark.jsonl` plus
`dataset-report.json` under `experiment/data/prepared/`, and refreshes
`data/cwe_frequencies.json`. The clone takes time
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
| `vector` | scorer | Cosine similarity against the committed Chroma `cwe_index` (rebuild with `uv run --extra notebook python -m experiment.vector_scorer`) |
| `jev-parent` | selector | Jev picks among offered CWEs; traversal also offers the current CWE itself as a way to stop |
| `jev-parent-rich` | selector | Same, plus each option's alternate names and up to 12 most common descendants (ranked by `dev`-split label counts) |

`experiment.jev_selector:create_selector` (an abstract `STOP` option instead of
the current CWE) remains available but is not run by default.

Selectors are asked one Choice question per step, and beam ranks paths by the
product of choice probabilities, so no cross-question calibration is needed.
Jev accepts at most 255 options per question, so flat (all catalog CWEs) is
skipped for it and listed under `skipped` in `metrics.json`.

The Jev models need `TYPESAFE_API_KEY` in the shell or in `experiment/.env`.
Optionally set `TYPESAFE_BASE_URL` to a Jev-compatible API root and
`TYPESAFE_DEFAULT_MODEL` to an immutable model name. They make several requests
per example; the notebook's cost table reports calls, tokens, and latency.
Credentials are read from the environment and never written to outputs.
(`main.py` also reads the root `.env`.)
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

- **`error: set TYPESAFE_API_KEY`**: add the key to `.env` or export it.
- **`error: Jev request failed`**: check the key, network access, and
  `TYPESAFE_BASE_URL`; the message includes the underlying error.
- **Vector baseline errors** (`cwe_index` missing or stale): rebuild the Chroma
  index with `uv run --extra notebook python -m experiment.vector_scorer`.

## Acknowledgments

- [MITRE Corporation](https://cwe.mitre.org/) for maintaining the CWE database
- [GitHub Advisory Database](https://github.com/github/advisory-database) for the benchmark labels
- [ChromaDB](https://www.trychroma.com/) for the vector baseline