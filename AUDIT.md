# Experiment audit and harness recommendations

Audit baseline: `d1f6cf8d97bad515ff1116798598c96ba74d5585`.
Scope: classifier/traversal, CLI, all experiment helpers, both existing notebooks,
data acquisition, dependencies and tests. This is a code/methodology audit;
no live model quality comparison was possible without a provider key.

## Findings addressed

| Priority | Finding and evidence at baseline | Change |
|---|---|---|
| P0 | `runner._previous_run` keyed reuse on benchmark/settings/spec, omitting catalog bytes, source, prompt artifacts, installed dependencies and requested model configuration | Content-addressed checkpoints include these inputs and selector metadata; record dirty source hashes and exact sampled IDs |
| P0 | `runner` wrote predictions after an entire system finished; smaller runs overwrote larger prediction files | Append/fsync per completed advisory, recover a torn final append, retain larger caches, atomic report publication and an exclusive output lock |
| P0 | Main notebook and README promoted results despite README admitting test-driven selection of beam width and rich option text | Default to dev, clear notebook outputs, remove performance marketing and require a new holdout for confirmation |
| P1 | `benchmark.metrics` called any-gold hit rate “recall”; notebook macro F1 ignored labels appearing only in predictions | Separate hit@k and true example-mean multilabel recall@k; include union of predicted and gold labels in top-1 macro F1 |
| P1 | Notebook implied overlapping Wilson intervals decide paired differences | Add an ID-matched bootstrap helper, report assumptions, and distinguish individual accuracy intervals from contrasts |
| P1 | CLI and dependencies required TypeSafe and printed old Jev accuracy for all model overrides | Default CLI and adapter use the actual OpenAI Decisions endpoint; Jev is optional; no borrowed accuracy claim |
| P1 | Selector contract accepted distributions not summing to one; beam's monotone early-stop bound assumes valid probabilities | Validate normalized distributions, exact option coverage, duplicate probabilities and model drift; explicitly fail refusals |
| P1 | `dataset_analysis` compared only IDs when checking regenerated data | Compare complete records, including text, gold and split; dataset report now hashes catalog and benchmark bytes |
| P1 | Acquisition recorded the latest clone's SHA but exposed no way to replay a chosen revision | Add `--revision` accepting a full commit SHA |
| P2 | Committed Chroma database lacked a demonstrated match to catalog/embedding settings | Remove generated DB, rebuild explicitly, refuse overwriting collections, check documents/embedding metadata, hash loaded vectors, reject zero/nonfinite embeddings |
| P2 | Decision depth was inferred from final surviving paths, losing pruned beam branches; coverage recomputed scores from possibly repeated DAG questions | Save depth when asking; analyze returned routing scores directly; deterministic tie handling |
| P2 | Public config silently accepted misspelled keys and unsafe output model names | Reject unknown settings, unsafe path components, credentials in model options and unknown benchmark labels |

## Highest-value next work

| Priority | Improvement | Concrete experiment / acceptance criterion |
|---|---|---|
| P0 | Fresh evaluation after test-set reuse | Freeze model/prompt/traversal/metric and sample size; build a later, package-family-grouped or independently reviewed holdout with no alias overlap. Publish IDs, source revision and all exclusions before evaluating. Do not re-label errors after looking at predictions. |
| P0 | Live OpenAI smoke and matched comparison | First classify one public advisory and verify tokens, returned model, latency and option mapping. Run OpenAI and Jev on identical dev IDs with matched descriptions/traversal (not plain OpenAI vs rich Jev as if only provider changed). Compare paired accuracy, macro F1, rare-class support and p95 requests/latency. No quality threshold is established by mock tests. |
| P1 | Evaluate decisions independently of routes | Build dev-only questions from gold ancestors so all providers answer the same option sets. Report root accuracy, stopping accuracy and child accuracy by depth/branch size. Keep these oracle-route diagnostics separate from end-to-end traversal. |
| P1 | Stopping and overspecific suggestions | Compare parent vs STOP on dev using `hypotheses.ipynb`; manually review early/late stopping failures with two blinded reviewers. Require top-1 gain without unacceptable loss in rare-label F1 or request budget. |
| P1 | Retrieval plus reranking rather than deleting roots blindly | Measure catalog-only shortlist recall@N and an oracle ceiling before reranking. Include broad labels and none-of-the-above; never concatenate independently normalized batch probabilities. Root bypass is not yet implemented or validated. |
| P1 | Calibrated abstention / unknown classes | Curated GHSA inputs always have catalog labels, unlike real reports. Add unlabeled, ambiguous, out-of-taxonomy and benign inputs. Fit thresholds on a calibration partition; report frozen risk/coverage and false assignment rates on holdout. Parent STOP is not abstention. |
| P1 | Label and population reliability | Stratify blind adjudication by common/rare CWE, ecosystem and root failure. Track inter-reviewer agreement, curator disagreement and gold cardinality. Report package-family-clustered uncertainty and temporal/external transfer. |
| P2 | Request-level ledger and spend controls | Record status, attempt count, request ID, cached-token usage, per-attempt latency and failure category; add an explicit run request/spend budget before concurrency or retries. Current failed requests abort, but are not persisted; only completed advisory predictions are checkpointed. |
| P2 | Calibration and beam semantics | Local choice probabilities change with option sets. Beam products favor short paths and keep max rather than summing DAG paths. Test rankings by depth and calibrate on separate dev data. A new length-normalized score requires a new early-stop proof. |
| P2 | Source / embedding artifact pinning | Pin embedding model weights and tokenizer revisions and store their hashes with index construction settings. For external custom factories, include code/artifact fingerprints in metadata; project-source hashing cannot capture arbitrary external files. |
| P2 | Safe scaling | After measuring a baseline, add bounded concurrency, rate-limit-aware retry budgets and request-level reuse with exact evidence/option/prompt keys. Retain stable ordering and fail-closed schema checks. Make comparison report publication a run-ID directory transaction before concurrent readers are supported. |

## Interpretation boundaries

Exact top-1 agreement with any curator label is the primary implemented outcome.
It is not full multilabel recovery. Hierarchical scores can overreward shared
broad ancestors. Descriptive ECE conditions on on-route questions and contains
correlated beam decisions, so it is not a claim about end-to-end confidence.
Bootstrap and Wilson intervals assume independent examples, while near duplicates
and package families may remain correlated. GHSA can also occur in model training
data; CWE-ID stripping cannot remove that contamination.

The historical rich-option/beam findings are hypotheses, not clean confirmatory
comparisons. Alternatives and reasons not to promote them live in the separate
`experiment/hypotheses.ipynb`, leaving the main notebook focused on one protocol.
