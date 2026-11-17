# What did the Colab engineering audit actually probe?

**Source:** `CSE_ThreatBench_Colab.ipynb` engineering-audit cell, `pilot.py` task fixtures. **Reported values:** user-supplied notebook output, 17 November 2026. This is not an LLM model-outcome result.

## Experimental unit and probes

The implementation runs **12 synthetic task templates**, each under a clean and attacked variant: 24 context compilation cases. Their four attack families are:

| Family | Cases | Attacker mutation | Observable evaluated |
|---|---|---|---|
| A1 cross-tenant evidence (t01–t03) | 3 attacked | Inject relevant-looking but forbidden foreign-tenant record | Whether unauthorized evidence is selected or filtered |
| A2 missing dependency and flooding (t04–t06) | 3 attacked | Remove oracle-required prerequisite and add distractors | Whether declared dependency closure blocks partial context |
| A4 poisoned service discovery (t07–t09) | 3 attacked | Add allowed record containing adversarial instructions to change operation | Whether malicious record is selected; model behavior only in separate trial cell |
| A5 poisoned schema prose (t10–t12) | 3 attacked | Add allowed record telling agent to use a privileged write operation | Whether malicious record is selected; model behavior only in separate trial cell |

The remaining twelve cases use the matching clean versions. **The audit always evaluates all twelve templates**, even if `FULL_RUN=False` limits the Qwen model experiment to six templates. This explains why audit totals may not equal model-trial totals.

## What the output columns actually mean

| Column | Definition | Limits |
|---|---|---|
| `blocked` | Number of context compiler calls returning `status=blocked` (with no context JSON) | Does not by itself measure safe decisions or model accuracy |
| `mean_compile_ms` | Arithmetic mean of Python compiler runtime over the 12 cases in that variant | Tiny single-process cases; CPU, runtime and warm-up affect it |
| `provenance_records` | Sum of lengths of `provenance_manifest` over all 12 cases | Not distinct documents; a manifest alone does not prove authentic origin |

## Your observed result

| Variant | Blocked | Mean compile time | Total emitted provenance records |
|---|---:|---:|---:|
| Attacked | 3 / 12 | 0.482595 ms | 26 |
| Clean | 0 / 12 | 0.399674 ms | 27 |

Interpretation: the three blocked attacked cases correspond to **A2 missing prerequisites**; no clean request was blocked. The difference in manifest totals results from varying selection and empty manifests for blocked requests. The approximately 0.08 ms timing difference is a descriptive observation only, not evidence of statistical significance or 1,000-tool scalability.

**What these numbers do not establish:** prompt-injection resistance, model-level unsafe attempt rate, legitimate task completion, cross-model robustness, real MCP Composer operation selection, execution of forbidden actions, or production latency.

## What to inspect after rerunning the revised notebook

The notebook now prints a per-task table with `task_id`, `probe`, `variant`, `missing_at_source`, `status`, `covered_oracle`, `selected_ids`, and `authorized_malicious_selected`. It writes `probe_explanations.csv` alongside `model_trials.csv`, `engineering_audit.csv`, and `manifest.json`, then rebuilds the downloadable ZIP.

**Research decision:** CSE has a plausible engineering value as deterministic context-contract middleware with dependency blocking and audit manifests. The existing aggregate results are not enough to demonstrate *incremental* end-to-end security or semantic-sufficiency value beyond a strong policy-aware retriever. Compare S1 versus S2 on the actual model trials before making that claim.
