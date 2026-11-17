# Implementation-value decision — even if CSE does not improve LLM outcomes

**Status:** Engineering assessment based on examined source and deterministic pilot, NOT an empirical model performance result.  
**Companion notebook:** [CSE_ThreatBench_Colab.ipynb](CSE_ThreatBench_Colab.ipynb)  
**Experiment protocol:** [submission/STRESS_TEST_AND_MINIMUM_EXPERIMENT.md](submission/STRESS_TEST_AND_MINIMUM_EXPERIMENT.md)

## What the existing deterministic pilot establishes

- S1 policy-aware lexical retrieval and S2 CSE retained the available oracle evidence in the same 21/24 cases; CSE has **not** shown an incremental retrieval benefit.
- Both systems avoided cross-tenant selection in A1, demonstrating **policy-aware filtering**, not unique CSE effectiveness.
- CSE explicitly blocked the three missing-dependency cases; S1 returned a partial context as `unverified`. This is a **control-plane contract difference** worthy of isolation.
- CSE selected malicious-but-authorized prose in six cases; the compiler is **not** a prompt-injection sanitizer.
- No downstream agent outcome or genuine runtime execution has yet been measured.

## What value might remain

| Property | Existing mechanism | Potential operational value | What must still be measured |
|---|---|---|---|
| Explicit context contracts | Declared requirement IDs, pinned records, dependencies | Caller receives `ready`, `unverified`, or `blocked` rather than arbitrary top-k | False blocking; trusted metadata availability; missed undeclared prerequisites |
| Pre-scoring eligibility | Tenant, clearance, scope, ACL, time | Prevent unauthorized evidence being sent to local/remote scorer | Gateway identity binding; denial traces; egress enforcement |
| Reproducible evidence bundle | Stable JSON, digest, provenance manifest | Audits/replay and support diagnostics | End-to-end trace linking and policy version provenance |
| Fail-closed dependency closure | Partial prerequisites result in no context when required | Prevent premature LLM tool calls | Legitimate read-only task degradation and recovery path |
| Separable scorer | Lexical / trained / hosted optional model | Cheap deterministic fallback; avoid reliance on larger model | Context recall and **cost per successful task**; remote privacy terms |
| Stateless library | Pure Python compilation without infrastructure | Lower deployment and ops complexity than dedicated context agent | p50/p95 compilation latency at 100/500/1000 records; memory consumption |
| Explicit deferred IDs | Controlled expansion after initial compile | Progressive disclosure under context budget | Number of expansion rounds and total task success |

## Engineering cautions in current code

1. `ready` checks only declared IDs; no intrinsic semantic sufficiency. Do not rename it `safe` or `verified`.
2. SHA-256 comparison is not authenticity unless digests are anchored to trusted ingestion records.
3. No authenticated external principal derivation or action policy is implemented; the gateway owns both.
4. The token budget estimator is `ceil(UTF8 bytes / 3)`, not a model-specific tokenizer.
5. The greedy closure/budget selection repeatedly encodes candidate contexts; scaling CPU and memory cost need measurement, not assumption.
6. Dependency and conflict metadata are supplied by ingestion. Incorrect metadata may produce bad admissions or unnecessary refusal.
7. The compiler may admit instruction-bearing authorized evidence as plain JSON; independent tool permissions are mandatory.
8. `deferred_ids` is not a revocation mechanism and a compiled bundle can become stale after source updates.

## Deployment decision tree

**Keep CSE as in-process library/middleware**, not a separate service or orchestration agent, when it demonstrably enforces domain-specific context contracts with acceptable p95 compilation cost and makes missing prerequisites explicit.

**Reduce CSE to a policy + provenance wrapper** if dependency closure and declared coverage add no benefit beyond a policy-aware retriever.

**Do not fine-tune a small model yet** unless a held-out scoring study outperforms lexical/hierarchical retrieval on task success and cost. Learned ranking must never grant access.

**Discard/rearchitect the compiler** if its false-blocking cost, maintenance overhead, or scaling complexity exceeds its measurable contract/provenance benefit.

## Colab experiment outcomes

The notebook produces:
- `model_trials.csv` with model-selected read/admin/abstain decisions, unsafe attempts, and simulated task completion;
- `engineering_audit.csv` with blocked states, provenance records, and local compiler timings;
- `manifest.json` with model ID, Git commit and seed.

The model tool calls are simulated, not actual MCP server calls. Do **not** write quantitative security efficacy claims into the submission until the notebook is executed and task outcomes are independently validated.

## Following the pilot

1. Run the notebook with one pinned HF model and compare S1 vs S2 per paired task.
2. Analyze false blocks vs detected missing evidence and compare total context bytes/tokens.
3. Add controlled tasks where dependencies are present but competing distractors require prioritization; current fixtures are easy.
4. Add an independent held-out corpus and a real MCP Composer layered discovery workload; do not expose oracle targets through context requirements.
5. If S1 matches or beats S2, publish a clear negative result or focus on the middleware contract contribution; do not market CSE as better context reasoning.
