# Research programme: Is context selection actually useful?

## Hypothesis

A compact, task-conditioned context decision model can lower **cost per correctly completed task** without increasing missing evidence, unauthorized exposure, or unsafe actions compared with simple baselines.

This project must distinguish **declared evidence coverage** (implemented) from **semantic evidence sufficiency** (unproven).

## Research stages

### Stage A — Baselines and truthful evaluation

1. Construct a leak-safe benchmark of task specifications, evidence records, required facts, dependencies, source validity windows, permitted principals and reference outcomes.
2. Compare full authorized context, recency cut, top-k lexical relevance, small linear scorer, and any available decision model.
3. For each task, run the same target LLM multiple times with controlled seeds where possible and score verified task outcomes, not subjective confidence.
4. Perform single-item and bundle ablations to find evidence whose removal changes task correctness.
5. Hold out sources, task families, and tenants; do not evaluate on synthetic training examples.

Primary metrics: (a) downstream task success, (b) critical evidence omission, (c) unauthorized disclosure attempts, (d) estimated and exact tokens, (e) p50/p95 total latency, (f) total cost per successful task. Report accuracy, calibration (Brier/ECE), false admission, false exclusion and abstention separately. All thresholds require held-out calibration.

### Stage B — Small contextual decision model

Start with the included hashed-linear classifier as a smoke-test, not a scientific baseline champion. Compare a compact 150M–500M encoder with separate admission, joint evidence sufficiency, dependency, conflict and refresh heads. Train on downstream ablation labels, document missing labels and contradictory examples, and evaluate against strong non-learning methods.

Keep policy enforcement independent from model output. An encoder must never create access grants or mutate source provenance metadata.

### Stage C — Adaptive context lifecycle

Model transitions: admit, retain, defer, refresh, revoke, expand, abstain. Introduce signed provenance and an event-driven revalidation protocol, then test concurrent revocation and replay safety. Evaluate cache reuse and stable prefix assembly as part of total inference cost.

## Example experiment

Task: diagnose a software outage. Evidence includes deployment logs, latency metrics, alert descriptions, incident notes and a red-herring document. The reference response must identify an observed change and verify its timing. A score-only ranker may choose the deployment log while omitting the metric that establishes chronology. A dependency-aware sufficiency model should select the pair—or explicitly abstain.

## Existing work to beat, not rename

- LLMLingua-2: https://arxiv.org/abs/2403.12968
- Lost in the Middle: https://arxiv.org/abs/2307.03172
- SCOPE (learned context optimisation): https://aclanthology.org/2026.emnlp-industry.129/
- When Learned Context Planning Fails to Beat Strong Retrieval: https://aclanthology.org/2026.insights-1.11/
- Cloudflare Clef-flash: https://developers.cloudflare.com/ai/models/%40cf/cloudflare/clef-flash/

The above are prior work and comparison points, not proof of novelty or patentability. Patent claims should be considered only after mapping concrete technical mechanisms to prior art.

## MVP benchmark limitations

`examples/eval_cases.json` covers structural invariants and simple selection expectations with synthetic data. It does not measure downstream correctness, evidence entailment, contamination, calibration, poisoning, adversarial resilience, or statistical significance. A 100% replay pass rate means only that the implementation agrees with those case labels.
