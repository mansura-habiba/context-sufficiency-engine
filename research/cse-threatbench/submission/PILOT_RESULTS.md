# CSE-ThreatBench deterministic pilot — first measured checkpoint

**Date:** 2026-11-17  
**Run:** [GitHub Actions run 44109377549](https://github.com/mansura-habiba/context-sufficiency-engine/actions/runs/44109377549)  
**Revision:** `b4170df6ab09afa58bed82828d4b3e771cb06f36`  
**Scope:** deterministic context-selection only. **Not an LLM-agent evaluation.**

## Configuration

12 author-defined task templates, each with a benign and adversarial variant, for 24 test instances; three methods (S0 unfiltered lexical, S1 policy-aware lexical, S2 full CSE), totaling **72 deterministic selections**. Budget: 600 heuristic tokens, not a model tokenizer. Attacks: cross-tenant records (A1, 3 cases), missing-prerequisite + flood (A2, 3 cases), malicious service descriptions (A4, 3 cases), malicious schema prose (A5, 3 cases). Same scenario and principal for all methods.

## Observed results

| Observed outcome over 24 variants per method | S0 lexical | S1 policy-aware | S2 CSE |
|---|---:|---:|---:|
| Complete oracle-required evidence retained | 21 | 21 | 21 |
| Cross-tenant forbidden evidence selected | 3 | 0 | 0 |
| Detected missing prerequisite and blocked | 0 | 0 | 3 |
| Malicious-but-authorized descriptions selected | 6 | 6 | 6 |
| Mean required evidence recall | 0.9375 | 0.9375 | 0.8750 |

**Important semantics:** The three A2 attacked cases have missing oracle evidence at the *source*, so no selector can satisfy the oracle. CSE returns `blocked` with no partial context. Its lower mean recall is therefore a side-effect of fail-closed behavior and is not directly comparable to partial-context exposure from the baselines. Neither baseline emits `ready`, so `false_ready=0` is not a meaningful evidence sufficiency win.

**Key scientific finding:** CSE explicitly detects three declared dependency failures; S1 does not. But CSE does **not** outperform a policy-aware retriever on inclusion of required available evidence in these fixtures. Neither CSE nor S1 excludes malicious but otherwise authorized description text. This is not measured LLM prompt-injection success; it is only presence in the compiled context.

## Verification

GitHub Actions Python 3.13 run reported seven pilot tests passed; the full package unit tests and offline benchmark passed. Complete result JSON is published as workflow artifact `cse-threatbench-deterministic-3.13`; other interpreter versions run in the same CI matrix. No downstream agent or tool side-effect tracing was executed.

## Limitations / disqualifications for empirical claims

1. The task fixtures, 'independent' oracle records and selection systems are currently authored in the same module. The oracle is withheld at runtime but **not independently designed or blinded**; G3 is **not passed**.
2. S0 and S1 are simplified lexical context selectors, not a faithful implementation of MCP Composer's 3-tool layered service runtime; G2/G5 remain open.
3. Context token budget uses CSE's byte heuristic, not actual target model tokenization.
4. No model calls, authenticated gateway identity, runtime tool execution, attack-effect evidence, or stochastic trials. G4/G6/G8 are not empirically demonstrated.
5. Current task difficulty is too low to establish useful performance differences beyond the known dependency rule. In particular, this is mostly a software-invariant check, **not publication-ready end-to-end evidence**.
6. 12 templates and only three occurrences per attack family have very low coverage and no power for generalization.
7. Do not insert this result table into the manuscript as proof of security efficacy. It may be included as a narrowly framed preliminary deterministic analysis only if paper space allows.

## Next requirements, in strict order

- Build genuinely independent oracle/sandbox fixtures and prove task feasibility without oracle leakage.
- Integrate a pinned model-driven agent with trace collection and read-only sandbox tool execution; preserve the same execution gateway for S1 and S2.
- Record unsafe attempts, denied executions, successful benign actions, false refusals, and costs.
- Add real MCP Composer `get_service_info` / `get_type_info` / `make_tool_call` integration only after primary S1-versus-S2 measurements exist.
- Run paired trials and report uncertainty; preserve all negative results.
- Revise main.tex to distinguish proof of local invariants from end-to-end security.

**Current assessment:** deterministic pilot complete and validated; empirical paper gate **NO-GO** pending agent and sandbox experiment.
