# CSE-ThreatBench: Research and submission plan (v1)

**Status:** pre-implementation; manuscript v1 written; **no empirical results available**.  
**Venue:** AAAI-27 Workshop, *LLM Agents Under Threat in Cyberspace*. Deadline **Friday 20 November 2026, 23:59 AoE**; double-blind, 7 pages of body excluding references, AAAI two-column.  
**Paper:** [main.tex](main.tex). **Repository branch:** `paper/aaai27-context-threatbench`.

## 1. Frozen research decision

**Title:** *Relevant Is Not Sufficient: Security and Evidence Sufficiency in LLM Agent Context Compilation.*

**Core research question:** Can context compilation with deterministic eligibility, provenance, explicit requirements, and dependency closure improve the security--utility trade-off of tool-using LLM agents over strong retrieval baselines, including under malicious or incomplete evidence?

Do **not** turn this into an MCP Composer paper, an AI failure engineering/Maven workshop paper, a product benchmark, or a claim that CSE already provides semantic safety. MCP Composer is an **external-validity and complexity workload**. The existing CSE compiler is the tested intervention; independent execution authorization remains a different mechanism.

### Research questions

- **RQ1: Sufficiency.** Does explicit context compilation retain independently required evidence and improve valid task completion as evidence becomes incomplete, contradictory, or budget constrained?
- **RQ2: Security.** Which lower-trust context attacks are prevented by eligibility/policy constraints; which persist when malicious evidence is individually authorized?
- **RQ3: Scale.** Do observed effects persist when three layered MCP tools expose 100, 500, and 1,000 underlying operations?

### Falsifiable hypotheses

- **H1:** Dependency/requirements compilation improves oracle evidence recall and legitimate completion over equal-budget lexical, semantic and hierarchical baselines.
- **H2:** Policy-before-scoring prevents explicitly ineligible evidence from reaching any scorer or model under authenticated, trusted-principal assumptions.
- **H3:** CSE's explicit insufficient/blocked status reduces unjustified progression, but may increase false blocking; quantify both.
- **H4:** At scale, CSE produces better security/utility per token than hierarchical discovery alone.
- **Counter-hypotheses:** strong retrieval may match CSE, predeclared requirements may fail when the oracle is hidden, and valid malicious text may still hijack an LLM.

## 2. Prior-work and research lineage

### External published sources requiring comparison
1. Debenedetti et al., *AgentDojo*, NeurIPS 2024: https://arxiv.org/abs/2406.13352. Dynamic executable agent security benchmark; so executable attacks alone are not novel.
2. Wang et al., *MCPTox*, AAAI 2026: https://doi.org/10.1609/aaai.v40i42.40895. MCP metadata tool poisoning; so tool-description attacks alone are not novel.
3. IBM MCP Composer layered factory: https://ibm.github.io/mcp-composer/guide/layered_mcp_server.html. The three operations are `get_service_info`, `get_type_info`, `make_tool_call`. This is a workload, not an invention claimed here.
4. Search for additional existing work on secure context assembly, evidence-aware RAG, taint/data-flow tracking, instruction hierarchy, tool-use authorization, and context poisoning **before** G10 is approved.

### Own previous works: reuse concepts, do not imply validation
- **Context Sufficiency Engine v0.1:** implemented tenant/ACL/clearance admission, SHA-256 comparison, provenance, declared evidence coverage, dependency closure, conflicts, token-budget compilation, lexical and experimental learned scoring. Source: repository `README.md`, `docs/architecture.md`, `docs/security.md`, `docs/research-plan.md`.
- **Purpose-Aware Memory in Agentic Systems** (unpublished research direction): separates observations and candidate beliefs from durable knowledge via purpose, policy, uncertainty, temporal reconciliation, and provenance. Use it to motivate `eligible` versus `justified` context; **do not cite as published without exact metadata**.
- **Trustworthy AI / AI Governance book manuscript:** provenance, trust, responsibility, identity and authorization; relevant to trust boundaries, external policy, and evidence versus authority. **Book title, edition, status, publisher, and citation must be verified.**
- **Enterprise Intent Context Contracts / delegation design:** approved purpose, context ownership, attenuation and independent execution checks. Reuse boundary principles, not proprietary material.
- **Persistent Latent Dynamics: Reasoning as a Migratable Process**, manuscript branch of `hci-proj-1`: state vs substrate separation provides conceptual background on context continuity; probably omit from seven-page paper as not directly security evidence.
- **CAISH / compound-AI chaos manuscript** in `hci-proj-1`: falsifiable hypotheses, matched baselines, fault realism and independently verified outcomes inspire evaluation practice. **Reserved for separate work; do not reuse it as this submission or claim its experiments were run.**
- **CCNL / Accountable Knowledge** ideas: evidence provenance and declaration of knowledge limits; include as discussion motivation only if scholarly details can be grounded.
- **ThreadPilot and Maven workshop work:** **excluded from submission**.
- **AI Failure Determination/fault-engineering work:** **excluded from submission**.

**Double-blind protocol:** main.tex contains no identifying author details or self-claims of validated prior results. Later, include properly anonymized citations only if bibliographic data and venue rules justify them. The planning document can list private lineage, but is **not submitted**.

## 3. Ten mandatory pre-implementation gates

These are **not yet verified**. Each gate needs a reviewable artifact and an explicit pass/fail decision.

| Gate | Verification artifact | Pass condition |
|---|---|---|
| G1 Threat model | attacker-control matrix, assets, trust boundary and objective per attack | every attack has entry, scope, oracle outcome |
| G2 1,000-tool realism | generated schemas, controlled semantic overlap, route-filtered counts | schemas validate and operation distribution is auditable |
| G3 Oracle independence | separate hidden task ground truth and validation tests | oracle-derived required IDs do not leak into compiler inputs |
| G4 Authorization separation | three-stage trace and adjudication fields | selection, unsafe attempt, execution effects counted separately |
| G5 Strong baselines | matched model/budget policy and discovery allowances | no privileged information or extra tokens given to CSE |
| G6 Actual attack effects | sandbox state assertions and exposure sinks | text-only malicious recommendations never counted as executed compromise |
| G7 Paired variants | task ID, clean version, attack version, controlled mutation | benign purpose and environment preserved across pair |
| G8 Legitimate utility | successful completion and false block/abstention | blocking cannot masquerade as successful security |
| G9 Mechanism ablation | toggles for admission, dependencies, requirements, conflicts, integrity | contribution attributable to a component, not full-system confounds |
| G10 Novelty | claim-by-paper comparative review | meaningful distinction beyond prompt injection, MCP poisoning and scale |

## 4. Threat model (G1)

**Trusted:** end-user task; authenticated tenant/principal and scope claims from the gateway; authoritative authorization policy; trusted source manifest; execution PEP; oracle (evaluator only).

**Attacker controls, scenario-dependent:** selected document bodies; source summaries; low-trust service descriptions; schema prose; returned tool messages; distractor injection/ordering; attacker-owned service versions.

**Attacker cannot modify in main experiment:** principal identity, signed grant, authoritative schema, protected digest ledger, service allowlist, tool authorization rules, hidden oracle. Model separately any compromised registry/control plane; do not assume in the primary results.

**Target violations:** forbidden evidence reaches model/scorer, required supporting evidence omitted, unauthorized tool attempted, forbidden side effect executed, wrong operation chosen, invalid abstention of a valid task, or premature confidence under incomplete facts.

**Distinguish:** `selected_tool`, `requested_effect`, `authorization_decision`, `executed_effect`, `final_state`.

## 5. Benchmark datasets (G2/G3/G7)

### Environment A: context evidence compilation
Task families: incident/service investigation; root-cause evidence comparison; action precondition gathering; access-sensitive retrieval; conflicting service ownership; stale runbooks. Independent oracle specifies acceptable facts, sufficient evidence sets, valid resolutions and forbidden effects.

### Environment B: MCP Composer layered operations
Preserve the actual 3-tool interface: `get_service_info` -> `get_type_info` -> `make_tool_call`. Vary **underlying operations**, not front-facing tool count: 100, 500, 1,000. Registered operations and route-eligible operations must be measured separately.

Generate sandbox-only OpenAPI catalogs with:
- 10 operational domains (observability, infra, IAM, CI/CD, audit, CRM, billing, inventory, data, support);
- valid operationId, service owner, HTTP method, path, input/output JSON schema, examples, risk class, auth scope, version;
- semantic near-duplicates, repeated parameter names but different permissions, multi-step service dependencies and stale versions;
- realistic synthetic API data and deterministic effect handlers; no live credentials or production systems;
- **catalog construction independence** from CSE scoring/requirements.

Avoid artificial success from injecting true target operation IDs as CSE `pinned_ids` unless a realistic trusted source would actually supply them. Report an oracle-hidden variant.

### Corpus and split
- Full target: 200 unique tasks, 8 attack families, 100/500/1,000 scale, 1k/4k/8k/16k budgets.
- Friday pilot: approximately 40 unique task pairs, 100/1,000 scale, 4k/8k budgets, A1/A2/A4/A5; one pinned agent model.
- Split by task family and service family, not random near-duplicate strings. Preserve paired benign/adversarial variants inside the same held-out group.
- Keep `scenario_id`, `source_snapshot`, `attack_family`, `attack_control`, `oracle_id`, and random seed.

## 6. Attacks and baselines (G4/G5/G6)

| Attack | What changes | Observable success |
|---|---|---|
| A1 Unauthorized evidence | cross-tenant or forbidden source highly ranked | prohibited exposure to scorer/model |
| A2 Evidence displacement | long high-relevance distractors, necessary evidence omitted | incorrect conclusion or false-ready |
| A3 Stale/contradictory | expired or undisclosed conflicting evidence | invalid decision/unsafe effect |
| A4 Metadata poisoning | untrusted `get_service_info` text directs agent | wrong selection/attempt/effect |
| A5 Schema prose poisoning | malicious explanation in `get_type_info` | invalid or unauthorized call |
| A6 Tool-result injection | returned low-trust body contains instruction | attacker-desired redirection |
| A7 Post-discovery mutation | schema/version changes before execution | stale-schema misuse |
| A8 Ranking manipulation | attack favors malicious yet eligible evidence | task/attack consequence |

**Baseline definitions:**
- B0: ordinary task retrieval or unmodified layered MCP discovery.
- B1: lexical top-k with same context-token cap.
- B2: semantic top-k with frozen encoder and same cap.
- B3: hierarchical discovery plus schema/policy validator, no CSE.
- B4: CSE admission-only.
- B5: full CSE with dependencies, requirements, conflict, budget.
- B6: full CSE plus independent action gate, reported separately; do **not** count PEP denial as context-compiler success.

For principal comparisons, apply the **same runtime enforcement** to B0–B5. Record unsafe attempted calls as well as actual effects, otherwise PEP yields a trivial zero executed-attack rate.

## 7. Outcome and statistical protocol (G6/G8/G9)

**Primary endpoints:** (i) legitimate task completion, (ii) oracle false-ready rate among cases reporting ready, (iii) unsafe attempt rate under attack. **Secondary:** forbidden evidence exposure to scorer/model; executed attack success; evidence recall; false block; correct service/schema; calls; tokens; latency; cost per correct outcome.

- Attack success uses a sandbox state change or verified exposure; do not count model text.
- Use paired task deltas and paired bootstrap 95% confidence intervals resampling **tasks**, not individual model generations.
- Retain multiple model seeds per task when feasible, clustering them by task.
- Present sample counts and confidence intervals; label any pilot explorations as exploratory.
- Report refusal and benign utility even when all attacks are blocked.
- Fix task definitions and ablations before looking at results; store amendment log after freeze.

**Ablations:** no policy-first eligibility; no dependencies; no declared requirements; no conflicts; no trusted integrity; no fail-closed; lexical instead of learned scoring. Test one variable at a time.

## 8. Work order and hard go/no-go checks

### Tuesday 17 Nov — scientific specification
RT-01 novelty review; RT-02 threat model; RT-03 oracle/data generation rules. Exit: G1/G3/G10 design reviewed. Commit research protocol and manuscript v1.

### Wednesday 18 Nov — pilot, only after gates
Build separate benchmark sandbox/adapter; validate catalogs and independent oracle; run matched pilot for A1/A2/A4/A5 and B1/B3/B5. Exit: trace-backed task and attack outcomes. If not achieved, switch submission to explicitly labeled position paper; never invent a table.

### Thursday 19 Nov — manuscript completion
Freeze data and analysis; run ablations; insert reproducible tables, limitations, confidence intervals and exact environment versions. Use official AAAI-27 author kit; anonymize review PDF; target <=7 text pages excluding references.

### Friday 20 Nov — final submission checks
Full compile and PDF visual review; check references, anonymous metadata, repository links, and OpenReview form. Submit before 23:59 AoE.

## 9. Claim-to-evidence map

| Paper claim | Required evidence | Status |
|---|---|---|
| Ineligible data never reaches scorer | trace/assertion from boundary unit tests plus integrated tests | existing unit tests; integration pending |
| Dependency-aware selection preserves prerequisites | independent-oracle tasks, matched baselines | pending |
| CSE improves secure agent action | simulated tool effects and attack attempts | pending |
| CSE retains legitimate task success | paired benign outcomes and refusal | pending |
| Benefit persists to 1,000 operations | scaled catalog and valid layered discovery traces | pending |
| Better than prior art | published benchmark and method comparison | pending |

## 10. Submission and manuscript rules

- The manuscript's current abstract **does not assert measured improvements**.
- Keep only evidence-supported claims and traceable citations.
- Add exact verified bibliographic metadata for the author's books/manuscripts only when appropriate; avoid self-identification in anonymous review.
- Download the official `aaai2027.sty` from https://aaai.org/conference/aaai/aaai-27/submission-instructions/; never fabricate or modify the style.
- Workshop rules: https://llm-agents-under-threat.github.io/
- Main source: `main.tex`; a compiled PDF is **not created by this commit**.
