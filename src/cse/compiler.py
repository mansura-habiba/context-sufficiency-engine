"""A policy-first deterministic context compiler; ML ranking is advisory only."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any

from cse.models import LEVELS, CompilationRequest, ContextItem, InvalidRequest
from cse.policy import PolicyConfig, authorize
from cse.scorers import LexicalScorer, Scorer, ScoringError

ESTIMATOR = "utf8_bytes_div_3_conservative_heuristic_not_tokenizer"


def encoded_context(items: list[ContextItem]) -> str:
    # JSON quoted values keep evidence in a data envelope; this does not neutralise
    # prompt injection. Downstream systems must enforce instruction priority.
    return json.dumps(
        {"untrusted_evidence": [item.as_prompt_record() for item in items]},
        separators=(",", ":"),
        ensure_ascii=False,
    )


def estimated_tokens(encoded: str) -> int:
    # Approximation, not a guarantee for every model/tokenizer.
    return math.ceil(len(encoded.encode("utf-8")) / 3)


@dataclass(frozen=True)
class CompileResult:
    status: str
    requirement_coverage: str
    context_json: str | None
    context_sha256: str | None
    provenance_manifest: tuple[dict[str, str], ...]
    selected_ids: tuple[str, ...]
    deferred_ids: tuple[str, ...]
    missing_requirements: tuple[str, ...]
    budget_tokens: int
    estimated_tokens: int
    excluded_counts: dict[str, int]
    scorer: str
    degraded: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "requirement_coverage": self.requirement_coverage,
            "context_json": self.context_json,
            "context_sha256": self.context_sha256,
            "provenance_manifest": list(self.provenance_manifest),
            "selected_ids": list(self.selected_ids),
            "deferred_ids": list(self.deferred_ids),
            "missing_requirements": list(self.missing_requirements),
            "budget_tokens": self.budget_tokens,
            "estimated_tokens": self.estimated_tokens,
            "token_estimator": ESTIMATOR,
            "excluded_counts": self.excluded_counts,
            "scorer": self.scorer,
            "degraded": self.degraded,
        }


class ContextCompiler:
    def __init__(
        self,
        *,
        scorer: Scorer | None = None,
        policy: PolicyConfig | None = None,
        minimum_optional_score: float = 0.10,
    ) -> None:
        if not 0 <= minimum_optional_score <= 1:
            raise InvalidRequest("minimum_optional_score must be in [0,1]")
        self.scorer = scorer or LexicalScorer()
        self.policy = policy or PolicyConfig()
        self.minimum_optional_score = minimum_optional_score

    def _scores(self, request: CompilationRequest, eligible: dict[str, ContextItem]) -> tuple[dict[str, float], str, bool]:
        candidate_items = list(eligible.values())
        if not self.scorer.external:
            return self._validate_scores(self.scorer.score(request.task, candidate_items), eligible), type(self.scorer).__name__, False

        if not self.policy.external_scoring_allowed:
            raise InvalidRequest("external model egress is disabled by policy")
        ceiling = LEVELS.index(self.policy.external_max_classification)
        if LEVELS.index(request.task_classification) > ceiling:
            raise InvalidRequest("task classification forbids external model egress")
        remote_items = [item for item in candidate_items if LEVELS.index(item.classification) <= ceiling]
        local_items = [item for item in candidate_items if LEVELS.index(item.classification) > ceiling]
        lexical = LexicalScorer()
        local_scores = lexical.score(request.task, local_items)
        try:
            remote_scores = self.scorer.score(request.task, remote_items) if remote_items else {}
            scores = {**local_scores, **remote_scores}
            return self._validate_scores(scores, eligible), type(self.scorer).__name__, bool(local_items)
        except ScoringError:
            return lexical.score(request.task, candidate_items), "LexicalScorer(fallback)", True

    @staticmethod
    def _validate_scores(scores: dict[str, float], eligible: dict[str, ContextItem]) -> dict[str, float]:
        if not isinstance(scores, dict):
            raise InvalidRequest("scorer must return score mapping")
        result: dict[str, float] = {}
        for item_id in eligible:
            value = scores.get(item_id)
            if not isinstance(value, (float, int)) or isinstance(value, bool) or not math.isfinite(value) or not 0 <= value <= 1:
                raise InvalidRequest("scorer must provide a finite score [0,1] for each eligible item")
            result[item_id] = float(value)
        return result

    def compile(self, request: CompilationRequest) -> CompileResult:
        eligible, exclusions = authorize(request, self.policy)
        scores, scorer_name, degraded = self._scores(request, eligible)
        # Dependency closures are computed *after* authorization so a missing or
        # inaccessible dependency is indistinguishable to an untrusted caller.
        cached: dict[str, frozenset[str] | None] = {}

        def closure(item_id: str, path: frozenset[str] = frozenset()) -> frozenset[str] | None:
            if item_id not in eligible:
                return None
            if item_id in path:
                raise InvalidRequest("dependency graph contains a cycle")
            if item_id in cached:
                return cached[item_id]
            union = {item_id}
            for dep in eligible[item_id].dependencies:
                required = closure(dep, path | {item_id})
                if required is None:
                    cached[item_id] = None
                    return None
                union.update(required)
            cached[item_id] = frozenset(union)
            return cached[item_id]

        valid = {item_id: deps for item_id in eligible if (deps := closure(item_id)) is not None}
        excluded = {**exclusions}
        excluded["unresolved_dependency"] = len(eligible) - len(valid)
        selected: set[str] = set()
        missing: list[str] = []

        def total_cost(ids: set[str]) -> int:
            return estimated_tokens(encoded_context([eligible[x] for x in sorted(ids)]))

        def compatible(ids: set[str]) -> bool:
            # Conflict declarations are interpreted symmetrically. The compiler does
            # not infer conflicts; ingestion must supply verified conflict metadata.
            return all(
                not (set(eligible[item_id].conflicts_with) & ids)
                for item_id in ids
            )

        def can_fit(ids: set[str]) -> bool:
            return compatible(ids) and total_cost(ids) <= request.budget_tokens

        for requested_id in request.pinned_ids:
            deps = valid.get(requested_id)
            if deps is None or not can_fit(selected | deps):
                missing.append("pinned:" + requested_id)
            else:
                selected.update(deps)

        # Greedy cover over explicitly declared acceptable evidence alternatives.
        for requirement in request.requirements:
            while len(selected.intersection(requirement.any_of)) < requirement.min_count:
                alternatives = []
                for item_id in set(requirement.any_of) - selected:
                    deps = valid.get(item_id)
                    if deps is None or not can_fit(selected | deps):
                        continue
                    marginal = total_cost(selected | deps) - total_cost(selected)
                    alternatives.append((marginal / (0.1 + scores[item_id]), marginal, item_id, deps))
                if not alternatives:
                    missing.append("requirement:" + requirement.id)
                    break
                _, _, _, best = min(alternatives, key=lambda x: x[:3])
                selected.update(best)

        if missing:
            # Fail closed on requirements: return no partial context and no authorized IDs
            # beyond the eligible deferred list (the caller already owns that data).
            return CompileResult(
                status="blocked",
                requirement_coverage="not_met",
                context_json=None,
                context_sha256=None,
                provenance_manifest=(),
                selected_ids=(),
                deferred_ids=tuple(sorted(valid)),
                missing_requirements=tuple(sorted(set(missing))),
                budget_tokens=request.budget_tokens,
                estimated_tokens=0,
                excluded_counts=excluded,
                scorer=scorer_name,
                degraded=degraded,
            )

        # Greedy utility per incremental token. Dependency closure is atomic.
        rest = set(valid) - selected
        while rest:
            candidates = []
            for item_id in rest:
                if scores[item_id] < self.minimum_optional_score:
                    continue
                deps = valid[item_id]
                proposed = selected | deps
                if not can_fit(proposed):
                    continue
                marginal = max(1, total_cost(proposed) - total_cost(selected))
                candidates.append((-scores[item_id] / marginal, item_id, deps))
            if not candidates:
                break
            _, chosen, deps = min(candidates, key=lambda x: (x[0], x[1]))
            selected.update(deps)
            rest.difference_update(deps)
            rest.discard(chosen)

        output = encoded_context([eligible[x] for x in sorted(selected)])
        # Explicit requirements are a declarative coverage check, not semantic proof.
        coverage = "declared_requirements_met" if (request.requirements or request.pinned_ids) else "not_evaluated"
        status = "ready" if coverage == "declared_requirements_met" else "unverified"
        return CompileResult(
            status=status,
            requirement_coverage=coverage,
            context_json=output,
            context_sha256=hashlib.sha256(output.encode("utf-8")).hexdigest(),
            provenance_manifest=tuple({
                "id": eligible[item_id].id,
                "source": eligible[item_id].source,
                "version": eligible[item_id].version,
                "sha256": eligible[item_id].sha256 or "not-verified",
            } for item_id in sorted(selected)),
            selected_ids=tuple(sorted(selected)),
            deferred_ids=tuple(sorted(set(valid) - selected)),
            missing_requirements=(),
            budget_tokens=request.budget_tokens,
            estimated_tokens=total_cost(selected),
            excluded_counts=excluded,
            scorer=scorer_name,
            degraded=degraded,
        )
