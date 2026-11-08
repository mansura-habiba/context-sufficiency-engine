"""Pure policy enforcement, upstream of every model and context selection decision."""
from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from cse.models import LEVELS, CompilationRequest, ContextItem, InvalidRequest, Principal


def digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PolicyConfig:
    require_digest: bool = True
    max_items: int = 1000
    max_content_chars: int = 25000
    max_total_chars: int = 2_000_000
    external_scoring_allowed: bool = False
    external_max_classification: str = "public"

    def __post_init__(self) -> None:
        if self.external_max_classification not in LEVELS:
            raise InvalidRequest("invalid external_max_classification")
        if self.max_items < 1 or self.max_content_chars < 1 or self.max_total_chars < 1:
            raise InvalidRequest("policy limits must be positive")


def can_access(item: ContextItem, principal: Principal, now: datetime, config: PolicyConfig) -> str | None:
    if item.tenant != principal.tenant:
        return "unauthorized"
    if LEVELS.index(item.classification) > LEVELS.index(principal.clearance):
        return "unauthorized"
    acl_specified = bool(item.allowed_subjects or item.allowed_scopes)
    has_acl_grant = (
        principal.subject in item.allowed_subjects
        or bool(principal.scopes.intersection(item.allowed_scopes))
    )
    if item.visibility == "restricted" and not acl_specified:
        return "unauthorized"
    if acl_specified and not has_acl_grant:
        return "unauthorized"
    if item.not_before and item.not_before > now:
        return "unavailable"
    if item.expires_at and item.expires_at <= now:
        return "expired"
    if config.require_digest and not item.sha256:
        return "unverified"
    if item.sha256 and digest(item.content) != item.sha256:
        return "unverified"
    if len(item.content) > config.max_content_chars:
        return "too_large"
    return None


def authorize(
    request: CompilationRequest, config: PolicyConfig, now: datetime | None = None
) -> tuple[dict[str, ContextItem], dict[str, int]]:
    if len(request.items) > config.max_items:
        raise InvalidRequest("too many context items")
    if sum(len(item.content) for item in request.items) > config.max_total_chars:
        raise InvalidRequest("aggregate context size exceeds policy")
    now = now or datetime.now(timezone.utc)
    eligible: dict[str, ContextItem] = {}
    counts: Counter[str] = Counter()
    for item in request.items:
        reason = can_access(item, request.principal, now, config)
        if reason:
            counts[reason] += 1
        else:
            eligible[item.id] = item
    return eligible, dict(sorted(counts.items()))
