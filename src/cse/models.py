"""Typed, validated context records. All identities here must come from trusted callers."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

LEVELS = ("public", "internal", "confidential", "restricted")
VISIBILITIES = ("tenant", "restricted")
MAX_TASK_CHARS = 20_000


class InvalidRequest(ValueError):
    """The client supplied an invalid context compilation request."""


def _nonempty(value: Any, name: str, max_chars: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_chars:
        raise InvalidRequest(f"{name} must be a nonempty string (max {max_chars} chars)")
    return value


def _strings(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > 500:
        raise InvalidRequest(f"{name} must be a list of at most 500 strings")
    return tuple(_nonempty(v, name) for v in value)


def _timestamp(value: Any, name: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidRequest(f"{name} must be an ISO 8601 timestamp with timezone")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidRequest(f"{name} must be an ISO 8601 timestamp") from exc
    if result.utcoffset() is None:
        raise InvalidRequest(f"{name} must include a timezone")
    return result.astimezone(timezone.utc)


@dataclass(frozen=True)
class Principal:
    tenant: str
    subject: str
    clearance: str = "internal"
    scopes: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> Principal:
        if not isinstance(value, dict):
            raise InvalidRequest("principal must be an object provided by a trusted gateway")
        clearance = value.get("clearance", "internal")
        if clearance not in LEVELS:
            raise InvalidRequest("invalid principal clearance")
        return cls(
            tenant=_nonempty(value.get("tenant"), "principal.tenant"),
            subject=_nonempty(value.get("subject"), "principal.subject"),
            clearance=clearance,
            scopes=frozenset(_strings(value.get("scopes", []), "principal.scopes")),
        )


@dataclass(frozen=True)
class ContextItem:
    id: str
    tenant: str
    title: str
    content: str
    source: str
    version: str = "1"
    classification: str = "internal"
    visibility: str = "tenant"
    allowed_subjects: tuple[str, ...] = ()
    allowed_scopes: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    conflicts_with: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    not_before: datetime | None = None
    expires_at: datetime | None = None
    sha256: str | None = None

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> ContextItem:
        if not isinstance(value, dict):
            raise InvalidRequest("each item must be an object")
        content = value.get("content")
        if not isinstance(content, str) or not content.strip():
            raise InvalidRequest("item.content must be a nonempty string")
        classification = value.get("classification", "internal")
        visibility = value.get("visibility", "tenant")
        if classification not in LEVELS or visibility not in VISIBILITIES:
            raise InvalidRequest("invalid item classification or visibility")
        digest = value.get("sha256")
        if digest is not None and (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise InvalidRequest("item.sha256 must be a lowercase hexadecimal SHA-256 digest")
        return cls(
            id=_nonempty(value.get("id"), "item.id"),
            tenant=_nonempty(value.get("tenant"), "item.tenant"),
            title=_nonempty(value.get("title"), "item.title", 500),
            content=content,
            source=_nonempty(value.get("source"), "item.source", 1024),
            version=_nonempty(value.get("version", "1"), "item.version"),
            classification=classification,
            visibility=visibility,
            allowed_subjects=_strings(value.get("allowed_subjects", []), "allowed_subjects"),
            allowed_scopes=_strings(value.get("allowed_scopes", []), "allowed_scopes"),
            dependencies=_strings(value.get("dependencies", []), "dependencies"),
            conflicts_with=_strings(value.get("conflicts_with", []), "conflicts_with"),
            tags=_strings(value.get("tags", []), "tags"),
            not_before=_timestamp(value.get("not_before"), "not_before"),
            expires_at=_timestamp(value.get("expires_at"), "expires_at"),
            sha256=digest,
        )

    def as_prompt_record(self) -> dict[str, str]:
        """Minimal portable content record. This is *data*, never instructions."""
        return {
            "id": self.id,
            "title": self.title,
            "source": self.source,
            "version": self.version,
            "content": self.content,
        }


@dataclass(frozen=True)
class Requirement:
    id: str
    any_of: tuple[str, ...]
    min_count: int = 1

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> Requirement:
        if not isinstance(value, dict):
            raise InvalidRequest("each requirement must be an object")
        options = _strings(value.get("any_of"), "requirement.any_of")
        count = value.get("min_count", 1)
        if not options or not isinstance(count, int) or isinstance(count, bool):
            raise InvalidRequest("requirement needs any_of and an integer min_count")
        if count < 1 or count > len(set(options)):
            raise InvalidRequest("requirement.min_count must fit distinct any_of ids")
        return cls(_nonempty(value.get("id"), "requirement.id"), options, count)


@dataclass(frozen=True)
class CompilationRequest:
    task: str
    principal: Principal
    items: tuple[ContextItem, ...]
    budget_tokens: int
    requirements: tuple[Requirement, ...] = ()
    pinned_ids: tuple[str, ...] = ()
    task_classification: str = "internal"

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> CompilationRequest:
        if not isinstance(value, dict):
            raise InvalidRequest("request must be an object")
        task = _nonempty(value.get("task"), "task", MAX_TASK_CHARS)
        budget = value.get("budget_tokens", 2048)
        if not isinstance(budget, int) or isinstance(budget, bool) or not 64 <= budget <= 100_000:
            raise InvalidRequest("budget_tokens must be an integer between 64 and 100000")
        items_raw = value.get("items", [])
        req_raw = value.get("requirements", [])
        if not isinstance(items_raw, list) or not isinstance(req_raw, list):
            raise InvalidRequest("items and requirements must be lists")
        items = tuple(ContextItem.parse(item) for item in items_raw)
        ids = [item.id for item in items]
        if len(set(ids)) != len(ids):
            raise InvalidRequest("duplicate context item ids")
        requirements = tuple(Requirement.parse(req) for req in req_raw)
        if len({req.id for req in requirements}) != len(requirements):
            raise InvalidRequest("duplicate requirement ids")
        sensitivity = value.get("task_classification", "internal")
        if sensitivity not in LEVELS:
            raise InvalidRequest("invalid task_classification")
        return cls(
            task=task,
            principal=Principal.parse(value.get("principal")),
            items=items,
            budget_tokens=budget,
            requirements=requirements,
            pinned_ids=_strings(value.get("pinned_ids", []), "pinned_ids"),
            task_classification=sensitivity,
        )
