"""Deterministic case replay, designed to discourage compression-only evaluation."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cse.compiler import ContextCompiler
from cse.models import CompilationRequest, InvalidRequest


def evaluate(compiler: ContextCompiler, path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise InvalidRequest("benchmark file must be a nonempty JSON array")
    reports = []
    for case in data:
        req = CompilationRequest.parse(case["request"])
        result = compiler.compile(req)
        selected = set(result.selected_ids)
        expected_include = set(case.get("must_include", []))
        expected_exclude = set(case.get("must_exclude", []))
        expected_status = case.get("expected_status", "ready")
        success = (
            result.status == expected_status and expected_include.issubset(selected)
            and not (selected & expected_exclude) and result.estimated_tokens <= req.budget_tokens
        )
        reports.append({
            "name": case.get("name", "unnamed"),
            "passed": success,
            "status": result.status,
            "estimated_tokens": result.estimated_tokens,
            "selected_count": len(selected),
        })
    return {
        "cases": len(reports),
        "pass_count": sum(case["passed"] for case in reports),
        "pass_rate": sum(case["passed"] for case in reports) / len(reports),
        "results": reports,
        "warning": "case replay only; not a held-out downstream LLM quality or leakage audit",
    }
