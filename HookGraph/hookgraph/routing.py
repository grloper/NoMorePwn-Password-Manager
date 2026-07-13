"""Routing rules — the conditional edges of the HookGraph graph.

Kept separate from node handlers so control-flow policy (when to retry, when
to give up, when to ship) can evolve without touching agent logic.
"""

from __future__ import annotations

from typing import Literal

from .state import HookGraphState

RouteDecision = Literal["hook_extractor", "package_compiler"]


def route_after_quality_control(state: HookGraphState) -> RouteDecision:
    """Decide where the pipeline goes after a QualityControl evaluation.

    - PASS  -> ``package_compiler`` (the compilation stage).
    - FAIL  -> ``hook_extractor`` with the violation payload left in
      ``active_violations`` for targeted repair.
    - FAIL with the retry budget exhausted -> ``package_compiler`` anyway;
      the compiler flags every package ``requires_human_review`` so a broken
      transcript degrades loudly instead of looping forever.
    """
    last_report = state["qc_reports"][-1]
    if last_report.passed:
        return "package_compiler"
    if state["extraction_attempts"] >= state["max_extraction_attempts"]:
        return "package_compiler"
    return "hook_extractor"
