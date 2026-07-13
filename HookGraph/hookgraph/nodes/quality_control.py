"""QualityControl node — the strict analytical rubric gate.

Evaluates the current hooks and their drafted artifacts against explicit,
machine-checkable rules. Failures are emitted as ``QCViolation`` payloads with
a ``remediation`` hint the HookExtractor can act on mechanically; the routing
layer decides whether the pipeline loops back or proceeds to compilation.

Rubric (blockers unless noted):

- ``exactly_three_hooks``   — the package must contain exactly 3 clips.
- ``duration_under_60s``    — every clip strictly under 60s (and >= 8s so a
                              clip is long enough to carry a story beat).
- ``punchy_opening_line``   — the first line must clear the punchiness gate.
- ``valid_timestamps``      — 0 <= start < end <= source duration, snapped to
                              real transcript segment boundaries.
- ``non_overlapping_times`` — no two clips may share source footage.
- ``metadata_completeness`` — every hook must carry a caption track and all 3
                              platform variants in sync with its revision.
- ``justified_virality``    — score in (0, 100] plus a substantive
                              justification (warning only).
"""

from __future__ import annotations

from langchain_core.runnables import RunnableConfig

from ..analysis import is_punchy_opening
from ..state import HookCandidate, QCReport, QCViolation, HookGraphState

MAX_CLIP_SECONDS = 60.0
MIN_CLIP_SECONDS = 8.0
TIMESTAMP_EPSILON = 0.011
MIN_JUSTIFICATION_CHARS = 40


def _check_hook_count(hooks: list[HookCandidate]) -> list[QCViolation]:
    if len(hooks) == 3:
        return []
    return [
        QCViolation(
            hook_id="package",
            rule="exactly_three_hooks",
            severity="blocker",
            message=f"Expected exactly 3 hooks, found {len(hooks)}.",
            remediation="Re-run extraction to produce exactly 3 ranked hooks.",
        )
    ]


def _check_duration(hook: HookCandidate) -> list[QCViolation]:
    duration = hook.duration_seconds
    if duration >= MAX_CLIP_SECONDS:
        return [
            QCViolation(
                hook_id=hook.hook_id,
                rule="duration_under_60s",
                severity="blocker",
                message=(
                    f"{hook.hook_id} runs {duration:.1f}s; platform ceiling is "
                    f"strictly under {MAX_CLIP_SECONDS:.0f}s."
                ),
                remediation=(
                    "Trim the lowest-retention edge segments until the clip is "
                    "under 60 seconds while preserving the peak."
                ),
            )
        ]
    if duration < MIN_CLIP_SECONDS:
        return [
            QCViolation(
                hook_id=hook.hook_id,
                rule="duration_under_60s",
                severity="blocker",
                message=f"{hook.hook_id} runs {duration:.1f}s; too short to carry a story beat.",
                remediation="Expand the window to at least 8 seconds of contiguous speech.",
            )
        ]
    return []


def _check_punchy_opening(hook: HookCandidate) -> list[QCViolation]:
    if is_punchy_opening(hook.opening_line):
        return []
    return [
        QCViolation(
            hook_id=hook.hook_id,
            rule="punchy_opening_line",
            severity="blocker",
            message=(
                f"{hook.hook_id} opens on a weak line: "
                f"'{hook.opening_line[:70].strip()}…'"
            ),
            remediation=(
                "Re-anchor the clip start on a short, high-punch line (question, "
                "exclamation, power opener, or number) near the retention peak."
            ),
        )
    ]


def _check_timestamps(
    hook: HookCandidate,
    source_duration: float,
    boundaries: dict[int, tuple[float, float]],
) -> list[QCViolation]:
    violations: list[QCViolation] = []

    def flag(message: str, remediation: str) -> None:
        violations.append(
            QCViolation(
                hook_id=hook.hook_id,
                rule="valid_timestamps",
                severity="blocker",
                message=message,
                remediation=remediation,
            )
        )

    if hook.start_seconds >= hook.end_seconds:
        flag(
            f"{hook.hook_id} has start {hook.start_seconds:.2f}s >= end {hook.end_seconds:.2f}s.",
            "Re-extract the window with a positive duration.",
        )
    if hook.end_seconds > source_duration + TIMESTAMP_EPSILON:
        flag(
            f"{hook.hook_id} ends at {hook.end_seconds:.2f}s, past the source "
            f"video end ({source_duration:.2f}s).",
            "Clamp the window inside the source video bounds.",
        )
    if not hook.segment_ids:
        flag(
            f"{hook.hook_id} references no transcript segments.",
            "Rebuild the window from real transcript segments.",
        )
    else:
        first = boundaries.get(hook.segment_ids[0])
        last = boundaries.get(hook.segment_ids[-1])
        if first is None or last is None:
            flag(
                f"{hook.hook_id} references unknown segment ids.",
                "Rebuild the window from real transcript segments.",
            )
        else:
            if abs(hook.start_seconds - first[0]) > TIMESTAMP_EPSILON:
                flag(
                    f"{hook.hook_id} start {hook.start_seconds:.2f}s is not snapped to "
                    f"segment {hook.segment_ids[0]} boundary ({first[0]:.2f}s).",
                    "Snap the clip start to its first segment's start time.",
                )
            if abs(hook.end_seconds - last[1]) > TIMESTAMP_EPSILON:
                flag(
                    f"{hook.hook_id} end {hook.end_seconds:.2f}s is not snapped to "
                    f"segment {hook.segment_ids[-1]} boundary ({last[1]:.2f}s).",
                    "Snap the clip end to its last segment's end time.",
                )
    return violations


def _check_overlaps(hooks: list[HookCandidate]) -> list[QCViolation]:
    violations: list[QCViolation] = []
    ordered = sorted(hooks, key=lambda hook: hook.start_seconds)
    for earlier, later in zip(ordered, ordered[1:]):
        if later.start_seconds < earlier.end_seconds - TIMESTAMP_EPSILON:
            overlap = earlier.end_seconds - later.start_seconds
            violations.append(
                QCViolation(
                    hook_id=later.hook_id,
                    rule="non_overlapping_times",
                    severity="blocker",
                    message=(
                        f"{later.hook_id} overlaps {earlier.hook_id} by {overlap:.1f}s "
                        f"({later.start_seconds:.1f}s < {earlier.end_seconds:.1f}s)."
                    ),
                    remediation=(
                        f"Shift or shrink {later.hook_id} so it starts at or after "
                        f"{earlier.end_seconds:.1f}s."
                    ),
                )
            )
    return violations


def _check_artifact_sync(hook: HookCandidate, state: HookGraphState) -> list[QCViolation]:
    violations: list[QCViolation] = []
    track = next(
        (track for track in state["caption_tracks"] if track.hook_id == hook.hook_id), None
    )
    package = next(
        (
            package
            for package in state["metadata_packages"]
            if package.hook_id == hook.hook_id
        ),
        None,
    )
    if track is None or track.hook_revision != hook.revision or not track.cues:
        violations.append(
            QCViolation(
                hook_id=hook.hook_id,
                rule="metadata_completeness",
                severity="blocker",
                message=f"{hook.hook_id} lacks a caption track in sync with revision {hook.revision}.",
                remediation="Regenerate the caption track for the current hook revision.",
            )
        )
    expected_platforms = {"youtube_shorts", "tiktok", "instagram_reels"}
    if (
        package is None
        or package.hook_revision != hook.revision
        or {variant.platform for variant in package.variants} != expected_platforms
    ):
        violations.append(
            QCViolation(
                hook_id=hook.hook_id,
                rule="metadata_completeness",
                severity="blocker",
                message=(
                    f"{hook.hook_id} lacks a complete tri-platform metadata package "
                    f"in sync with revision {hook.revision}."
                ),
                remediation="Regenerate the metadata package for the current hook revision.",
            )
        )
    return violations


def _check_virality_justification(hook: HookCandidate) -> list[QCViolation]:
    if hook.virality_score > 0 and len(hook.virality_justification) >= MIN_JUSTIFICATION_CHARS:
        return []
    return [
        QCViolation(
            hook_id=hook.hook_id,
            rule="justified_virality",
            severity="warning",
            message=(
                f"{hook.hook_id} has a weak virality rationale "
                f"(score {hook.virality_score}, justification "
                f"{len(hook.virality_justification)} chars)."
            ),
            remediation="Recompute the score breakdown and expand the justification.",
        )
    ]


def quality_control_node(state: HookGraphState, config: RunnableConfig) -> dict:
    """LangGraph node handler: run the full rubric and emit an audit report."""
    hooks = state["hooks"]
    source_duration = state["source_video"].duration_seconds
    boundaries = {
        segment.segment_id: (segment.start, segment.end) for segment in state["transcript"]
    }

    violations: list[QCViolation] = []
    violations += _check_hook_count(hooks)
    for hook in hooks:
        violations += _check_duration(hook)
        violations += _check_punchy_opening(hook)
        violations += _check_timestamps(hook, source_duration, boundaries)
        violations += _check_artifact_sync(hook, state)
        violations += _check_virality_justification(hook)
    violations += _check_overlaps(hooks)

    blockers = [violation for violation in violations if violation.severity == "blocker"]
    passed = not blockers
    attempt = state["extraction_attempts"]

    if passed:
        summary = (
            f"Attempt {attempt} PASSED: {len(hooks)} hooks cleared all rubric rules"
            + (f" ({len(violations)} warnings)." if violations else ".")
        )
    else:
        rules = sorted({violation.rule for violation in blockers})
        summary = (
            f"Attempt {attempt} FAILED with {len(blockers)} blocker(s) across "
            f"rules: {', '.join(rules)}."
        )

    report = QCReport(
        attempt=max(1, attempt),
        passed=passed,
        violations=violations,
        checked_hook_ids=[hook.hook_id for hook in hooks],
        summary=summary,
    )
    return {
        "qc_reports": [report],
        "active_violations": blockers,
        "pipeline_events": [f"[QualityControl] {summary}"],
    }
