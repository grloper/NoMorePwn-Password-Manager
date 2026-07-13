"""HookExtractor node — finds the top 3 highest-retention clip windows.

First pass: score every transcript segment, pick the strongest non-adjacent
retention peaks, and expand each peak outward to its *natural narrative arc*
(neighbors keep getting absorbed while they stay retention-relevant). The
extractor deliberately optimizes for story completeness, not platform limits —
enforcing the 60-second ceiling is QualityControl's job, which is what makes
the corrective feedback edge meaningful.

Repair pass: when QualityControl routes back with ``active_violations``, only
the offending hooks are re-emitted (the upsert reducer keeps passing hooks
untouched). Each violation's ``rule`` maps to a concrete repair strategy:
trim low-value edge segments, re-anchor on a punchier opening, or shift a
window off its neighbor.
"""

from __future__ import annotations

from langchain_core.runnables import RunnableConfig

from ..analysis import (
    SegmentScore,
    is_punchy_opening,
    opening_punchiness,
    score_segments,
    top_keywords,
)
from ..state import (
    HookCandidate,
    PeakType,
    QCViolation,
    ScoreBreakdown,
    TranscriptSegment,
    HookGraphState,
)

TOP_HOOK_COUNT = 3
NARRATIVE_ARC_CAP_SECONDS = 95.0   # first-pass cap: full story beat
PLATFORM_CAP_SECONDS = 58.0        # repair-pass cap: safely under the 60s rubric
EXPANSION_KEEP_RATIO = 0.55        # neighbor must retain >=55% of peak retention
MIN_PEAK_GAP_SEGMENTS = 4          # candidate peaks must be spread apart

_TITLE_TEMPLATES: dict[PeakType, tuple[str, ...]] = {
    "emotional_spike": (
        "The {kw} Moment Nobody Saw Coming",
        "This {kw} Confession Changes Everything",
        "Why {kw} Nearly Broke Him",
    ),
    "semantic_density": (
        "The {kw} Framework Explained in 60 Seconds",
        "Steal This {kw} Playbook",
        "How {kw} Actually Works",
    ),
    "topic_transition": (
        "Wait — {kw} Is Not What You Think",
        "The {kw} Plot Twist",
        "From Zero to {kw}: The Pivot",
    ),
}


def _segment_index(transcript: list[TranscriptSegment]) -> dict[int, int]:
    """Map segment_id -> position in the transcript list."""
    return {segment.segment_id: position for position, segment in enumerate(transcript)}


def _window_duration(transcript: list[TranscriptSegment], lo: int, hi: int) -> float:
    return transcript[hi].end - transcript[lo].start


def _expand_window(
    transcript: list[TranscriptSegment],
    scores: list[SegmentScore],
    peak_pos: int,
    max_duration: float,
    claimed: set[int],
) -> tuple[int, int]:
    """Grow [lo, hi] around a peak while neighbors stay retention-relevant.

    Greedy symmetric expansion: at each step absorb whichever unclaimed
    neighbor has the higher retention, stopping when both fall below the keep
    ratio, the duration budget is spent, or a neighbor already belongs to
    another hook.
    """
    peak_retention = scores[peak_pos].retention
    floor = peak_retention * EXPANSION_KEEP_RATIO
    lo = hi = peak_pos
    while True:
        left = lo - 1 if lo - 1 >= 0 and (lo - 1) not in claimed else None
        right = hi + 1 if hi + 1 < len(transcript) and (hi + 1) not in claimed else None
        left_score = scores[left].retention if left is not None else -1.0
        right_score = scores[right].retention if right is not None else -1.0

        candidates: list[tuple[float, str]] = []
        if left is not None and left_score >= floor:
            candidates.append((left_score, "left"))
        if right is not None and right_score >= floor:
            candidates.append((right_score, "right"))
        if not candidates:
            break

        best_score, direction = max(candidates)
        new_lo, new_hi = (lo - 1, hi) if direction == "left" else (lo, hi + 1)
        if _window_duration(transcript, new_lo, new_hi) > max_duration:
            # Try the other direction before giving up on expansion entirely.
            if len(candidates) == 2:
                direction = "right" if direction == "left" else "left"
                new_lo, new_hi = (lo - 1, hi) if direction == "left" else (lo, hi + 1)
                if _window_duration(transcript, new_lo, new_hi) > max_duration:
                    break
            else:
                break
        lo, hi = new_lo, new_hi
    return lo, hi


def _trim_window_to_duration(
    transcript: list[TranscriptSegment],
    scores: list[SegmentScore],
    lo: int,
    hi: int,
    max_duration: float,
) -> tuple[int, int]:
    """Shrink a window under a duration cap by shedding the weaker edge first."""
    while lo < hi and _window_duration(transcript, lo, hi) > max_duration:
        if scores[lo].retention <= scores[hi].retention:
            lo += 1
        else:
            hi -= 1
    return lo, hi


def _anchor_on_punchy_start(
    transcript: list[TranscriptSegment],
    scores: list[SegmentScore],
    lo: int,
    hi: int,
) -> tuple[int, int]:
    """Advance the window start to the punchiest early segment.

    Vertical clips live or die in the first second, so the clip must open on
    the strongest available line within the front of the window.
    """
    search_hi = min(hi, lo + 3)
    best = lo
    best_punch = opening_punchiness(transcript[lo].text)
    for position in range(lo + 1, search_hi + 1):
        punch = opening_punchiness(transcript[position].text)
        if punch > best_punch + 1e-9:
            best, best_punch = position, punch
    return best, hi


def _make_hook(
    transcript: list[TranscriptSegment],
    scores: list[SegmentScore],
    hook_id: str,
    rank: int,
    lo: int,
    hi: int,
    revision: int,
) -> HookCandidate:
    """Assemble a fully-scored HookCandidate from a segment window."""
    window_segments = transcript[lo : hi + 1]
    window_scores = scores[lo : hi + 1]
    count = len(window_scores)

    avg_density = sum(score.semantic_density for score in window_scores) / count
    avg_emotion = sum(score.emotional_intensity for score in window_scores) / count
    avg_novelty = sum(score.topic_novelty for score in window_scores) / count
    punch = opening_punchiness(window_segments[0].text)

    # The clip inherits its type from the retention peak that earned it a slot:
    # the classification is z-scored against the whole episode in analysis.py.
    peak_position = max(range(count), key=lambda position: window_scores[position].retention)
    peak_type = window_scores[peak_position].peak_type
    peak_start = window_segments[peak_position].start

    raw = 0.30 * avg_density + 0.34 * avg_emotion + 0.16 * avg_novelty + 0.20 * punch
    virality = round(min(100.0, raw * 145.0), 1)

    window_text = " ".join(segment.text for segment in window_segments)
    keywords = top_keywords(window_text, limit=3)
    keyword = (keywords[0] if keywords else "this").replace("-", " ").title()
    template = _TITLE_TEMPLATES[peak_type][(rank - 1) % len(_TITLE_TEMPLATES[peak_type])]
    title = template.format(kw=keyword)[:80]

    duration = _window_duration(transcript, lo, hi)
    justification = (
        f"Retention composite {virality:.1f}/100 across {count} segments "
        f"({duration:.1f}s): semantic density {avg_density:.2f}, emotional "
        f"intensity {avg_emotion:.2f}, topic novelty {avg_novelty:.2f}, and an "
        f"opening-punch score of {punch:.2f} on the first line "
        f"('{window_segments[0].text[:60].strip()}…'). The retention peak at "
        f"{peak_start:.0f}s registers as {peak_type.replace('_', ' ')} against "
        f"the episode baseline."
    )

    return HookCandidate(
        hook_id=hook_id,
        rank=rank,
        hook_title=title,
        virality_score=virality,
        virality_justification=justification,
        peak_type=peak_type,
        start_seconds=window_segments[0].start,
        end_seconds=window_segments[-1].end,
        segment_ids=[segment.segment_id for segment in window_segments],
        opening_line=window_segments[0].text,
        score_breakdown=ScoreBreakdown(
            semantic_density=round(min(1.0, avg_density), 4),
            emotional_intensity=round(min(1.0, avg_emotion), 4),
            topic_novelty=round(min(1.0, avg_novelty), 4),
            opening_punch=round(min(1.0, punch), 4),
        ),
        revision=revision,
    )


def _extract_fresh(
    transcript: list[TranscriptSegment],
    scores: list[SegmentScore],
    max_window_seconds: float = NARRATIVE_ARC_CAP_SECONDS,
) -> list[HookCandidate]:
    """First-pass extraction: top peaks expanded to their narrative arcs.

    Peaks are selected and expanded in one greedy pass over the retention
    ranking: a candidate peak that already fell inside a claimed window is
    skipped in favor of the next-best unclaimed peak, which structurally
    guarantees the three windows never overlap.
    """
    ranked_peaks = sorted(scores, key=lambda score: -score.retention)
    positions = _segment_index(transcript)

    claimed: set[int] = set()
    chosen_peaks: list[int] = []
    windows: list[tuple[int, int, int]] = []  # (peak_pos, lo, hi)
    for peak in ranked_peaks:
        position = positions[peak.segment_id]
        if position in claimed:
            continue
        if any(abs(position - other) < MIN_PEAK_GAP_SEGMENTS for other in chosen_peaks):
            continue
        lo, hi = _expand_window(transcript, scores, position, max_window_seconds, claimed)
        lo, _ = _anchor_on_punchy_start(transcript, scores, lo, hi)
        claimed.update(range(lo, hi + 1))
        chosen_peaks.append(position)
        windows.append((position, lo, hi))
        if len(windows) == TOP_HOOK_COUNT:
            break

    # Rank hooks by their peak segment's retention (strongest peak = rank 1).
    windows.sort(key=lambda window: -scores[window[0]].retention)
    return [
        _make_hook(transcript, scores, f"hook-{rank}", rank, lo, hi, revision=0)
        for rank, (_, lo, hi) in enumerate(windows, start=1)
    ]


def _repair_hook(
    hook: HookCandidate,
    violations: list[QCViolation],
    transcript: list[TranscriptSegment],
    scores: list[SegmentScore],
    sibling_windows: dict[str, tuple[float, float]],
) -> HookCandidate:
    """Apply rule-specific repairs to a failing hook, preserving its identity."""
    positions = _segment_index(transcript)
    lo = positions[hook.segment_ids[0]]
    hi = positions[hook.segment_ids[-1]]
    rules = {violation.rule for violation in violations}

    if "non_overlapping_times" in rules:
        # Shrink away from whichever sibling this window collides with.
        for other_id, (other_start, other_end) in sibling_windows.items():
            if other_id == hook.hook_id:
                continue
            while lo < hi and transcript[lo].start < other_end and transcript[hi].end > other_start:
                if transcript[lo].start >= other_start:
                    lo += 1
                else:
                    hi -= 1

    if "duration_under_60s" in rules or _window_duration(transcript, lo, hi) > PLATFORM_CAP_SECONDS:
        lo, hi = _trim_window_to_duration(transcript, scores, lo, hi, PLATFORM_CAP_SECONDS)

    if "punchy_opening_line" in rules or not is_punchy_opening(transcript[lo].text):
        lo, _ = _anchor_on_punchy_start(transcript, scores, lo, hi)
        # Re-anchoring never repairs a too-long window, so re-check duration.
        lo, hi = _trim_window_to_duration(transcript, scores, lo, hi, PLATFORM_CAP_SECONDS)

    return _make_hook(
        transcript, scores, hook.hook_id, hook.rank, lo, hi, revision=hook.revision + 1
    )


def hook_extractor_node(state: HookGraphState, config: RunnableConfig) -> dict:
    """LangGraph node handler: fresh extraction or violation-driven repair."""
    transcript = state["transcript"]
    scores = score_segments(transcript)
    attempt = state["extraction_attempts"] + 1
    violations = state["active_violations"]

    structural_failure = any(
        violation.rule == "exactly_three_hooks" for violation in violations
    )
    if not violations or not state["hooks"] or structural_failure:
        # A structural failure means the wide narrative-arc windows could not
        # coexist; retry the whole extraction with tight platform-sized windows.
        cap = PLATFORM_CAP_SECONDS if structural_failure else NARRATIVE_ARC_CAP_SECONDS
        hooks = _extract_fresh(transcript, scores, max_window_seconds=cap)
        events = [
            f"[HookExtractor] Attempt {attempt}: scored {len(transcript)} segments and "
            f"extracted {len(hooks)} hooks (window cap {cap:.0f}s): "
            + "; ".join(
                f"{hook.hook_id} '{hook.hook_title}' "
                f"({hook.start_seconds:.0f}s-{hook.end_seconds:.0f}s, "
                f"score {hook.virality_score})"
                for hook in hooks
            )
        ]
        return {
            "hooks": hooks,
            "extraction_attempts": attempt,
            "active_violations": [],
            "pipeline_events": events,
        }

    # Repair pass: only touch the hooks QualityControl flagged.
    by_hook: dict[str, list[QCViolation]] = {}
    for violation in violations:
        by_hook.setdefault(violation.hook_id, []).append(violation)

    current = {hook.hook_id: hook for hook in state["hooks"]}
    sibling_windows = {
        hook.hook_id: (hook.start_seconds, hook.end_seconds)
        for hook in state["hooks"]
        if hook.hook_id not in by_hook  # only healthy siblings constrain repairs
    }

    repaired: list[HookCandidate] = []
    events: list[str] = []
    for hook_id, hook_violations in sorted(by_hook.items()):
        if hook_id not in current:
            continue
        fixed = _repair_hook(current[hook_id], hook_violations, transcript, scores, sibling_windows)
        sibling_windows[fixed.hook_id] = (fixed.start_seconds, fixed.end_seconds)
        repaired.append(fixed)
        applied = ", ".join(sorted({violation.rule for violation in hook_violations}))
        events.append(
            f"[HookExtractor] Attempt {attempt}: repaired {hook_id} (rev "
            f"{fixed.revision}) for [{applied}] -> now "
            f"{fixed.start_seconds:.0f}s-{fixed.end_seconds:.0f}s "
            f"({fixed.duration_seconds:.1f}s), opening line "
            f"'{fixed.opening_line[:50].strip()}…'"
        )

    return {
        "hooks": repaired,  # upsert reducer merges these over the failing ones
        "extraction_attempts": attempt,
        "active_violations": [],
        "pipeline_events": events,
    }
