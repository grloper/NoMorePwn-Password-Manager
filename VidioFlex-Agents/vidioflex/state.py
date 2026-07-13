"""State schema layer for the VidioFlex-Agents graph.

Every value that flows across a graph edge is declared here. The module has three
sections:

1. Pydantic payload models — the typed media/content artifacts the agents exchange.
2. Reducer functions — custom accumulators wired into ``Annotated`` state channels
   so concurrent or repeated node writes merge instead of clobbering each other.
3. ``VidioFlexState`` — the TypedDict LangGraph compiles the graph against.
"""

from __future__ import annotations

import operator
from typing import Annotated, Literal, Optional, TypedDict

from pydantic import BaseModel, Field, model_validator

PeakType = Literal["semantic_density", "emotional_spike", "topic_transition"]
Platform = Literal["youtube_shorts", "tiktok", "instagram_reels"]
Severity = Literal["blocker", "warning"]


# ---------------------------------------------------------------------------
# Section 1 — Pydantic payload models
# ---------------------------------------------------------------------------


class TranscriptSegment(BaseModel):
    """One timed utterance from the master landscape-video transcript."""

    segment_id: int = Field(ge=0)
    start: float = Field(ge=0.0, description="Segment start in seconds from video start.")
    end: float = Field(gt=0.0, description="Segment end in seconds from video start.")
    speaker: str
    text: str = Field(min_length=1)

    @model_validator(mode="after")
    def _check_bounds(self) -> "TranscriptSegment":
        if self.end <= self.start:
            raise ValueError(
                f"segment {self.segment_id}: end ({self.end}) must be after start ({self.start})"
            )
        return self

    @property
    def duration(self) -> float:
        return self.end - self.start


class SourceVideo(BaseModel):
    """Metadata for the full-length landscape source video."""

    video_id: str
    title: str
    duration_seconds: float = Field(gt=0.0)
    language: str = "en"
    creator_handle: str = "@vidioflex"


class ScoreBreakdown(BaseModel):
    """Sub-scores backing a hook's virality score, kept for auditability."""

    semantic_density: float = Field(ge=0.0, le=1.0)
    emotional_intensity: float = Field(ge=0.0, le=1.0)
    topic_novelty: float = Field(ge=0.0, le=1.0)
    opening_punch: float = Field(ge=0.0, le=1.0)


class HookCandidate(BaseModel):
    """A high-retention clip window proposed by the HookExtractor agent."""

    hook_id: str = Field(pattern=r"^hook-\d+$")
    rank: int = Field(ge=1, le=3)
    hook_title: str = Field(min_length=1, max_length=80)
    virality_score: float = Field(ge=0.0, le=100.0)
    virality_justification: str = Field(min_length=1)
    peak_type: PeakType
    start_seconds: float = Field(ge=0.0)
    end_seconds: float = Field(gt=0.0)
    segment_ids: list[int]
    opening_line: str
    score_breakdown: ScoreBreakdown
    revision: int = Field(default=0, ge=0)

    @property
    def duration_seconds(self) -> float:
        return self.end_seconds - self.start_seconds


class CaptionCue(BaseModel):
    """A single clip-relative caption cue (one on-screen text unit)."""

    index: int = Field(ge=1)
    start_seconds: float = Field(ge=0.0)
    end_seconds: float = Field(gt=0.0)
    text: str = Field(min_length=1)


class CaptionTrack(BaseModel):
    """Timestamp-synced vertical caption sequence for one hook clip."""

    hook_id: str
    hook_revision: int
    cues: list[CaptionCue]
    srt: str = Field(description="The cue list rendered as a ready-to-burn SRT document.")


class PlatformVariant(BaseModel):
    """Platform-specific metadata variation for one clip."""

    platform: Platform
    title: str
    description: str
    hashtags: list[str]
    seo_tags: list[str] = Field(default_factory=list)
    trend_tags: list[str] = Field(default_factory=list)
    sound_suggestion: Optional[str] = None
    call_to_action: str


class MetadataPackage(BaseModel):
    """All platform variants for one hook clip."""

    hook_id: str
    hook_revision: int
    variants: list[PlatformVariant]


class QCViolation(BaseModel):
    """A single rubric failure, with an explicit machine-actionable remediation hint."""

    hook_id: str
    rule: str
    severity: Severity
    message: str
    remediation: str


class QCReport(BaseModel):
    """The audit record of one QualityControl evaluation pass."""

    attempt: int = Field(ge=1)
    passed: bool
    violations: list[QCViolation]
    checked_hook_ids: list[str]
    summary: str


class RenderManifest(BaseModel):
    """Instructions a downstream render worker needs to cut the vertical clip."""

    source_video_id: str
    clip_in: float
    clip_out: float
    aspect_ratio: str = "9:16"
    target_resolution: str = "1080x1920"
    crop_strategy: str = "speaker-centered auto-reframe"
    srt_filename: str
    ffmpeg_command: str


class ClipPackage(BaseModel):
    """The final compiled deliverable for one short-form clip."""

    hook: HookCandidate
    captions: CaptionTrack
    metadata: MetadataPackage
    render: RenderManifest
    requires_human_review: bool = False


# ---------------------------------------------------------------------------
# Section 2 — Reducer functions (custom state accumulators)
# ---------------------------------------------------------------------------


def _upsert_by_hook_id(existing: list, incoming: list) -> list:
    """Merge two lists of hook-keyed models by upserting on ``hook_id``.

    LangGraph calls reducers with the channel's current value and a node's
    partial update. A plain overwrite would clobber sibling hooks whenever the
    HookExtractor re-emits only the hooks that failed QC, so instead:

    - an incoming item replaces the existing item with the same ``hook_id``;
    - unseen ``hook_id``s are appended;
    - the merged list is returned sorted by ``hook_id`` for determinism.
    """
    if not existing:
        merged = {item.hook_id: item for item in incoming}
    else:
        merged = {item.hook_id: item for item in existing}
        for item in incoming:
            merged[item.hook_id] = item
    return [merged[key] for key in sorted(merged)]


def merge_hooks(
    existing: list[HookCandidate], incoming: list[HookCandidate]
) -> list[HookCandidate]:
    """Accumulator for the ``hooks`` channel: upsert by hook_id, never clobber."""
    return _upsert_by_hook_id(existing, incoming)


def merge_caption_tracks(
    existing: list[CaptionTrack], incoming: list[CaptionTrack]
) -> list[CaptionTrack]:
    """Accumulator for the ``caption_tracks`` channel: upsert by hook_id."""
    return _upsert_by_hook_id(existing, incoming)


def merge_metadata_packages(
    existing: list[MetadataPackage], incoming: list[MetadataPackage]
) -> list[MetadataPackage]:
    """Accumulator for the ``metadata_packages`` channel: upsert by hook_id."""
    return _upsert_by_hook_id(existing, incoming)


def replace_value(existing: object, incoming: object) -> object:
    """Explicit last-write-wins reducer for single-slot control channels."""
    return incoming


# ---------------------------------------------------------------------------
# Section 3 — The graph state
# ---------------------------------------------------------------------------


class VidioFlexState(TypedDict):
    """The full structural payload threaded through every node.

    Channels with ``Annotated[..., reducer]`` accumulate across node writes;
    the rest are plain last-write-wins channels.
    """

    # Immutable inputs
    source_video: SourceVideo
    transcript: list[TranscriptSegment]

    # Content artifacts (accumulated with upsert reducers)
    hooks: Annotated[list[HookCandidate], merge_hooks]
    caption_tracks: Annotated[list[CaptionTrack], merge_caption_tracks]
    metadata_packages: Annotated[list[MetadataPackage], merge_metadata_packages]

    # Quality-control loop channels
    qc_reports: Annotated[list[QCReport], operator.add]
    active_violations: Annotated[list[QCViolation], replace_value]
    extraction_attempts: Annotated[int, replace_value]
    max_extraction_attempts: int

    # Final compiled output
    final_packages: list[ClipPackage]
    pipeline_degraded: bool

    # Human-readable execution narration (append-only audit log)
    pipeline_events: Annotated[list[str], operator.add]


def initial_state(
    source_video: SourceVideo,
    transcript: list[TranscriptSegment],
    max_extraction_attempts: int = 4,
) -> VidioFlexState:
    """Build a fully-populated initial state for a graph invocation."""
    return VidioFlexState(
        source_video=source_video,
        transcript=sorted(transcript, key=lambda seg: seg.start),
        hooks=[],
        caption_tracks=[],
        metadata_packages=[],
        qc_reports=[],
        active_violations=[],
        extraction_attempts=0,
        max_extraction_attempts=max_extraction_attempts,
        final_packages=[],
        pipeline_degraded=False,
        pipeline_events=[
            f"Pipeline initialized for '{source_video.title}' "
            f"({source_video.duration_seconds:.0f}s, {len(transcript)} transcript segments)."
        ],
    )
