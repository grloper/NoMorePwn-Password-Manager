"""Scriptwriter node — caption sequencing and platform metadata drafting.

For every current hook it produces:

1. A pristine, timestamp-synced caption track. Source segments are rebased to
   clip-relative time, split into short vertical-friendly cues (max 42 chars),
   and each cue's duration is prorated by word count so text stays glued to
   speech. The track is also rendered to a ready-to-burn SRT document.
2. A metadata package with per-platform variations: SEO-driven tags and
   descriptions for YouTube Shorts, sound/trend tags for TikTok, and
   save-oriented hashtag stacks for Instagram Reels.

The node is idempotent per (hook_id, revision): repaired hooks get fresh
tracks/packages and the upsert reducers replace the stale ones in state.
"""

from __future__ import annotations

from langchain_core.runnables import RunnableConfig

from ..analysis import top_keywords
from ..state import (
    CaptionCue,
    CaptionTrack,
    HookCandidate,
    MetadataPackage,
    PlatformVariant,
    SourceVideo,
    TranscriptSegment,
    HookGraphState,
)

MAX_CUE_CHARS = 42
MIN_CUE_SECONDS = 0.7

_SOUND_MOODS = {
    "emotional_spike": "trending dramatic build-up audio (slow rise, hard drop)",
    "semantic_density": "lo-fi focus beat, low-volume bed under voice",
    "topic_transition": "record-scratch transition sting into ambient pad",
}


def _chunk_text(text: str, max_chars: int) -> list[str]:
    """Split an utterance into caption-sized chunks on word boundaries."""
    words = text.split()
    chunks: list[str] = []
    current: list[str] = []
    length = 0
    for word in words:
        added = len(word) + (1 if current else 0)
        if current and length + added > max_chars:
            chunks.append(" ".join(current))
            current, length = [word], len(word)
        else:
            current.append(word)
            length += added
    if current:
        chunks.append(" ".join(current))
    return chunks


def _format_srt_timestamp(seconds: float) -> str:
    total_ms = int(round(seconds * 1000))
    hours, remainder = divmod(total_ms, 3_600_000)
    minutes, remainder = divmod(remainder, 60_000)
    secs, millis = divmod(remainder, 1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d},{millis:03d}"


def _render_srt(cues: list[CaptionCue]) -> str:
    blocks = [
        f"{cue.index}\n"
        f"{_format_srt_timestamp(cue.start_seconds)} --> {_format_srt_timestamp(cue.end_seconds)}\n"
        f"{cue.text}"
        for cue in cues
    ]
    return "\n\n".join(blocks) + "\n"


def _build_caption_track(
    hook: HookCandidate, segments_by_id: dict[int, TranscriptSegment]
) -> CaptionTrack:
    """Rebase the hook's segments to clip time and cut them into timed cues."""
    cues: list[CaptionCue] = []
    index = 1
    clip_start = hook.start_seconds
    for segment_id in hook.segment_ids:
        segment = segments_by_id[segment_id]
        chunks = _chunk_text(segment.text, MAX_CUE_CHARS)
        if not chunks:
            continue
        total_words = sum(len(chunk.split()) for chunk in chunks)
        seg_start = segment.start - clip_start
        seg_duration = segment.end - segment.start
        cursor = seg_start
        for position, chunk in enumerate(chunks):
            share = len(chunk.split()) / total_words
            duration = max(MIN_CUE_SECONDS, seg_duration * share)
            end = min(seg_start + seg_duration, cursor + duration)
            if position == len(chunks) - 1:
                end = seg_start + seg_duration
            if end - cursor < 0.05:
                end = cursor + 0.05
            cues.append(
                CaptionCue(
                    index=index,
                    start_seconds=round(max(0.0, cursor), 3),
                    end_seconds=round(end, 3),
                    text=chunk,
                )
            )
            cursor = end
            index += 1
    return CaptionTrack(
        hook_id=hook.hook_id,
        hook_revision=hook.revision,
        cues=cues,
        srt=_render_srt(cues),
    )


def _hashtagify(keyword: str) -> str:
    return "#" + "".join(part.capitalize() for part in keyword.replace("-", " ").split())


def _build_metadata_package(
    hook: HookCandidate,
    source: SourceVideo,
    segments_by_id: dict[int, TranscriptSegment],
) -> MetadataPackage:
    """Draft the three platform-specific metadata variants for one hook."""
    clip_text = " ".join(segments_by_id[segment_id].text for segment_id in hook.segment_ids)
    keywords = top_keywords(clip_text, limit=6) or ["viral", "clips"]
    primary = keywords[0]
    topic_tags = [_hashtagify(keyword) for keyword in keywords[:4]]
    duration = f"{hook.duration_seconds:.0f}s"

    youtube = PlatformVariant(
        platform="youtube_shorts",
        title=f"{hook.hook_title} #Shorts"[:100],
        description=(
            f"{hook.opening_line.strip()}\n\n"
            f"Clipped from \"{source.title}\" — the full breakdown of {primary} "
            f"is on the channel. This {duration} moment covers: "
            f"{', '.join(keywords[:4])}.\n\n"
            f"Subscribe for the full-length episodes.\n"
            f"{' '.join(['#Shorts'] + topic_tags)}"
        ),
        hashtags=["#Shorts"] + topic_tags,
        seo_tags=keywords + [source.title.lower(), "short form", "viral clips"],
        trend_tags=[],
        sound_suggestion=None,
        call_to_action="Subscribe for the full episode breakdown.",
    )

    tiktok = PlatformVariant(
        platform="tiktok",
        title=hook.hook_title[:80],
        description=(
            f"{hook.hook_title} 👀 wait for the {primary} part "
            f"{' '.join(['#fyp', '#foryou'] + topic_tags[:3])}"
        )[:150],
        hashtags=["#fyp", "#foryou", "#LearnOnTikTok"] + topic_tags[:3],
        seo_tags=[],
        trend_tags=[f"{primary}tok", "storytime", "didyouknow"],
        sound_suggestion=_SOUND_MOODS[hook.peak_type],
        call_to_action="Follow — part 2 drops tomorrow.",
    )

    instagram = PlatformVariant(
        platform="instagram_reels",
        title=hook.hook_title[:80],
        description=(
            f"{hook.hook_title}\n.\n"
            f"{hook.opening_line.strip()}\n.\n"
            f"Save this one — the {primary} details matter. Full episode: "
            f"\"{source.title}\" (link in bio).\n"
            f"{' '.join(topic_tags + ['#Reels', '#Explore'])}"
        ),
        hashtags=topic_tags + ["#Reels", "#Explore", "#" + primary.capitalize()],
        seo_tags=[],
        trend_tags=[],
        sound_suggestion="original audio (voice-forward mix)",
        call_to_action="Save this for later & share it with one person.",
    )

    return MetadataPackage(
        hook_id=hook.hook_id,
        hook_revision=hook.revision,
        variants=[youtube, tiktok, instagram],
    )


def scriptwriter_node(state: HookGraphState, config: RunnableConfig) -> dict:
    """LangGraph node handler: (re)draft captions + metadata for current hooks."""
    segments_by_id = {segment.segment_id: segment for segment in state["transcript"]}
    existing_tracks = {
        track.hook_id: track.hook_revision for track in state["caption_tracks"]
    }

    tracks: list[CaptionTrack] = []
    packages: list[MetadataPackage] = []
    refreshed: list[str] = []
    for hook in state["hooks"]:
        if existing_tracks.get(hook.hook_id) == hook.revision:
            continue  # artifact already in sync with this hook revision
        tracks.append(_build_caption_track(hook, segments_by_id))
        packages.append(_build_metadata_package(hook, state["source_video"], segments_by_id))
        refreshed.append(f"{hook.hook_id}(rev {hook.revision})")

    total_cues = sum(len(track.cues) for track in tracks)
    event = (
        f"[Scriptwriter] Drafted {len(tracks)} caption tracks ({total_cues} cues) "
        f"and {len(packages)} tri-platform metadata packages for: "
        f"{', '.join(refreshed) if refreshed else 'no hooks (all artifacts current)'}."
    )
    return {
        "caption_tracks": tracks,
        "metadata_packages": packages,
        "pipeline_events": [event],
    }
