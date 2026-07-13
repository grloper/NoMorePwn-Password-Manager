"""PackageCompiler node — the terminal compilation stage.

Assembles everything QualityControl approved into shippable ``ClipPackage``
deliverables: the hook, its caption track, its tri-platform metadata, and a
render manifest a downstream video worker (or a human editor) can execute
directly. If the pipeline arrived here degraded (QC retries exhausted), every
package is flagged ``requires_human_review`` instead of silently shipping.
"""

from __future__ import annotations

import shlex

from langchain_core.runnables import RunnableConfig

from ..state import ClipPackage, HookCandidate, RenderManifest, SourceVideo, HookGraphState


def _build_render_manifest(hook: HookCandidate, source: SourceVideo) -> RenderManifest:
    srt_filename = f"{source.video_id}_{hook.hook_id}.srt"
    source_file = f"{source.video_id}.mp4"
    output_file = f"{source.video_id}_{hook.hook_id}_vertical.mp4"
    ffmpeg_command = (
        f"ffmpeg -ss {hook.start_seconds:.3f} -to {hook.end_seconds:.3f} "
        f"-i {shlex.quote(source_file)} "
        f"-vf \"crop=ih*9/16:ih,scale=1080:1920,"
        f"subtitles={srt_filename}:force_style='Fontsize=14,Alignment=2,MarginV=60'\" "
        f"-c:v libx264 -preset medium -crf 20 -c:a aac -b:a 160k "
        f"{shlex.quote(output_file)}"
    )
    return RenderManifest(
        source_video_id=source.video_id,
        clip_in=round(hook.start_seconds, 3),
        clip_out=round(hook.end_seconds, 3),
        srt_filename=srt_filename,
        ffmpeg_command=ffmpeg_command,
    )


def package_compiler_node(state: HookGraphState, config: RunnableConfig) -> dict:
    """LangGraph node handler: compile approved artifacts into final packages."""
    source = state["source_video"]
    tracks = {track.hook_id: track for track in state["caption_tracks"]}
    metadata = {package.hook_id: package for package in state["metadata_packages"]}
    last_report = state["qc_reports"][-1] if state["qc_reports"] else None
    degraded = last_report is None or not last_report.passed

    packages: list[ClipPackage] = []
    for hook in sorted(state["hooks"], key=lambda hook: hook.rank):
        track = tracks.get(hook.hook_id)
        package = metadata.get(hook.hook_id)
        if track is None or package is None:
            continue
        packages.append(
            ClipPackage(
                hook=hook,
                captions=track,
                metadata=package,
                render=_build_render_manifest(hook, source),
                requires_human_review=degraded,
            )
        )

    status = (
        "flagged for human review (QC retries exhausted)" if degraded else "fully QC-approved"
    )
    event = (
        f"[PackageCompiler] Compiled {len(packages)} short-form clip packages "
        f"({status}) totalling "
        f"{sum(package.hook.duration_seconds for package in packages):.0f}s of vertical content."
    )
    return {
        "final_packages": packages,
        "pipeline_degraded": degraded,
        "pipeline_events": [event],
    }
