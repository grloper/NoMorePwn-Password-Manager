"""Graph compilation block — wires state, nodes, and routing into a runnable app.

Topology::

    START -> hook_extractor -> scriptwriter -> quality_control
                 ^                                   |
                 |            (rubric FAILED,        | (rubric PASSED, or
                 +--- error payload in state --------+  retry budget spent)
                                                     v
                                            package_compiler -> END
"""

from __future__ import annotations

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from .nodes import (
    hook_extractor_node,
    package_compiler_node,
    quality_control_node,
    scriptwriter_node,
)
from .routing import route_after_quality_control
from .state import (
    CaptionCue,
    CaptionTrack,
    ClipPackage,
    HookCandidate,
    MetadataPackage,
    PlatformVariant,
    QCReport,
    QCViolation,
    RenderManifest,
    ScoreBreakdown,
    SourceVideo,
    TranscriptSegment,
    HookGraphState,
)

# Explicit serializer allowlist: every Pydantic model that can appear in a
# checkpoint is registered, so snapshots round-trip without trust-on-first-use
# deserialization warnings (and anything unexpected is loudly blocked).
_STATE_MODELS = (
    CaptionCue,
    CaptionTrack,
    ClipPackage,
    HookCandidate,
    MetadataPackage,
    PlatformVariant,
    QCReport,
    QCViolation,
    RenderManifest,
    ScoreBreakdown,
    SourceVideo,
    TranscriptSegment,
)


def _default_checkpointer() -> InMemorySaver:
    return InMemorySaver(serde=JsonPlusSerializer(allowed_msgpack_modules=_STATE_MODELS))


def build_graph(checkpointer: BaseCheckpointSaver | None = None) -> CompiledStateGraph:
    """Compile the HookGraph pipeline into an executable LangGraph app.

    A checkpointer is always attached (in-memory by default) so every
    super-step — including each QC retry — is durably snapshotted and the run
    can be inspected or resumed by thread id.
    """
    builder = StateGraph(HookGraphState)

    builder.add_node("hook_extractor", hook_extractor_node)
    builder.add_node("scriptwriter", scriptwriter_node)
    builder.add_node("quality_control", quality_control_node)
    builder.add_node("package_compiler", package_compiler_node)

    builder.add_edge(START, "hook_extractor")
    builder.add_edge("hook_extractor", "scriptwriter")
    builder.add_edge("scriptwriter", "quality_control")
    builder.add_conditional_edges(
        "quality_control",
        route_after_quality_control,
        {
            "hook_extractor": "hook_extractor",
            "package_compiler": "package_compiler",
        },
    )
    builder.add_edge("package_compiler", END)

    return builder.compile(checkpointer=checkpointer or _default_checkpointer())
