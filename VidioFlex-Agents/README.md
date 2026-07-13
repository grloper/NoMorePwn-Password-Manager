# VidioFlex-Agents

**A stateful LangGraph multi-agent pipeline that turns one long-form landscape video
transcript into three publish-ready vertical short-form content packages — for TikTok,
YouTube Shorts, and Instagram Reels — with a self-correcting quality-control loop.**

---

## The problem this solves

Repurposing a 10–90 minute episode into shorts is the highest-leverage growth activity
for most video creators, and it is almost entirely manual today: someone scrubs the
timeline hunting for "the good parts," guesses at clip boundaries, retypes captions,
and rewrites the title/description/hashtag set three times — once per platform. It is
slow, inconsistent, and the platform rules (hard sub-60s ceilings, cold-open hooks,
non-overlapping cuts) are enforced by nothing but human memory.

VidioFlex-Agents turns that workflow into a deterministic, auditable agent graph:

- **HookExtractor** scores every transcript segment for semantic density, emotional
  spikes, and sharp topic transitions, then extracts exactly the **top 3
  highest-retention hooks** — each with an attention-grabbing alternate title, a
  justified 0–100 virality score, and explicit timestamp boundaries snapped to real
  transcript segments.
- **Scriptwriter** rebases each hook to clip-relative time, cuts a pristine
  timestamp-synced caption sequence (ready-to-burn SRT included), and drafts
  platform-specific metadata variations: SEO tags for YouTube Shorts, sound/trend tags
  for TikTok, save-oriented hashtag stacks for Reels.
- **QualityControl** evaluates everything against a strict analytical rubric. On
  failure it routes **back** to the HookExtractor with a machine-actionable error
  payload; on success it releases the batch to compilation.
- **PackageCompiler** assembles the final deliverables, including an executable
  ffmpeg render manifest per clip.

The whole pipeline runs **offline with zero API keys** — the analytical engines are
deterministic and rule-based — while every node boundary is typed so any single engine
can be swapped for an LLM call (the node handlers already accept a `langchain_core`
`RunnableConfig`) without touching the graph topology.

## Architecture

```
                              VidioFlex-Agents graph topology
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                                                                                 │
 │   START                                                                         │
 │     │  transcript + source metadata                                             │
 │     ▼                                                                           │
 │  ┌────────────────┐   hooks (top-3, scored,      ┌────────────────┐             │
 │  │ HookExtractor  │──── timestamped) ───────────▶│  Scriptwriter  │             │
 │  │                │                              │                │             │
 │  │ · segment      │                              │ · SRT caption  │             │
 │  │   retention    │                              │   sequencing   │             │
 │  │   scoring      │                              │ · YT/TikTok/IG │             │
 │  │ · arc expansion│                              │   metadata     │             │
 │  │ · targeted     │                              └───────┬────────┘             │
 │  │   repair       │                                      │ caption tracks +     │
 │  └────────────────┘                                      │ metadata packages    │
 │     ▲                                                    ▼                      │
 │     │  active_violations                        ┌─────────────────┐             │
 │     │  (error payload:                          │ QualityControl  │             │
 │     │   rule, message,                          │                 │             │
 │     │   remediation hint)                       │ · <60s duration │             │
 │     │                                           │ · punchy opener │             │
 │     │              RUBRIC FAILED                │ · valid, non-   │             │
 │     └────────────── (retries left) ─────────────│   overlapping   │             │
 │                                                 │   timestamps    │             │
 │                                                 │ · artifact sync │             │
 │                                                 └────────┬────────┘             │
 │                                                          │ RUBRIC PASSED        │
 │                                                          │ (or retry budget     │
 │                                                          │  spent → degraded)   │
 │                                                          ▼                      │
 │                                                 ┌─────────────────┐             │
 │                                                 │ PackageCompiler │────▶ END    │
 │                                                 │ · ClipPackage ×3│             │
 │                                                 │ · ffmpeg render │             │
 │                                                 │   manifests     │             │
 │                                                 └─────────────────┘             │
 │                                                                                 │
 └─────────────────────────────────────────────────────────────────────────────────┘

 State channels (all typed, see vidioflex/state.py):
   hooks ················· Annotated[list[HookCandidate],  merge_hooks]          (upsert by hook_id)
   caption_tracks ········ Annotated[list[CaptionTrack],   merge_caption_tracks] (upsert by hook_id)
   metadata_packages ····· Annotated[list[MetadataPackage],merge_metadata_packages]
   qc_reports ············ Annotated[list[QCReport],       operator.add]         (append-only audit)
   pipeline_events ······· Annotated[list[str],            operator.add]         (append-only log)
   active_violations ····· error payload driving the corrective edge
```

### Why custom reducers matter here

When QualityControl rejects, say, only `hook-2`, the HookExtractor re-emits **only the
repaired `hook-2`**. The `merge_hooks` reducer upserts it by `hook_id`, so the two
passing hooks (and their caption tracks and metadata, keyed the same way) are never
clobbered by the retry — the loop converges by repairing state, not rebuilding it.
Append-only reducers (`operator.add`) keep the QC audit trail and the event log
complete across every attempt.

### The quality-control rubric

| Rule                    | Severity | Requirement                                                        |
| ----------------------- | -------- | ------------------------------------------------------------------ |
| `exactly_three_hooks`   | blocker  | The package contains exactly 3 clips                               |
| `duration_under_60s`    | blocker  | Every clip is strictly under 60s (and ≥ 8s)                        |
| `punchy_opening_line`   | blocker  | First line clears the punchiness gate (short/interrogative/power)  |
| `valid_timestamps`      | blocker  | 0 ≤ start < end ≤ source duration, snapped to segment boundaries   |
| `non_overlapping_times` | blocker  | No two clips share source footage                                  |
| `metadata_completeness` | blocker  | Captions + all 3 platform variants in sync with the hook revision  |
| `justified_virality`    | warning  | Score in (0, 100] with a substantive written justification         |

Every violation carries a `remediation` hint (e.g. *"Trim the lowest-retention edge
segments until the clip is under 60 seconds"*) that the HookExtractor maps to a
concrete repair strategy. The loop is budgeted (`--max-attempts`, default 4): if the
budget is spent, the pipeline completes **degraded** with every package flagged
`requires_human_review` instead of looping forever.

### Durable execution

The compiled graph always carries a checkpointer (in-memory by default, with an
explicit serializer allowlist for every state model). Each super-step — including
every QC retry — is snapshotted under the run's `thread_id`, so a run can be
inspected, resumed, or time-traveled with `graph.get_state_history(config)`. Swap in
`langgraph-checkpoint-sqlite`/`-postgres` for cross-process durability.

## Installation

```bash
git clone https://github.com/grloper/VidioFlex-Agents.git
cd VidioFlex-Agents

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Requires Python 3.10+. No API keys, no external services.

## Running the simulation

```bash
python main.py
```

This runs the bundled ~12-minute demo episode (a two-speaker podcast about habit
formation) through the full graph and prints the streamed node updates, the final
packages, the QC audit trail, and the event log. You will see the corrective loop
fire for real: attempt 1 extracts full narrative arcs that exceed 60 seconds,
QualityControl rejects them with remediation payloads, and attempt 2 ships repaired
clips that clear the whole rubric.

Artifacts (one `.srt` per clip plus a `packages.json` manifest with every hook,
caption cue, platform variant, QC report, and ffmpeg command) are exported to
`./output/<video_id>/`.

Run your own transcript:

```bash
python main.py --transcript my_episode.json --output-dir dist --max-attempts 4
```

Transcript JSON shape:

```json
{
  "source_video": {
    "video_id": "ep-001",
    "title": "My Episode",
    "duration_seconds": 900.0
  },
  "segments": [
    { "segment_id": 0, "start": 0.0, "end": 8.2, "speaker": "Host", "text": "..." }
  ]
}
```

Exit code `0` means every rubric rule passed; `1` means the run completed degraded
and the packages need human review.

## Repository structure

```
VidioFlex-Agents/
├── main.py                        # CLI entry: graph compilation + simulation run
├── requirements.txt               # pinned open-source dependencies
├── README.md
├── LICENSE
├── .gitignore
└── vidioflex/
    ├── __init__.py
    ├── state.py                   # Layer 1 — Pydantic payload models, reducers, graph state
    ├── analysis.py                # deterministic linguistic scoring engines
    ├── sample_data.py             # bundled demo transcript (offline simulation)
    ├── nodes/                     # Layer 2 — isolated agent node handlers
    │   ├── __init__.py
    │   ├── hook_extractor.py      #   top-3 hook mining + violation-driven repair
    │   ├── scriptwriter.py        #   SRT caption sequencing + tri-platform metadata
    │   ├── quality_control.py     #   the strict rubric gate
    │   └── package_compiler.py    #   final ClipPackage + render manifests
    ├── routing.py                 # Layer 3 — conditional-edge routing rules
    └── graph.py                   # Layer 4 — graph compilation block
```

## Extending it

- **LLM-powered engines** — every node handler takes `(state, config: RunnableConfig)`;
  replace any function in `vidioflex/analysis.py` (titling, scoring, tag generation)
  with a `langchain-core` runnable and the graph, state schema, and QC loop are
  untouched. The rubric stays deterministic, which is exactly what makes an
  LLM-backed extractor safe to loop.
- **Real rendering** — each `ClipPackage.render` contains a runnable ffmpeg command
  (9:16 center crop + subtitle burn-in); point it at the source `.mp4` to cut actual
  clips.
- **More platforms** — add a `PlatformVariant` builder in
  `vidioflex/nodes/scriptwriter.py` and extend the `Platform` literal in
  `vidioflex/state.py`; QC's completeness check follows the type.

## License

[MIT](LICENSE)
