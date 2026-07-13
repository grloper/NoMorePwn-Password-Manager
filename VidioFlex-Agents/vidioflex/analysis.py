"""Deterministic linguistic scoring engines used by the agent nodes.

These engines are intentionally rule-based and dependency-free so the whole
pipeline runs offline with zero API keys. Every node consumes them through
small, typed functions, so swapping any engine for an LLM call (via a
``langchain_core`` runnable) only touches this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .state import PeakType, TranscriptSegment

# ---------------------------------------------------------------------------
# Lexicons
# ---------------------------------------------------------------------------

STOPWORDS: frozenset[str] = frozenset(
    """
    a about above after again all am an and any are as at be because been before
    being below between both but by could did do does doing down during each few
    for from further had has have having he her here hers herself him himself his
    how i if in into is it its itself just me more most my myself no nor not now
    of off on once only or other our ours ourselves out over own same she should
    so some such than that the their theirs them themselves then there these they
    this those through to too under until up very was we were what when where
    which while who whom why will with you your yours yourself yourselves
    im ive youre weve dont didnt cant wont isnt thats theres gonna really actually
    basically kind sort thing things get got like know yeah right okay well
    """.split()
)

EMOTION_LEXICON: dict[str, float] = {
    "amazing": 0.8, "astonishing": 0.9, "backfires": 0.8, "brutal": 0.8,
    "breakthrough": 0.8, "catastrophic": 0.9, "collapse": 0.8, "crazy": 0.7,
    "dangerous": 0.7, "devastating": 0.9, "disaster": 0.8, "dread": 0.8,
    "explosive": 0.8, "fail": 0.6, "failed": 0.7, "failure": 0.7, "fear": 0.7,
    "furious": 0.8, "hate": 0.7, "hated": 0.7, "horrifying": 0.9, "hurts": 0.6,
    "incredible": 0.7, "insane": 0.8, "lie": 0.7, "lied": 0.8, "love": 0.5,
    "miserable": 0.8, "mistake": 0.6, "nightmare": 0.8, "obsessed": 0.7,
    "painful": 0.7, "panic": 0.8, "powerful": 0.6, "quit": 0.6, "relapsed": 0.8,
    "ruined": 0.8, "sabotage": 0.8, "scared": 0.7, "shocked": 0.8,
    "shocking": 0.8, "staggering": 0.8, "stunned": 0.8, "terrified": 0.9,
    "terrifying": 0.9, "toxic": 0.7, "trap": 0.7, "unbelievable": 0.7,
    "wrecked": 0.8, "wild": 0.6,
}

POWER_OPENERS: frozenset[str] = frozenset(
    """
    stop imagine nobody everyone never why how here heres this listen forget
    warning truth secret most the-one one three five seven ninety most people
    scientists your you
    """.split()
)

FILLER_OPENERS: tuple[str, ...] = (
    "um", "uh", "so,", "so ", "you know", "like,", "okay,", "alright,",
    "anyway", "well,", "i mean",
)

_WORD_RE = re.compile(r"[a-zA-Z][a-zA-Z'\-]*")
_NUMBER_RE = re.compile(r"\d")


# ---------------------------------------------------------------------------
# Tokenization helpers
# ---------------------------------------------------------------------------


def tokenize(text: str) -> list[str]:
    """Lowercased word tokens, apostrophes stripped for lexicon matching."""
    return [word.lower().replace("'", "") for word in _WORD_RE.findall(text)]


def content_words(text: str) -> list[str]:
    """Tokens that carry topical meaning (stopwords removed)."""
    return [token for token in tokenize(text) if token not in STOPWORDS and len(token) > 2]


# ---------------------------------------------------------------------------
# Per-segment scoring engines
# ---------------------------------------------------------------------------


def semantic_density(segment: TranscriptSegment) -> float:
    """Ratio-based measure of how information-packed an utterance is (0..1).

    Combines the share of content words with their lexical variety, so a
    segment that names many distinct concrete concepts scores high while
    filler-heavy chatter scores low.
    """
    tokens = tokenize(segment.text)
    if not tokens:
        return 0.0
    contents = [token for token in tokens if token not in STOPWORDS and len(token) > 2]
    if not contents:
        return 0.0
    content_ratio = len(contents) / len(tokens)
    variety_ratio = len(set(contents)) / len(contents)
    long_word_ratio = sum(1 for token in contents if len(token) >= 7) / len(contents)
    return round(min(1.0, 0.45 * content_ratio + 0.35 * variety_ratio + 0.4 * long_word_ratio), 4)


def emotional_intensity(segment: TranscriptSegment) -> float:
    """Arousal measure from an emotion lexicon plus prosodic punctuation (0..1)."""
    tokens = tokenize(segment.text)
    if not tokens:
        return 0.0
    lexicon_mass = sum(EMOTION_LEXICON.get(token, 0.0) for token in tokens)
    lexicon_score = lexicon_mass / max(4.0, len(tokens) * 0.35)
    exclaim_bonus = 0.12 * min(2, segment.text.count("!"))
    question_bonus = 0.05 * min(2, segment.text.count("?"))
    return round(min(1.0, lexicon_score + exclaim_bonus + question_bonus), 4)


def topic_novelty(previous: TranscriptSegment | None, current: TranscriptSegment) -> float:
    """How sharply this segment pivots away from the previous one (0..1).

    Jaccard distance between adjacent content-word vocabularies: 1.0 means a
    hard topic transition, 0.0 means the speaker is still on the same ground.
    The very first segment is a maximal pivot by definition.
    """
    if previous is None:
        return 1.0
    prev_vocab = set(content_words(previous.text))
    cur_vocab = set(content_words(current.text))
    if not prev_vocab or not cur_vocab:
        return 0.5
    union = prev_vocab | cur_vocab
    overlap = prev_vocab & cur_vocab
    return round(1.0 - len(overlap) / len(union), 4)


def opening_punchiness(text: str) -> float:
    """Score (0..1) for how hard the first line of a clip lands.

    Rewards short lines, interrogative/exclamatory delivery, power-word or
    numeric openers; punishes filler starts. Mirrors the QC rubric so the
    extractor and the reviewer measure punch with the same ruler.
    """
    stripped = text.strip()
    if not stripped:
        return 0.0
    lowered = stripped.lower()
    first_sentence = re.split(r"(?<=[.!?])\s+", stripped)[0]
    words = tokenize(first_sentence)

    score = 0.0
    if len(words) <= 12:
        score += 0.35
    elif len(words) <= 18:
        score += 0.15
    if first_sentence.endswith(("?", "!")):
        score += 0.25
    if words and (words[0] in POWER_OPENERS or _NUMBER_RE.search(first_sentence)):
        score += 0.25
    if any(token in EMOTION_LEXICON for token in words):
        score += 0.15
    if any(lowered.startswith(filler) for filler in FILLER_OPENERS):
        score -= 0.45
    return round(max(0.0, min(1.0, score)), 4)


def is_punchy_opening(text: str) -> bool:
    """The boolean rubric gate used by QualityControl (threshold on the score)."""
    return opening_punchiness(text) >= 0.5


# ---------------------------------------------------------------------------
# Composite retention scoring
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SegmentScore:
    """Full retention profile of one transcript segment."""

    segment_id: int
    semantic_density: float
    emotional_intensity: float
    topic_novelty: float
    opening_punch: float
    retention: float
    peak_type: PeakType


def _z_scores(values: list[float]) -> list[float]:
    """Standard scores against the list's own mean/stddev (0.0 if flat)."""
    count = len(values)
    mean = sum(values) / count
    variance = sum((value - mean) ** 2 for value in values) / count
    std = variance**0.5
    if std < 1e-9:
        return [0.0] * count
    return [(value - mean) / std for value in values]


def score_segments(transcript: list[TranscriptSegment]) -> list[SegmentScore]:
    """Score every segment and classify which retention driver dominates it.

    Classification is done on z-scores against the whole episode's baseline:
    an "emotional spike" is a segment whose emotional intensity is anomalously
    high *for this transcript*, not merely nonzero. Raw-value comparison would
    let topic novelty (structurally the largest raw number in conversational
    speech) win everywhere.
    """
    raw: list[tuple[TranscriptSegment, float, float, float, float]] = []
    previous: TranscriptSegment | None = None
    for segment in transcript:
        density = semantic_density(segment)
        emotion = emotional_intensity(segment)
        novelty = topic_novelty(previous, segment)
        punch = opening_punchiness(segment.text)
        raw.append((segment, density, emotion, novelty, punch))
        previous = segment

    density_z = _z_scores([row[1] for row in raw])
    emotion_z = _z_scores([row[2] for row in raw])
    novelty_z = _z_scores([row[3] for row in raw])

    scores: list[SegmentScore] = []
    for position, (segment, density, emotion, novelty, punch) in enumerate(raw):
        retention = round(
            0.30 * density + 0.34 * emotion + 0.16 * novelty + 0.20 * punch, 4
        )
        drivers: dict[PeakType, float] = {
            "semantic_density": density_z[position],
            "emotional_spike": emotion_z[position],
            "topic_transition": novelty_z[position],
        }
        peak_type = max(drivers, key=lambda key: drivers[key])
        scores.append(
            SegmentScore(
                segment_id=segment.segment_id,
                semantic_density=density,
                emotional_intensity=emotion,
                topic_novelty=novelty,
                opening_punch=punch,
                retention=retention,
                peak_type=peak_type,
            )
        )
    return scores


# ---------------------------------------------------------------------------
# Keyword extraction (used by the Scriptwriter for SEO/tag generation)
# ---------------------------------------------------------------------------


def top_keywords(text: str, limit: int = 6) -> list[str]:
    """Most frequent content words, ties broken alphabetically for determinism."""
    counts: dict[str, int] = {}
    for token in content_words(text):
        counts[token] = counts.get(token, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [word for word, _ in ranked[:limit]]
