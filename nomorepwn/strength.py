"""Local password strength evaluation. Nothing here touches the network.

Primary engine: zxcvbn (Dropbox's pattern-aware estimator — catches
dictionary words, keyboard walks, l33t substitutions, dates).
Fallback: a conservative charset-entropy estimate if zxcvbn is missing,
so the app degrades gracefully instead of crashing.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field

try:
    from zxcvbn import zxcvbn as _zxcvbn

    HAS_ZXCVBN = True
except ImportError:  # pragma: no cover - depends on environment
    HAS_ZXCVBN = False

SCORE_LABELS = {
    0: "Very weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very strong",
}


@dataclass
class StrengthResult:
    score: int                      # 0 (worst) .. 4 (best)
    label: str
    crack_time_display: str
    warning: str = ""
    suggestions: list[str] = field(default_factory=list)


def evaluate(password: str) -> StrengthResult:
    if not password:
        return StrengthResult(0, SCORE_LABELS[0], "instant", "Empty password.")
    if HAS_ZXCVBN:
        return _evaluate_zxcvbn(password)
    return _evaluate_entropy(password)


def _evaluate_zxcvbn(password: str) -> StrengthResult:
    # zxcvbn slows down sharply on very long inputs; 100 chars is plenty
    # for an accurate score.
    result = _zxcvbn(password[:100])
    feedback = result.get("feedback", {})
    return StrengthResult(
        score=int(result["score"]),
        label=SCORE_LABELS[int(result["score"])],
        crack_time_display=str(
            result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
        ),
        warning=feedback.get("warning") or "",
        suggestions=list(feedback.get("suggestions") or []),
    )


def _evaluate_entropy(password: str) -> StrengthResult:
    """Charset-pool entropy estimate. Deliberately conservative."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c not in string.ascii_letters + string.digits for c in password):
        pool += 33
    entropy_bits = len(password) * math.log2(pool) if pool else 0

    if entropy_bits < 28:
        score = 0
    elif entropy_bits < 40:
        score = 1
    elif entropy_bits < 60:
        score = 2
    elif entropy_bits < 80:
        score = 3
    else:
        score = 4

    return StrengthResult(
        score=score,
        label=SCORE_LABELS[score],
        crack_time_display=f"~{entropy_bits:.0f} bits of entropy",
        suggestions=(
            ["Install zxcvbn for smarter, pattern-aware analysis."]
            if score >= 3
            else [
                "Use a longer passphrase (4+ random words) or a generated password.",
                "Install zxcvbn for smarter, pattern-aware analysis.",
            ]
        ),
    )
