"""Cryptographically secure password & passphrase generation.

Everything here uses :mod:`secrets` (CSPRNG) — never :mod:`random`. The
generator is pure logic with no UI or network dependencies so it can be
unit-tested and reused by both the desktop app and scripts.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

# Characters that are easy to confuse when typing or reading aloud.
AMBIGUOUS = set("O0oIl1|`'\";:.,{}[]()")

# A curated wordlist for memorable passphrases. Short, common, unambiguous
# words keep phrases easy to type while length supplies the entropy.
WORDLIST = (
    "apple orange silver planet river mountain garden rocket harbor meadow "
    "castle forest island candle bridge market pillow copper velvet marble "
    "falcon jungle canyon glacier thunder breeze anchor lantern compass "
    "orchid maple willow cedar pepper ginger almond walnut cherry lemon "
    "cobalt indigo crimson golden violet scarlet amber azure teal ivory "
    "tiger otter panda eagle heron bison moose lynx raven finch koala "
    "puzzle guitar violin drummer painter poet sculptor dancer archer sailor "
    "signal beacon prism vortex nebula comet meteor quasar photon plasma "
    "summit valley prairie tundra lagoon delta fjord reef dune oasis"
).split()


@dataclass(frozen=True)
class PasswordOptions:
    length: int = 20
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    avoid_ambiguous: bool = False


def _pool(opts: PasswordOptions) -> str:
    pool = ""
    if opts.use_lower:
        pool += LOWER
    if opts.use_upper:
        pool += UPPER
    if opts.use_digits:
        pool += DIGITS
    if opts.use_symbols:
        pool += SYMBOLS
    if opts.avoid_ambiguous:
        pool = "".join(c for c in pool if c not in AMBIGUOUS)
    return pool


def _required_sets(opts: PasswordOptions) -> list[str]:
    """Each enabled class the result must contain at least one of."""
    sets: list[str] = []
    for enabled, chars in (
        (opts.use_lower, LOWER),
        (opts.use_upper, UPPER),
        (opts.use_digits, DIGITS),
        (opts.use_symbols, SYMBOLS),
    ):
        if enabled:
            usable = "".join(c for c in chars if c not in AMBIGUOUS) if opts.avoid_ambiguous else chars
            if usable:
                sets.append(usable)
    return sets


def generate_password(opts: PasswordOptions) -> str:
    """Return a random password honouring the given options.

    Guarantees at least one character from every enabled class (as long
    as the length allows), then fills the rest from the full pool and
    shuffles — all with a CSPRNG.
    """
    length = max(4, min(int(opts.length), 128))
    pool = _pool(opts)
    if not pool:
        # Nothing selected — fall back to a sane default so the UI never
        # hands the user an empty string.
        pool = LOWER + UPPER + DIGITS
        opts = PasswordOptions(length=length)

    required = _required_sets(opts)
    chars: list[str] = [secrets.choice(s) for s in required[:length]]
    while len(chars) < length:
        chars.append(secrets.choice(pool))

    # Fisher-Yates shuffle with the CSPRNG (random.shuffle is not secure).
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def generate_passphrase(
    words: int = 4, separator: str = "-", capitalize: bool = True, add_number: bool = True
) -> str:
    """Return a memorable passphrase, e.g. ``Falcon-Cobalt-River-Maple7``."""
    words = max(3, min(int(words), 12))
    chosen = [secrets.choice(WORDLIST) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    if add_number:
        phrase += separator + str(secrets.randbelow(90) + 10)
    return phrase
