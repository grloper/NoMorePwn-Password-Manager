"""Credential groups: the suggested set, and guessing one from a service name.

Groups are plain metadata stored beside `service_name` — a label the user
picks, not a secret. This module holds only the *suggestions*: which groups to
offer, and which one a service like ``gmail.com`` or ``steamcommunity.com``
probably belongs to. Nothing here is authoritative; the user can type any
label that passes :func:`nomorepwn.validation.validate_group_name`.

Pure functions over strings, no I/O and no vault access, so the guessing rules
are testable without a database.
"""

from __future__ import annotations

# Offered in the editor's dropdown, in this order, before any custom groups.
SUGGESTED_GROUPS: tuple[str, ...] = (
    "Email",
    "Social",
    "Gaming",
    "Banking & Finance",
    "Shopping",
    "Work",
    "Development",
    "Entertainment",
)

# Substring -> group. Matched against the lowercased service name, longest
# first, so "office365" beats "office" and "battle.net" beats "battle".
_HINTS: dict[str, str] = {
    # Email
    "gmail": "Email", "googlemail": "Email", "mail.google": "Email",
    "outlook": "Email",
    "hotmail": "Email", "yahoo": "Email", "protonmail": "Email",
    "proton.me": "Email", "zoho": "Email", "fastmail": "Email",
    "icloud": "Email", "tutanota": "Email",
    # Gaming
    "steampowered": "Gaming", "steamcommunity": "Gaming", "steam": "Gaming",
    "epicgames": "Gaming", "battle.net": "Gaming", "blizzard": "Gaming",
    "riotgames": "Gaming", "leagueoflegends": "Gaming", "xbox": "Gaming",
    "playstation": "Gaming", "nintendo": "Gaming", "ubisoft": "Gaming",
    "rockstargames": "Gaming", "ea.com": "Gaming", "origin.com": "Gaming",
    "gog.com": "Gaming", "roblox": "Gaming", "minecraft": "Gaming",
    "itch.io": "Gaming", "twitch": "Gaming",
    # Social
    "facebook": "Social", "instagram": "Social", "twitter": "Social",
    "x.com": "Social", "reddit": "Social", "tiktok": "Social",
    "linkedin": "Social", "discord": "Social", "snapchat": "Social",
    "telegram": "Social", "whatsapp": "Social", "mastodon": "Social",
    "pinterest": "Social", "tumblr": "Social", "bluesky": "Social",
    # Banking & Finance
    "paypal": "Banking & Finance", "stripe": "Banking & Finance",
    "revolut": "Banking & Finance", "wise.com": "Banking & Finance",
    "chase": "Banking & Finance", "wellsfargo": "Banking & Finance",
    "bankofamerica": "Banking & Finance", "citibank": "Banking & Finance",
    "hsbc": "Banking & Finance", "barclays": "Banking & Finance",
    "coinbase": "Banking & Finance", "binance": "Banking & Finance",
    "kraken": "Banking & Finance", "monzo": "Banking & Finance",
    "leumi": "Banking & Finance", "hapoalim": "Banking & Finance",
    "isracard": "Banking & Finance", "max.co.il": "Banking & Finance",
    # Shopping
    "amazon": "Shopping", "ebay": "Shopping", "aliexpress": "Shopping",
    "etsy": "Shopping", "walmart": "Shopping", "target.com": "Shopping",
    "ikea": "Shopping", "asos": "Shopping", "shein": "Shopping",
    "bestbuy": "Shopping", "newegg": "Shopping",
    # Development
    "github": "Development", "gitlab": "Development", "bitbucket": "Development",
    "npmjs": "Development", "pypi": "Development", "dockerhub": "Development",
    "docker.com": "Development", "stackoverflow": "Development",
    "digitalocean": "Development", "heroku": "Development", "vercel": "Development",
    "netlify": "Development", "cloudflare": "Development", "aws.amazon": "Development",
    "azure": "Development", "jetbrains": "Development", "atlassian": "Development",
    # Work
    "slack": "Work", "zoom.us": "Work", "notion": "Work", "asana": "Work",
    "trello": "Work", "monday.com": "Work", "office365": "Work",
    "microsoft365": "Work", "workspace.google": "Work", "dropbox": "Work",
    "box.com": "Work",
    # Entertainment
    "netflix": "Entertainment", "spotify": "Entertainment", "youtube": "Entertainment",
    "disneyplus": "Entertainment", "disney": "Entertainment", "hulu": "Entertainment",
    "hbomax": "Entertainment", "primevideo": "Entertainment", "appletv": "Entertainment",
    "soundcloud": "Entertainment", "deezer": "Entertainment", "audible": "Entertainment",
}


def suggest_group(service_name: str) -> str:
    """Best-guess group for a service name, or "" when nothing matches.

    Only ever a *suggestion* — a pre-selected dropdown value the user can
    override. Never applied to an existing credential behind their back.
    """
    if not isinstance(service_name, str) or not service_name.strip():
        return ""
    needle = service_name.strip().lower()
    # Longest hint first so the most specific rule wins.
    for hint in sorted(_HINTS, key=len, reverse=True):
        if hint in needle:
            return _HINTS[hint]
    return ""


UNGROUPED_LABEL = "Ungrouped"


def group_credentials(creds: list[dict]) -> list[tuple[str, list[dict]]]:
    """Bucket credentials for display: named groups A–Z, ungrouped last.

    Pure over the public credential dicts, so the list view only has to render
    what this returns. Grouping is case-insensitive for ordering but keeps the
    stored spelling of whichever entry appeared first.
    """
    buckets: dict[str, list[dict]] = {}
    labels: dict[str, str] = {}
    for cred in creds:
        raw = (cred.get("group_name") or "").strip()
        key = raw.casefold()
        labels.setdefault(key, raw)
        buckets.setdefault(key, []).append(cred)

    out = [(labels[k], buckets[k]) for k in sorted(k for k in buckets if k)]
    if "" in buckets:
        out.append((UNGROUPED_LABEL, buckets[""]))
    return out


def known_hint_count() -> int:
    """How many services the suggester recognises (for docs and tests)."""
    return len(_HINTS)


def choices(existing: list[str] | None = None) -> list[str]:
    """Dropdown options: suggested groups first, then the user's own.

    Case-insensitive de-duplication, because "gaming" and "Gaming" being two
    entries in a picker is a bug, not a feature.
    """
    out: list[str] = []
    seen: set[str] = set()
    for name in (*SUGGESTED_GROUPS, *(existing or [])):
        key = name.casefold()
        if name and key not in seen:
            seen.add(key)
            out.append(name)
    return out
