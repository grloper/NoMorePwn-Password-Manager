# 🔐 NoMorePwn — a local-first password manager for Windows

A **modern, tray-resident** password manager that keeps every secret
encrypted on your own machine. No cloud account, no telemetry, no
subscription — just one file on your disk, sealed with a key derived from
your master password that **never touches disk**.

> Think 1Password's polish, but zero-knowledge and 100% local.

<!-- Screenshots live in the GitHub Release notes and docs/ -->

## ✨ What it does

- 🗂 **Two-pane vault** — searchable item list + rich detail view, colour
  avatars, MFA badges, and password age at a glance.
- 🧊 **Lives in the system tray** — the "show hidden icons" ⌃ area,
  bottom-right. Close the window and it keeps running, locked, ready for
  instant access. Quit fully from the tray whenever you want.
- 🔒 **Smart locking** — auto-locks after inactivity, locks the moment you
  hide it, and the **X button always asks**: *keep running in the tray* or
  *quit completely* — either way it locks first.
- 🎲 **Built-in generator** — cryptographically secure passwords and
  memorable passphrases, with a live strength meter.
- 🩺 **Security dashboard** — a health score plus weak, reused, stale, and
  MFA-less accounts surfaced instantly; optional breach scan via
  HaveIBeenPwned k-anonymity.
- 🔑 **Zero-knowledge crypto** — Argon2id key derivation (PBKDF2-600k
  fallback) + AES-256-GCM per field. The master key lives only in memory.
- 🕵️ **Tamper-evident** — every ciphertext and history entry is checksummed
  and GCM-authenticated; verified automatically at every unlock.
- ☁️ **Breach check via k-anonymity** — only the first 5 characters of a
  SHA-1 hash ever leave your machine, and only when you ask.

## ⬇️ Install (Windows)

Grab the latest build from **[Releases](https://github.com/grloper/NoMorePwn-Password-Manager/releases)**:

| File | Use it if… |
|---|---|
| **`NoMorePwn-<version>-Setup.exe`** | You want it installed properly — Start-menu shortcut, optional *launch at sign-in*, and an uninstaller. No admin required. |
| **`NoMorePwn-<version>-portable.exe`** | You just want to download one file and run it. |

Every push to `main` publishes a fresh signed-off build automatically.

On first launch you'll create your **master password**. There is no
recovery — choose something strong and memorable.

## 🖱 How it behaves

- **Left-click the tray icon** → open the window (it prompts for your
  master password if locked).
- **Right-click the tray icon** → open, lock, or quit completely.
- **Press ✕ on the window** → choose *keep running in the tray* or *quit
  completely*. The vault is always locked either way.
- **Step away** → it auto-locks after your chosen timeout (default 5 min).

Everything is configurable under **Settings** (auto-lock, clipboard
auto-wipe, close behaviour, launch-at-startup, dark/light theme).

## 🧑‍💻 Run from source

```bash
git clone https://github.com/grloper/NoMorePwn-Password-Manager
cd NoMorePwn-Password-Manager
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt

python NoMorePwn.py            # open the app
python NoMorePwn.py --tray     # start hidden in the tray (locked)
```

## 🏗 Build the .exe yourself

```bash
pip install -r requirements-build.txt
python build/make_icon.py                                   # regenerate the icon
pyinstaller build/NoMorePwn.spec --distpath dist --noconfirm  # -> dist/NoMorePwn.exe
# optional installer (needs Inno Setup 6):
ISCC build/installer.iss                                     # -> dist/NoMorePwn-Setup.exe
```

## 🗄 Where your data lives

The encrypted vault is stored at `%APPDATA%\NoMorePwn\vault.db`, with
preferences in `settings.json` next to it. Set the `NOMOREPWN_DATA`
environment variable to relocate it (e.g. onto an encrypted volume).

## 🔐 Security honesty

- Your master password is the **only** key. There is no recovery.
- The vault file is safe to lose, not safe to hand out: encrypted fields
  are unbreakable without the passphrase, but service names and usernames
  are visible metadata.
- No tool can protect an unlocked vault from malware already running on
  your machine. Lock it when you step away (NoMorePwn does this for you).

Full design details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 🧪 Tests

```bash
python -m unittest discover tests -v
```

Covers crypto round-trips, tamper detection, validation, the SQL-injection
policy, the secure generator, and the vault lifecycle.
