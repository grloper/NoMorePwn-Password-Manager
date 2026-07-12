# 🔐 NoMorePwn — Local Password Manager & Security Auditor

A **local-first, zero-knowledge** credential vault with built-in
security auditing. One SQLite file on your disk, one Streamlit
dashboard in your browser, and nothing leaves your network unless you
explicitly export an encrypted backup.

## Why

Passwords in a plaintext notepad are one stolen laptop away from
disaster. NoMorePwn fixes that without handing your secrets to a cloud
vendor:

- 🗄 **Local vault** — add, view, rotate credentials in a clean web UI (Streamlit + SQLite)
- 🔑 **Zero-knowledge encryption** — Argon2id key derivation (PBKDF2-600k fallback) + AES-256-GCM per field; the master key never touches disk
- ☁️ **Leak check via k-anonymity** — HaveIBeenPwned lookups that send only the first 5 characters of a SHA-1 hash; the password never leaves your machine
- 🛡 **MFA tracker** — per-account toggle with loud warnings for accounts missing MFA
- 💪 **Strength calculator** — zxcvbn pattern-aware scoring, fully offline
- 🕵️ **Tamper-evident history** — every password version checksummed (SHA-256) and GCM-authenticated; verified automatically at every unlock, with an "unchanged for N days" age metric
- 🚫 **SQLi-proof by construction** — 100% parameterized queries, allowlist input validation, and a test that fails if dynamic SQL ever appears

Full design details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Quickstart

```bash
git clone <this-repo> && cd NoMorePwn-Password-Manager
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1. Create your encrypted vault (choose a strong master passphrase)
python scripts/init_db.py

# 2. Import your existing notepad file (service,username,password per line)
python scripts/import_notepad.py my-old-passwords.txt

# 3. Launch the dashboard
streamlit run app.py
```

Then open http://localhost:8501, unlock, and check the **Security
audit** tab. Once you've verified the import, securely delete the
plaintext file (`shred -u my-old-passwords.txt` on Linux).

## Encrypted cloud backup (optional)

```bash
# Everything is sealed with AES-256-GCM BEFORE it leaves your machine:
python scripts/backup_tool.py export --out vault-backup.nmpbak
# → drop vault-backup.nmpbak into Google Drive / Supabase / anywhere.

# Restore on any machine:
python scripts/backup_tool.py restore vault-backup.nmpbak
```

## Project layout

```
├── app.py                    # Streamlit dashboard (unlock, vault, audit)
├── requirements.txt
├── nomorepwn/                # core library
│   ├── config.py             #   paths & audit thresholds
│   ├── crypto.py             #   Argon2id/PBKDF2 KDF, AES-256-GCM, checksums
│   ├── db.py                 #   SQLite layer — parameterized queries ONLY
│   ├── validation.py         #   allowlist input validation
│   ├── vault.py              #   orchestration: unlock, CRUD, tamper sweep
│   ├── strength.py           #   zxcvbn strength scoring (offline)
│   └── leakcheck.py          #   HIBP k-anonymity (5 hash chars out, max)
├── scripts/
│   ├── init_db.py            # create a new vault
│   ├── import_notepad.py     # bulk-import plaintext passwords → encrypted
│   └── backup_tool.py        # zero-knowledge export/restore blob
├── tests/test_core.py        # crypto, tamper, validation & SQLi-policy tests
└── docs/ARCHITECTURE.md      # security model deep-dive
```

## Running the tests

```bash
python -m unittest discover tests -v
```

## Security honesty

- Your master password is the **only** key. There is no recovery.
- The vault file is safe to lose, not safe to hand out: encrypted
  fields are unbreakable without the passphrase, but service names and
  usernames are visible metadata in v0.1.
- No tool can protect an unlocked vault from malware already running on
  your machine. Lock when you step away.
