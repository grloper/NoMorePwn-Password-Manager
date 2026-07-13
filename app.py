"""NoMorePwn — local Streamlit dashboard.

Run with:  streamlit run app.py

Security posture of this UI:
* The derived master key lives only in Streamlit session state (process
  memory) and is destroyed by the Lock button or a browser refresh.
* Passwords are decrypted one at a time, only when you click Reveal.
* The tamper-evidence sweep runs automatically at every unlock.
* The only network call this app can make is the k-anonymity HIBP range
  query (5 hash characters), and only when you click a leak-check button.
"""

from __future__ import annotations

import streamlit as st

from nomorepwn import config, leakcheck, strength, vault
from nomorepwn.validation import ValidationError

st.set_page_config(page_title="NoMorePwn", layout="wide")

DB_PATH = str(config.DB_PATH)


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def get_vault() -> vault.Vault | None:
    key = st.session_state.get("vault_key")
    return vault.Vault(DB_PATH, key) if key else None


def do_lock() -> None:
    for state_key in ("vault_key", "integrity_issues", "revealed", "confirm_delete"):
        st.session_state.pop(state_key, None)


def run_integrity_sweep(unlocked: vault.Vault) -> None:
    st.session_state["integrity_issues"] = unlocked.verify_integrity()


# ---------------------------------------------------------------------------
# Create / unlock screens
# ---------------------------------------------------------------------------

def screen_create_vault() -> None:
    st.title("NoMorePwn")
    st.subheader("Create a vault")
    st.write(
        "No vault exists yet at `%s`. Your master password is stretched "
        "with Argon2id into a 256-bit key that is held in memory only — "
        "it is never written to disk." % DB_PATH
    )
    st.write(
        "There is no recovery mechanism. If you forget the master "
        "password, the vault contents cannot be decrypted."
    )
    with st.form("create_vault"):
        pw1 = st.text_input("Master password (minimum 10 characters)", type="password")
        pw2 = st.text_input("Confirm master password", type="password")
        if st.form_submit_button("Create vault", type="primary"):
            if pw1 != pw2:
                st.error("Passwords do not match.")
            else:
                try:
                    config.ensure_data_dir()
                    vault.create_vault(DB_PATH, pw1)
                    st.session_state["vault_created"] = True
                    st.rerun()
                except vault.VaultError as exc:
                    st.error(str(exc))


def screen_unlock() -> None:
    st.title("NoMorePwn")
    st.subheader("Unlock vault")
    if st.session_state.pop("vault_created", False):
        st.success("Vault created. Unlock it with your master password.")
    st.caption(f"Vault file: `{DB_PATH}`")
    with st.form("unlock"):
        password = st.text_input("Master password", type="password")
        if st.form_submit_button("Unlock", type="primary"):
            try:
                unlocked = vault.Vault.unlock(DB_PATH, password)
            except vault.InvalidMasterPasswordError:
                st.error("Master password is incorrect.")
            except vault.VaultError as exc:
                st.error(str(exc))
            else:
                st.session_state["vault_key"] = unlocked.session_key
                run_integrity_sweep(unlocked)
                st.rerun()


# ---------------------------------------------------------------------------
# Main dashboard
# ---------------------------------------------------------------------------

def banner_integrity() -> None:
    issues = st.session_state.get("integrity_issues")
    if issues is None:
        return
    if not issues:
        st.caption(
            "Integrity check at unlock: passed. Every ciphertext and "
            "history checksum verified."
        )
    else:
        st.error(
            f"Integrity check failed: {len(issues)} issue(s) found. "
            "The vault file was modified outside this application."
        )
        for issue in issues:
            st.warning(
                f"{issue.service_name} / {issue.username} "
                f"(id {issue.credential_id}): {issue.detail}"
            )


def render_table(rows: list[dict]) -> None:
    """Small read-only tables as markdown: predictable rendering, no
    interactive chrome."""
    if not rows:
        return
    headers = list(rows[0].keys())

    def cell(value) -> str:
        if value is None:
            return "—"
        return str(value).replace("|", "\\|")

    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(cell(row.get(h)) for h in headers) + " |")
    st.markdown("\n".join(lines))


def render_strength(password: str) -> None:
    result = strength.evaluate(password)
    st.write(
        f"Strength: **{result.label}** — "
        f"estimated crack time: {result.crack_time_display}"
    )
    if result.warning:
        st.caption(result.warning)
    for suggestion in result.suggestions:
        st.caption(suggestion)


def render_credential(unlocked: vault.Vault, cred: dict) -> None:
    flags = []
    if not cred["mfa_enabled"]:
        flags.append("MFA off")
    age = cred["age_days"]
    if age is not None and age >= config.PASSWORD_AGE_WARN_DAYS:
        flags.append(f"unchanged {age} days")
    # Backticks keep the username from being auto-linked as mailto.
    header = f"{cred['service_name']} — `{cred['username']}`"
    if flags:
        header += "  ({})".format(", ".join(flags))

    with st.expander(header):
        left, right = st.columns(2, gap="large")

        with left:
            st.markdown("**Details**")
            age_text = f"{age} days" if age is not None else "unknown"
            st.write(f"Password unchanged for: {age_text}")

            mfa_new = st.toggle(
                "MFA enabled on this account",
                value=cred["mfa_enabled"],
                key=f"mfa_{cred['id']}",
                help="Tracks whether you have turned on multi-factor "
                     "authentication on the service itself.",
            )
            if mfa_new != cred["mfa_enabled"]:
                unlocked.set_mfa(cred["id"], mfa_new)
                st.rerun()

            if cred["id"] in st.session_state.get("revealed", set()):
                password = unlocked.reveal_password(cred["id"])
                st.code(password, language=None)
                render_strength(password)
                notes = unlocked.reveal_notes(cred["id"])
                if notes:
                    st.text_area(
                        "Notes (decrypted)", notes, disabled=True,
                        key=f"notes_{cred['id']}",
                    )
                if st.button("Hide password", key=f"hide_{cred['id']}"):
                    st.session_state["revealed"].discard(cred["id"])
                    st.rerun()
            else:
                if st.button("Reveal password", key=f"reveal_{cred['id']}"):
                    st.session_state.setdefault("revealed", set()).add(cred["id"])
                    st.rerun()

            if st.button(
                "Check against known breaches",
                key=f"leak_{cred['id']}",
                help="Queries HaveIBeenPwned with the first 5 characters "
                     "of a SHA-1 hash. The password itself is never sent.",
            ):
                try:
                    count = leakcheck.check_password(unlocked.reveal_password(cred["id"]))
                except leakcheck.LeakCheckError as exc:
                    st.error(str(exc))
                else:
                    if count:
                        st.error(
                            f"This password appears in {count:,} known "
                            "breaches. Rotate it and enable MFA on the account."
                        )
                    else:
                        st.success("Not found in any known breach.")

        with right:
            st.markdown("**Rotate password**")
            with st.form(f"update_{cred['id']}"):
                new_pw = st.text_input("New password", type="password")
                if st.form_submit_button("Rotate"):
                    try:
                        unlocked.update_password(cred["id"], new_pw)
                        st.rerun()
                    except (ValidationError, vault.VaultError) as exc:
                        st.error(str(exc))

            st.markdown("**Password history** (newest first)")
            for entry in unlocked.password_history(cred["id"]):
                status = "verified" if entry["checksum_ok"] else "CHECKSUM MISMATCH"
                st.text(
                    f"{entry['changed_at']}  {status}  "
                    f"sha256:{entry['ciphertext_sha256'][:16]}…"
                )

            st.markdown("**Delete**")
            if st.session_state.get("confirm_delete") == cred["id"]:
                st.warning(
                    "This permanently removes the credential and its "
                    "entire history. This cannot be undone."
                )
                confirm_col, cancel_col = st.columns(2)
                if confirm_col.button("Confirm delete", key=f"del_yes_{cred['id']}", type="primary"):
                    unlocked.delete_credential(cred["id"])
                    st.session_state.pop("confirm_delete", None)
                    st.rerun()
                if cancel_col.button("Cancel", key=f"del_no_{cred['id']}"):
                    st.session_state.pop("confirm_delete", None)
                    st.rerun()
            else:
                if st.button("Delete credential", key=f"del_{cred['id']}"):
                    st.session_state["confirm_delete"] = cred["id"]
                    st.rerun()


def tab_vault(unlocked: vault.Vault) -> None:
    creds = unlocked.list_credentials()
    if not creds:
        st.write(
            "The vault is empty. Add credentials in the **Add credential** "
            "tab, or import an existing plaintext file with "
            "`python scripts/import_notepad.py <file>`."
        )
        return
    search = st.text_input(
        "Filter", placeholder="Filter by service or username",
        label_visibility="collapsed",
    )
    shown = 0
    for cred in creds:
        if search and search.lower() not in (
            cred["service_name"] + " " + cred["username"]
        ).lower():
            continue
        render_credential(unlocked, cred)
        shown += 1
    st.caption(f"{shown} of {len(creds)} credentials shown.")


def tab_add(unlocked: vault.Vault) -> None:
    st.write(
        "The password and notes are encrypted with AES-256-GCM before "
        "they are written to disk."
    )
    with st.form("add_credential", clear_on_submit=True):
        service = st.text_input("Service name", max_chars=64)
        username = st.text_input("Username or email", max_chars=128)
        password = st.text_input("Password", type="password", max_chars=1024)
        notes = st.text_area("Notes (optional, encrypted)", max_chars=2000)
        mfa = st.checkbox("MFA is enabled on this account")
        if st.form_submit_button("Add to vault", type="primary"):
            try:
                unlocked.add_credential(service, username, password, notes, mfa)
                st.success(f"Added {service}.")
            except (ValidationError, vault.VaultError) as exc:
                st.error(str(exc))


def tab_audit(unlocked: vault.Vault) -> None:
    creds = unlocked.list_credentials()
    if not creds:
        st.write("Nothing to audit yet. The vault is empty.")
        return

    no_mfa = [c for c in creds if not c["mfa_enabled"]]
    stale = [c for c in creds if (c["age_days"] or 0) >= config.PASSWORD_AGE_WARN_DAYS]

    col1, col2, col3 = st.columns(3)
    col1.metric("Credentials", len(creds))
    col2.metric("Missing MFA", len(no_mfa))
    col3.metric(f"Older than {config.PASSWORD_AGE_WARN_DAYS} days", len(stale))

    if no_mfa:
        st.subheader("Accounts without MFA")
        render_table(
            [
                {"Service": c["service_name"], "Username": c["username"]}
                for c in no_mfa
            ]
        )
    if stale:
        st.subheader("Stale passwords")
        render_table(
            [
                {
                    "Service": c["service_name"],
                    "Username": c["username"],
                    "Unchanged (days)": c["age_days"],
                }
                for c in stale
            ]
        )

    st.divider()
    st.subheader("Breach and strength sweep")
    st.caption(
        "Checks every password against HaveIBeenPwned via k-anonymity "
        "(5 hash characters sent per password) and scores strength locally."
    )
    if st.button("Run full audit", type="primary"):
        progress = st.progress(0.0)
        rows = []
        for i, cred in enumerate(creds):
            password = unlocked.reveal_password(cred["id"])
            score = strength.evaluate(password)
            try:
                breaches = leakcheck.check_password(password)
                breach_text = f"{breaches:,} breaches" if breaches else "none found"
            except leakcheck.LeakCheckError:
                breach_text = "check failed (offline?)"
            rows.append({
                "Service": cred["service_name"],
                "Username": cred["username"],
                "Strength": score.label,
                "Breaches": breach_text,
                "MFA": "yes" if cred["mfa_enabled"] else "no",
                "Age (days)": cred["age_days"],
            })
            progress.progress((i + 1) / len(creds))
        progress.empty()
        render_table(rows)

    st.divider()
    if st.button("Re-run integrity check"):
        run_integrity_sweep(unlocked)
        st.rerun()


def main() -> None:
    if not vault.vault_exists(DB_PATH):
        screen_create_vault()
        return
    unlocked = get_vault()
    if unlocked is None:
        screen_unlock()
        return

    with st.sidebar:
        st.title("NoMorePwn")
        st.caption(f"Vault: `{DB_PATH}`")
        if st.button("Lock vault", use_container_width=True):
            do_lock()
            st.rerun()
        st.caption(
            "Local-first: nothing leaves this machine except 5-character "
            "hash prefixes during opt-in breach checks."
        )

    banner_integrity()
    vault_tab, add_tab, audit_tab = st.tabs(["Vault", "Add credential", "Audit"])
    with vault_tab:
        tab_vault(unlocked)
    with add_tab:
        tab_add(unlocked)
    with audit_tab:
        tab_audit(unlocked)


main()
