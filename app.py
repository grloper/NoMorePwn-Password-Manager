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

st.set_page_config(page_title="NoMorePwn", page_icon="🔐", layout="wide")

DB_PATH = str(config.DB_PATH)
STRENGTH_ICONS = {0: "🟥", 1: "🟧", 2: "🟨", 3: "🟩", 4: "✅"}


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def get_vault() -> vault.Vault | None:
    key = st.session_state.get("vault_key")
    return vault.Vault(DB_PATH, key) if key else None


def do_lock() -> None:
    for state_key in ("vault_key", "integrity_issues", "revealed"):
        st.session_state.pop(state_key, None)


def run_integrity_sweep(unlocked: vault.Vault) -> None:
    st.session_state["integrity_issues"] = unlocked.verify_integrity()


# ---------------------------------------------------------------------------
# Create / unlock screens
# ---------------------------------------------------------------------------

def screen_create_vault() -> None:
    st.title("🔐 NoMorePwn — create your vault")
    st.info(
        "No vault exists yet. Your master password is stretched with "
        "Argon2id into a 256-bit key that never touches disk. "
        "**There is no recovery if you forget it.**"
    )
    with st.form("create_vault"):
        pw1 = st.text_input("Master password (min 10 chars)", type="password")
        pw2 = st.text_input("Confirm master password", type="password")
        if st.form_submit_button("Create vault", type="primary"):
            if pw1 != pw2:
                st.error("Passwords do not match.")
            else:
                try:
                    config.ensure_data_dir()
                    vault.create_vault(DB_PATH, pw1)
                    st.success("Vault created. Unlock it below.")
                    st.rerun()
                except vault.VaultError as exc:
                    st.error(str(exc))


def screen_unlock() -> None:
    st.title("🔐 NoMorePwn — unlock")
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
        st.success("✅ Tamper check passed: every ciphertext and history checksum verified.")
    else:
        st.error(
            f"🚨 TAMPER CHECK FAILED — {len(issues)} issue(s). "
            "The vault file was modified outside this app."
        )
        for issue in issues:
            st.warning(
                f"**{issue.service_name} / {issue.username}** "
                f"(id {issue.credential_id}): {issue.detail}"
            )


def render_credential(unlocked: vault.Vault, cred: dict) -> None:
    mfa_badge = "🛡️ MFA on" if cred["mfa_enabled"] else "⚠️ MFA OFF"
    age = cred["age_days"]
    age_text = f"{age}d old" if age is not None else "age unknown"
    header = f"{cred['service_name']} — {cred['username']}  ·  {mfa_badge}  ·  {age_text}"

    with st.expander(header):
        left, right = st.columns(2)

        with left:
            st.metric(
                "Unchanged for",
                f"{age} days" if age is not None else "—",
                help="Days this password has remained securely unchanged "
                     "(from tamper-verified history).",
            )
            if not cred["mfa_enabled"]:
                st.warning("MFA is disabled for this account. Enable it on the service, then flip the toggle.")
            mfa_new = st.toggle("MFA enabled", value=cred["mfa_enabled"], key=f"mfa_{cred['id']}")
            if mfa_new != cred["mfa_enabled"]:
                unlocked.set_mfa(cred["id"], mfa_new)
                st.rerun()

            if st.button("👁 Reveal password", key=f"reveal_{cred['id']}"):
                st.session_state.setdefault("revealed", set()).add(cred["id"])
            if cred["id"] in st.session_state.get("revealed", set()):
                password = unlocked.reveal_password(cred["id"])
                st.code(password, language=None)
                result = strength.evaluate(password)
                st.write(
                    f"{STRENGTH_ICONS[result.score]} **{result.label}** — "
                    f"crack time: {result.crack_time_display}"
                )
                if result.warning:
                    st.caption(f"⚠️ {result.warning}")
                if st.button("Hide", key=f"hide_{cred['id']}"):
                    st.session_state["revealed"].discard(cred["id"])
                    st.rerun()

            if st.button("☁️ Check against known breaches", key=f"leak_{cred['id']}",
                         help="k-anonymity: only 5 characters of a SHA-1 hash are sent."):
                try:
                    count = leakcheck.check_password(unlocked.reveal_password(cred["id"]))
                except leakcheck.LeakCheckError as exc:
                    st.error(str(exc))
                else:
                    if count:
                        st.error(f"🚨 Found in {count:,} breaches — change this password NOW.")
                    else:
                        st.success("Not found in any known breach.")

        with right:
            with st.form(f"update_{cred['id']}"):
                new_pw = st.text_input("New password", type="password")
                if st.form_submit_button("Rotate password"):
                    try:
                        unlocked.update_password(cred["id"], new_pw)
                        st.success("Password rotated; previous version kept in tamper-evident history.")
                        st.rerun()
                    except (ValidationError, vault.VaultError) as exc:
                        st.error(str(exc))

            st.caption("Password history (newest first)")
            for entry in unlocked.password_history(cred["id"]):
                ok = "✅" if entry["checksum_ok"] else "🚨 CHECKSUM MISMATCH"
                st.text(f"{entry['changed_at']}  {ok}  sha256:{entry['ciphertext_sha256'][:16]}…")

            if st.button("🗑 Delete credential", key=f"del_{cred['id']}", type="secondary"):
                unlocked.delete_credential(cred["id"])
                st.rerun()


def tab_vault(unlocked: vault.Vault) -> None:
    creds = unlocked.list_credentials()
    if not creds:
        st.info("Vault is empty. Add credentials in the **Add** tab or run "
                "`python scripts/import_notepad.py <your-notepad-file>`.")
        return
    search = st.text_input("🔎 Filter", placeholder="service or username…")
    for cred in creds:
        if search and search.lower() not in (
            cred["service_name"] + " " + cred["username"]
        ).lower():
            continue
        render_credential(unlocked, cred)


def tab_add(unlocked: vault.Vault) -> None:
    with st.form("add_credential", clear_on_submit=True):
        service = st.text_input("Service name", max_chars=64)
        username = st.text_input("Username / email", max_chars=128)
        password = st.text_input("Password", type="password", max_chars=1024)
        notes = st.text_area("Notes (optional, encrypted)", max_chars=2000)
        mfa = st.checkbox("MFA is enabled on this account")
        if st.form_submit_button("Add to vault", type="primary"):
            try:
                unlocked.add_credential(service, username, password, notes, mfa)
                st.success(f"Added {service}. Password encrypted with AES-256-GCM.")
            except (ValidationError, vault.VaultError) as exc:
                st.error(str(exc))


def tab_audit(unlocked: vault.Vault) -> None:
    creds = unlocked.list_credentials()
    if not creds:
        st.info("Nothing to audit yet.")
        return

    no_mfa = [c for c in creds if not c["mfa_enabled"]]
    stale = [c for c in creds if (c["age_days"] or 0) >= config.PASSWORD_AGE_WARN_DAYS]

    col1, col2, col3 = st.columns(3)
    col1.metric("Credentials", len(creds))
    col2.metric("Missing MFA", len(no_mfa), delta_color="inverse")
    col3.metric(f"Older than {config.PASSWORD_AGE_WARN_DAYS}d", len(stale), delta_color="inverse")

    if no_mfa:
        st.subheader("⚠️ Accounts without MFA")
        for c in no_mfa:
            st.write(f"- **{c['service_name']}** — {c['username']}")
    if stale:
        st.subheader("⏳ Stale passwords")
        for c in stale:
            st.write(f"- **{c['service_name']}** — {c['username']} (unchanged {c['age_days']} days)")

    st.divider()
    st.subheader("Breach + strength sweep")
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
                breach_text = f"🚨 {breaches:,}× breached" if breaches else "✅ clean"
            except leakcheck.LeakCheckError:
                breach_text = "❔ check failed (offline?)"
            rows.append({
                "Service": cred["service_name"],
                "Username": cred["username"],
                "Strength": f"{STRENGTH_ICONS[score.score]} {score.label}",
                "Breaches": breach_text,
                "MFA": "🛡️" if cred["mfa_enabled"] else "⚠️ off",
                "Age (days)": cred["age_days"],
            })
            progress.progress((i + 1) / len(creds))
        st.dataframe(rows, use_container_width=True)

    st.divider()
    if st.button("Re-run tamper check"):
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
        st.title("🔐 NoMorePwn")
        st.caption(f"Vault: `{DB_PATH}`")
        if st.button("🔒 Lock vault", use_container_width=True):
            do_lock()
            st.rerun()
        st.caption(
            "Local-first: nothing leaves this machine except 5-character "
            "hash prefixes during opt-in breach checks."
        )

    banner_integrity()
    vault_tab, add_tab, audit_tab = st.tabs(["📋 Vault", "➕ Add", "🩺 Security audit"])
    with vault_tab:
        tab_vault(unlocked)
    with add_tab:
        tab_add(unlocked)
    with audit_tab:
        tab_audit(unlocked)


main()
