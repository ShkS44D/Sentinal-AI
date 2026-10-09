"""Authentication boundary for the Streamlit app."""
import time

import streamlit as st

from src.auth import load_users, verify_password


def require_login():
    try:
        users = load_users()
    except (OSError, ValueError, TypeError) as exc:
        st.error(f"Account configuration could not be loaded: {exc}")
        st.stop()
    if users is None:
        st.session_state["local_demo_mode"] = True
        return "admin"
    st.session_state.pop("local_demo_mode", None)
    identity = st.session_state.get("identity")
    if identity and identity["username"] in users:
        account = users[identity["username"]]
        if identity.get("credential") == account["password_hash"] and time.time() - identity["signed_in"] < 3600:
            st.sidebar.caption(f"Signed in: {identity['username']} · {account['role']}")
            if st.sidebar.button("Sign out"):
                st.session_state.clear()
                st.rerun()
            return account["role"]
    st.title("Sign in to Sentinel IDS")
    with st.form("sign_in"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        if time.time() < st.session_state.get("login_retry_at", 0):
            st.error("Please wait a few seconds before trying again.")
        else:
            account = users.get(username)
            # Run password verification even for unknown accounts.
            fallback = next(iter(users.values()))["password_hash"]
            valid = verify_password(password, account["password_hash"] if account else fallback)
            if account and valid:
                st.session_state.clear()
                st.session_state["identity"] = {
                    "username": username, "credential": account["password_hash"],
                    "signed_in": time.time(),
                }
                st.rerun()
            else:
                st.session_state["login_retry_at"] = time.time() + 3
                st.error("Username or password is incorrect.")
    st.stop()
