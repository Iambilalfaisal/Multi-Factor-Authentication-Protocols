"""Streamlit admin dashboard for the MFA Authentication Server.

This is the single entry point for Streamlit Community Cloud (set the app's
main file to ``dashboard/streamlit_app.py``). It provides:

* Users      - create / enable / disable accounts.
* MFA log    - the full AuthEvent audit table with filters.
* Anomalies  - flagged events with LLM (or fallback) explanations.
* Analytics  - charts: MFA attempts over time, success/fail, flagged counts.

The dashboard reads through ``data_source`` which transparently uses either the
remote REST API (HTTP mode) or the in-process service layer (EMBEDDED mode).
There is intentionally NO login screen on the dashboard for this capstone demo
(documented in SECURITY_NOTES.md).
"""

from __future__ import annotations

import os
import sys

# Ensure the project root is on sys.path so that ``backend.*`` is importable
# when this file is launched from the ``dashboard/`` subdirectory (e.g. on
# Streamlit Community Cloud where the main file is dashboard/streamlit_app.py).
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import pandas as pd
import plotly.express as px
import streamlit as st

# ---------------------------------------------------------------------------
# Map Streamlit Cloud secrets into the environment BEFORE importing anything
# that reads config, so EMBEDDED/API_BASE_URL/MASTER_KEY are picked up.
# ---------------------------------------------------------------------------
for _key in (
    "EMBEDDED", "API_BASE_URL", "MASTER_KEY", "DATABASE_URL",
    "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL", "SECRET_KEY",
):
    try:
        if _key in st.secrets:  # type: ignore[operator]
            os.environ[_key] = str(st.secrets[_key])
    except Exception:
        # st.secrets raises if no secrets file exists locally - that's fine.
        pass

from data_source import get_data_source  # noqa: E402  (after env setup)

st.set_page_config(page_title="MFA Admin Dashboard", page_icon="lock", layout="wide")


@st.cache_resource
def _ds():
    return get_data_source()


@st.cache_resource
def _ensure_seed_data():
    """Auto-seed demo login history on first boot when there are no events.

    Streamlit Community Cloud has no terminal and an ephemeral filesystem, so
    ``python -m scripts.seed`` can never be run there. To make the deployed demo
    show login history and anomalies, we seed in-process on the first run when
    (a) we're in EMBEDDED mode and (b) the database has no events yet.

    Crucially this back-fills history for whatever users already exist (e.g.
    accounts you created in the dashboard) AND adds the canonical alice/bob/carol
    demo users if the DB is empty - so the log/anomaly/analytics pages have data
    regardless of how the users got there. Cached so it runs at most once per
    container. Safe no-op otherwise.
    """
    embedded = os.environ.get("EMBEDDED", "0").strip().lower() in {"1", "true", "yes", "on"}
    if not embedded:
        return "skipped (not EMBEDDED)"
    try:
        ds = _ds()
        from scripts.seed import seed, seed_existing_users
        # If the DB has no users at all, add the canonical alice/bob/carol demo
        # users (each with their own history).
        if not ds.list_users():
            seed()
            return "seeded"
        # Otherwise back-fill history for any existing user that lacks events
        # (your real accounts). Idempotent: users that already have history are
        # untouched, so a freshly-created user gets seeded on the next refresh.
        n = seed_existing_users()
        return f"seeded {n} user(s)" if n else "skipped (all users have history)"
    except Exception as exc:  # noqa: BLE001  - never let seeding crash the app
        return f"error: {exc}"


def _mode_badge() -> str:
    embedded = os.environ.get("EMBEDDED", "0").lower() in {"1", "true", "yes", "on"}
    return "EMBEDDED (in-process)" if embedded else f"HTTP -> {os.environ.get('API_BASE_URL', 'localhost:5000')}"


def page_users(ds):
    st.header("Users")
    with st.expander("Create a new user"):
        with st.form("create_user"):
            c1, c2, c3 = st.columns(3)
            username = c1.text_input("Username")
            email = c2.text_input("Email")
            password = c3.text_input("Password", type="password")
            if st.form_submit_button("Create") and username and email and password:
                try:
                    ds.create_user(username, email, password)
                    st.success(f"Created user {username}")
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Could not create user: {exc}")

    try:
        users = ds.list_users()
    except Exception as exc:  # noqa: BLE001
        st.error(f"Failed to load users: {exc}")
        return

    if not users:
        st.info("No users yet. Create one above or run `python -m scripts.seed`.")
        return

    df = pd.DataFrame(users)
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.subheader("Enable / disable")
    ids = [u["id"] for u in users]
    target = st.selectbox("User id", ids)
    c1, c2 = st.columns(2)
    if c1.button("Disable"):
        ds.set_active(target, False)
        st.rerun()
    if c2.button("Enable"):
        ds.set_active(target, True)
        st.rerun()


def _events_df(ds, **kwargs) -> pd.DataFrame:
    rows = ds.list_events(**kwargs)
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    if "timestamp" in df:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def page_logs(ds):
    st.header("MFA Event Log")

    # Build a user picker for drill-down (id -> "username (id)").
    try:
        users = ds.list_users()
    except Exception:  # noqa: BLE001
        users = []
    user_options = {"All users": None}
    for u in users:
        user_options[f"{u['username']} (id {u['id']})"] = u["id"]

    c1, c2, c3 = st.columns(3)
    chosen = c1.selectbox("User", list(user_options.keys()))
    flagged_only = c2.checkbox("Flagged only", value=False)
    limit = c3.number_input("Max rows", min_value=10, max_value=5000, value=500, step=50)

    kwargs = {"flagged_only": flagged_only, "limit": int(limit)}
    selected_user_id = user_options[chosen]
    if selected_user_id is not None:
        kwargs["user_id"] = selected_user_id

    df = _events_df(ds, **kwargs)
    if df.empty:
        st.info("No matching events.")
        return

    # Per-user drill-down summary when a single user is selected.
    if selected_user_id is not None:
        total = len(df)
        ok = int(df["success"].sum()) if "success" in df else 0
        flagged = int(df["is_flagged"].sum()) if "is_flagged" in df else 0
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Events", total)
        m2.metric("Successes", ok)
        m3.metric("Failures", total - ok)
        m4.metric("Flagged", flagged)
        if "factor" in df:
            st.caption("Attempts by factor: " + ", ".join(
                f"{k}={v}" for k, v in df["factor"].value_counts().items()
            ))

    show_cols = [
        c for c in [
            "timestamp", "user_id", "username_attempted", "factor", "success",
            "reason", "ip_address", "anomaly_score", "is_flagged",
        ] if c in df.columns
    ]
    st.dataframe(df[show_cols], use_container_width=True, hide_index=True)


def page_anomalies(ds):
    st.header("Anomaly Alerts")
    df = _events_df(ds, flagged_only=True, limit=500)
    if df.empty:
        st.success("No flagged events. Run `python -m scripts.seed` to generate demo anomalies.")
        return

    st.metric("Flagged events", len(df))
    for _, row in df.iterrows():
        title = (
            f"{row.get('timestamp')} - user {row.get('user_id')} "
            f"via {row.get('factor')} (score {row.get('anomaly_score')})"
        )
        with st.expander(title):
            explanation = row.get("explanation")
            if explanation:
                st.markdown(f"**Risk explanation:** {explanation}")
            else:
                st.warning("No LLM explanation available - showing raw features.")
            features = row.get("features")
            if isinstance(features, dict):
                st.json(features)
            st.caption(
                f"IP {row.get('ip_address')} | device {row.get('device_fingerprint')}"
            )


def page_analytics(ds):
    st.header("Analytics")
    try:
        a = ds.analytics()
    except Exception as exc:  # noqa: BLE001
        st.error(f"Failed to load analytics: {exc}")
        return

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total events", a.get("total_events", 0))
    c2.metric("Successes", a.get("successes", 0))
    c3.metric("Failures", a.get("failures", 0))
    c4.metric("Flagged", a.get("flagged", 0))

    by_day = a.get("by_day", {})
    if by_day:
        day_df = pd.DataFrame({"date": list(by_day.keys()), "attempts": list(by_day.values())})
        st.plotly_chart(
            px.line(day_df, x="date", y="attempts", title="MFA attempts over time"),
            use_container_width=True,
        )

    cols = st.columns(2)
    by_factor = a.get("by_factor", {})
    if by_factor:
        f_df = pd.DataFrame({"factor": list(by_factor.keys()), "count": list(by_factor.values())})
        cols[0].plotly_chart(
            px.bar(f_df, x="factor", y="count", title="Attempts by factor"),
            use_container_width=True,
        )

    ratio_df = pd.DataFrame({
        "outcome": ["success", "failure"],
        "count": [a.get("successes", 0), a.get("failures", 0)],
    })
    cols[1].plotly_chart(
        px.pie(ratio_df, names="outcome", values="count", title="Success / fail ratio"),
        use_container_width=True,
    )

    # Geographic login map - directly visualises the geo-anomaly feature.
    st.subheader("Login locations")
    geo_df = _events_df(ds, limit=5000)
    if not geo_df.empty and "geo" in geo_df.columns:
        records = []
        for _, row in geo_df.iterrows():
            geo = row.get("geo")
            if isinstance(geo, dict) and geo.get("lat") is not None:
                records.append({
                    "lat": geo["lat"],
                    "lon": geo["lon"],
                    "status": "flagged" if row.get("is_flagged") else (
                        "success" if row.get("success") else "failure"
                    ),
                    "user_id": row.get("user_id"),
                    "factor": row.get("factor"),
                })
        if records:
            map_df = pd.DataFrame(records)
            fig = px.scatter_geo(
                map_df, lat="lat", lon="lon", color="status",
                hover_data=["user_id", "factor"],
                title="Login origins (flagged events highlighted)",
                projection="natural earth",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No geo-tagged events to map yet.")
    else:
        st.info("No geo-tagged events to map yet.")


def page_evidence(ds):
    """Render the most recent captured pytest evidence file, if present."""
    import glob
    import os

    st.header("Security Test Evidence")
    st.caption(
        "Output captured by `python -m scripts.capture_test_results`. "
        "Available when the dashboard runs alongside the repository."
    )
    files = sorted(glob.glob(os.path.join("test_evidence", "report_*.txt")))
    if not files:
        st.info("No evidence files found. Run `python -m scripts.capture_test_results`.")
        return
    latest = files[-1]
    st.success(f"Showing: {latest}")
    with open(latest, "r", encoding="utf-8", errors="replace") as fh:
        st.code(fh.read(), language="text")


def main():
    ds = _ds()
    seed_status = _ensure_seed_data()
    st.sidebar.title("MFA Admin")
    st.sidebar.caption(f"Backend: {_mode_badge()}")
    if isinstance(seed_status, str) and seed_status.startswith(("seeded", "seeded ")):
        st.sidebar.success(f"Demo data auto-seeded ({seed_status}).")
    elif isinstance(seed_status, str) and seed_status.startswith("error"):
        st.sidebar.warning(f"Auto-seed problem: {seed_status}")
    page = st.sidebar.radio(
        "Navigate", ["Users", "MFA Log", "Anomalies", "Analytics", "Test Evidence"]
    )
    if st.sidebar.button("Refresh data"):
        st.cache_resource.clear()
        st.rerun()
    st.sidebar.divider()
    st.sidebar.caption(
        "This dashboard has no login by design (capstone demo). "
        "See SECURITY_NOTES.md."
    )

    if page == "Users":
        page_users(ds)
    elif page == "MFA Log":
        page_logs(ds)
    elif page == "Anomalies":
        page_anomalies(ds)
    elif page == "Analytics":
        page_analytics(ds)
    else:
        page_evidence(ds)


if __name__ == "__main__":
    main()
