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

st.set_page_config(page_title="MFA Admin Dashboard", page_icon="🔐", layout="wide")


# ---------------------------------------------------------------------------
# Theme + animations. Pure CSS injected into Streamlit (no extra dependencies,
# so the app still deploys cleanly to Streamlit Community Cloud).
# ---------------------------------------------------------------------------
_THEME_CSS = """
<style>
/* ---- "SOC console" palette ---------------------------------------------- */
:root {
  --mfa-navy:  #0f172a;   /* slate-900 base   */
  --mfa-teal:  #0e7490;   /* cyan-800 deep    */
  --mfa-cyan:  #22d3ee;   /* cyan-400 accent  */
  --mfa-cyan2: #0891b2;   /* cyan-600         */
  --mfa-blue:  #2563eb;   /* blue-600         */
  --mfa-threat:#ef4444;   /* red - threats ONLY */
}
.stApp {
  background:
    radial-gradient(1200px 600px at 10% -10%, rgba(14,116,144,.20), transparent 60%),
    radial-gradient(1000px 500px at 110% 0%, rgba(34,211,238,.12), transparent 55%),
    radial-gradient(900px 520px at 50% 120%, rgba(37,99,235,.10), transparent 55%);
}

/* ---- MFA hero banner (calm: slow gradient + single scan line) ----------- */
.mfa-hero {
  position: relative; overflow: hidden;
  display: flex; align-items: center; gap: 1.1rem;
  padding: 1.15rem 1.5rem; margin: 0 0 1.25rem 0;
  border-radius: 18px;
  background: linear-gradient(120deg, var(--mfa-navy), var(--mfa-teal), var(--mfa-cyan2), #155e75);
  background-size: 280% 280%;
  animation: mfaGradient 18s ease infinite;
  box-shadow: 0 10px 30px rgba(8,145,178,.30);
  border: 1px solid rgba(34,211,238,.25);
}
@keyframes mfaGradient {
  0%   { background-position: 0% 50%; }
  50%  { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}
/* sweeping "scan line" - the one kept motion (reads as a security scan) */
.mfa-hero::after {
  content: ""; position: absolute; top: 0; left: -35%;
  width: 35%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(34,211,238,.22), transparent);
  animation: mfaScan 6s linear infinite;
}
@keyframes mfaScan { 0% { left: -35%; } 100% { left: 120%; } }

/* shield: slow, subtle pulse */
.mfa-shield {
  font-size: 2.6rem; line-height: 1;
  filter: drop-shadow(0 0 10px rgba(34,211,238,.6));
  animation: mfaPulse 3.5s ease-in-out infinite;
}
@keyframes mfaPulse {
  0%, 100% { transform: scale(1);    filter: drop-shadow(0 0 6px rgba(34,211,238,.45)); }
  50%      { transform: scale(1.08); filter: drop-shadow(0 0 14px rgba(34,211,238,.85)); }
}
/* lock: static, steady glow (no motion) */
.mfa-lock {
  margin-left: auto; font-size: 2.1rem; line-height: 1;
  filter: drop-shadow(0 0 8px rgba(34,211,238,.5));
}
.mfa-hero-title {
  color: #f1f5f9; font-size: 1.7rem; font-weight: 800; letter-spacing: .3px;
  text-shadow: 0 2px 8px rgba(0,0,0,.35); margin: 0;
}
.mfa-hero-sub { color: rgba(224,242,254,.92); font-size: .92rem; margin-top: 3px; }

/* ---- Gradient section headers (cyan -> teal -> blue) -------------------- */
h1, h2 {
  background: linear-gradient(90deg, var(--mfa-cyan), var(--mfa-cyan2), var(--mfa-blue));
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent;
  font-weight: 800 !important;
}

/* ---- Metric cards with hover lift --------------------------------------- */
[data-testid="stMetric"] {
  background: linear-gradient(160deg, rgba(14,116,144,.18), rgba(15,23,42,.30));
  border: 1px solid rgba(34,211,238,.25);
  border-left: 5px solid var(--mfa-cyan);
  border-radius: 14px; padding: 14px 16px;
  transition: transform .15s ease, box-shadow .15s ease;
}
[data-testid="stMetric"]:hover {
  transform: translateY(-4px);
  box-shadow: 0 10px 24px rgba(34,211,238,.25);
  border-left-color: var(--mfa-cyan2);
}
[data-testid="stMetricValue"] { color: #e0f2fe; font-weight: 800; }

/* ---- Buttons ------------------------------------------------------------ */
.stButton > button {
  border: 0; border-radius: 12px; font-weight: 700; color: #fff;
  background: linear-gradient(90deg, var(--mfa-teal), var(--mfa-cyan2));
  transition: transform .12s ease, box-shadow .12s ease, filter .12s ease;
}
.stButton > button:hover {
  transform: translateY(-2px); filter: brightness(1.10);
  box-shadow: 0 8px 20px rgba(8,145,178,.40);
}

/* ---- Sidebar accent ----------------------------------------------------- */
[data-testid="stSidebar"] {
  background: linear-gradient(180deg, rgba(14,116,144,.16), rgba(15,23,42,.30));
  border-right: 1px solid rgba(34,211,238,.20);
}

/* ---- Dataframe rounding ------------------------------------------------- */
[data-testid="stDataFrame"] { border-radius: 12px; overflow: hidden; }
</style>
"""


def _inject_theme() -> None:
    st.markdown(_THEME_CSS, unsafe_allow_html=True)


def _render_hero(subtitle: str) -> None:
    st.markdown(
        f"""
        <div class="mfa-hero">
          <div class="mfa-shield">🛡️</div>
          <div>
            <div class="mfa-hero-title">MFA Admin Dashboard</div>
            <div class="mfa-hero-sub">{subtitle}</div>
          </div>
          <div class="mfa-lock">🔐</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# "SOC console" sequence: cyan/teal/blue family for neutral categories. Red is
# reserved exclusively for threats (see _STATUS_COLORS) so flagged events pop.
_MFA_COLORS = ["#22d3ee", "#0891b2", "#0e7490", "#2563eb", "#38bdf8", "#5eead4"]
_STATUS_COLORS = {"success": "#22c55e", "failure": "#f59e0b", "flagged": "#ef4444"}


def _style_fig(fig):
    """Apply the dashboard's colourful, transparent-background look to a chart."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e0f2fe"),
        title_font=dict(size=18, color="#a5f3fc"),
        margin=dict(l=10, r=10, t=50, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    return fig


# Bump this whenever the data layer's shape changes (new methods, etc.). It is
# part of the cache key below, so a new value forces Streamlit to rebuild the
# cached resources on the next run instead of reusing a stale object that an
# earlier build cached (a known Streamlit Cloud hot-reload pitfall).
_BUILD = "2026-06-06.delete-user"


@st.cache_resource
def _ds(build: str = _BUILD):
    return get_data_source()


@st.cache_resource
def _ensure_seed_data(build: str = _BUILD):
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

    st.subheader("Manage account")
    label_by_id = {u["id"]: f"{u['username']} (id {u['id']})" for u in users}
    ids = list(label_by_id.keys())
    target = st.selectbox("User", ids, format_func=lambda i: label_by_id[i])
    c1, c2, c3 = st.columns(3)
    if c1.button("Enable"):
        ds.set_active(target, True)
        st.rerun()
    if c2.button("Disable"):
        ds.set_active(target, False)
        st.rerun()

    # Deletion is permanent (removes the user, their credentials and all of
    # their audit events), so require an explicit confirmation first.
    with c3.popover("🗑️ Delete", use_container_width=True):
        st.warning(
            f"Permanently delete **{label_by_id[target]}** and all of their "
            "events and credentials? This cannot be undone."
        )
        if st.checkbox("Yes, I'm sure", key=f"confirm_del_{target}"):
            if st.button("Delete permanently", type="primary"):
                try:
                    ds.delete_user(target)
                    st.success(f"Deleted {label_by_id[target]}")
                    st.rerun()
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Could not delete user: {exc}")


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
        line_fig = px.line(
            day_df, x="date", y="attempts", title="MFA attempts over time",
            markers=True, color_discrete_sequence=["#22d3ee"],
        )
        line_fig.update_traces(line=dict(width=3), fill="tozeroy", fillcolor="rgba(34,211,238,.15)")
        st.plotly_chart(_style_fig(line_fig), use_container_width=True)

    cols = st.columns(2)
    by_factor = a.get("by_factor", {})
    if by_factor:
        f_df = pd.DataFrame({"factor": list(by_factor.keys()), "count": list(by_factor.values())})
        bar_fig = px.bar(
            f_df, x="factor", y="count", title="Attempts by factor",
            color="factor", color_discrete_sequence=_MFA_COLORS,
        )
        cols[0].plotly_chart(_style_fig(bar_fig), use_container_width=True)

    ratio_df = pd.DataFrame({
        "outcome": ["success", "failure"],
        "count": [a.get("successes", 0), a.get("failures", 0)],
    })
    pie_fig = px.pie(
        ratio_df, names="outcome", values="count", title="Success / fail ratio",
        hole=0.45, color="outcome",
        color_discrete_map={"success": "#22c55e", "failure": "#f59e0b"},
    )
    pie_fig.update_traces(textinfo="percent+label")
    cols[1].plotly_chart(_style_fig(pie_fig), use_container_width=True)

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
                color_discrete_map=_STATUS_COLORS,
            )
            fig.update_traces(marker=dict(size=11, line=dict(width=1, color="rgba(255,255,255,.6)")))
            fig.update_geos(
                bgcolor="rgba(0,0,0,0)", landcolor="rgba(99,102,241,.12)",
                oceancolor="rgba(2,6,23,.6)", showocean=True,
                lakecolor="rgba(2,6,23,.6)", coastlinecolor="rgba(148,163,184,.4)",
            )
            st.plotly_chart(_style_fig(fig), use_container_width=True)
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


_PAGE_SUBTITLES = {
    "Users": "👥 Manage accounts & enrolled factors",
    "MFA Log": "📜 Live authentication audit trail",
    "Anomalies": "🚨 AI-flagged suspicious logins",
    "Analytics": "📊 Metrics, trends & geo intelligence",
    "Test Evidence": "🧪 Captured security test results",
}


def main():
    _inject_theme()
    ds = _ds()
    # Self-heal: if a previous build cached a DataSource that predates a method
    # we now rely on, drop the stale object and rebuild it. Guards against the
    # "object has no attribute ..." error after a hot-reload deploy.
    if not hasattr(ds, "delete_user"):
        st.cache_resource.clear()
        ds = _ds()
    seed_status = _ensure_seed_data()
    st.sidebar.title("🔐 MFA Admin")
    # Data initialisation is silent by design so the console reads like a live
    # system; only surface a problem if one occurs.
    if isinstance(seed_status, str) and seed_status.startswith("error"):
        st.sidebar.warning(f"Data init problem: {seed_status}")
    page = st.sidebar.radio(
        "Navigate", ["Users", "MFA Log", "Anomalies", "Analytics", "Test Evidence"]
    )
    if st.sidebar.button("🔄 Refresh data"):
        st.cache_resource.clear()
        st.rerun()
    st.sidebar.divider()
    st.sidebar.caption("Read-only security admin console. See SECURITY_NOTES.md.")

    _render_hero(_PAGE_SUBTITLES.get(page, "Multi-Factor Authentication control center"))

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
