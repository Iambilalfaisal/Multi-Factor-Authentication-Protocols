"""Admin routes powering the dashboard: users, events, anomalies, analytics.

NOTE: These endpoints are unauthenticated in this capstone build so the
Streamlit dashboard can read them directly for the demo. In production they
would sit behind admin authentication + RBAC. Documented in SECURITY_NOTES.md.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify

from ..models import AuthEvent
from ..services import events as events_svc
from ..services.users import (
    UserError,
    create_user,
    delete_user,
    list_users,
    set_active,
)
from .helpers import error, json_body, with_session

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.get("/users")
@with_session
def get_users():
    users = list_users(g.session)
    return jsonify({"users": [u.to_dict() for u in users]}), 200


@admin_bp.post("/users")
@with_session
def post_user():
    body = json_body()
    try:
        user = create_user(
            g.session,
            username=body.get("username", ""),
            email=body.get("email", ""),
            password=body.get("password", ""),
            is_admin=bool(body.get("is_admin", False)),
        )
    except UserError as exc:
        return error(str(exc), 409)
    return jsonify({"user": user.to_dict()}), 201


@admin_bp.patch("/users/<int:user_id>")
@with_session
def patch_user(user_id: int):
    body = json_body()
    try:
        user = set_active(g.session, user_id, bool(body.get("is_active", True)))
    except UserError as exc:
        return error(str(exc), 404)
    return jsonify({"user": user.to_dict()}), 200


@admin_bp.delete("/users/<int:user_id>")
@with_session
def remove_user(user_id: int):
    try:
        delete_user(g.session, user_id)
    except UserError as exc:
        return error(str(exc), 404)
    return jsonify({"deleted": user_id}), 200


@admin_bp.get("/events")
@with_session
def get_events():
    from flask import request

    user_id = request.args.get("user_id", type=int)
    flagged_only = request.args.get("flagged_only", "false").lower() == "true"
    limit = request.args.get("limit", default=500, type=int)
    rows = events_svc.list_events(
        g.session, user_id=user_id, flagged_only=flagged_only, limit=limit
    )
    return jsonify({"events": [e.to_dict() for e in rows]}), 200


@admin_bp.get("/analytics")
@with_session
def analytics():
    """Aggregate metrics for the dashboard charts."""
    rows = events_svc.list_events(g.session, limit=5000)
    total = len(rows)
    successes = sum(1 for r in rows if r.success)
    flagged = sum(1 for r in rows if r.is_flagged)

    by_factor = Counter(r.factor for r in rows)
    by_day: Counter = Counter()
    for r in rows:
        ts = r.timestamp
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        by_day[ts.date().isoformat()] += 1

    return jsonify({
        "total_events": total,
        "successes": successes,
        "failures": total - successes,
        "success_ratio": (successes / total) if total else 0.0,
        "flagged": flagged,
        "by_factor": dict(by_factor),
        "by_day": dict(sorted(by_day.items())),
    }), 200


@admin_bp.get("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()}), 200
