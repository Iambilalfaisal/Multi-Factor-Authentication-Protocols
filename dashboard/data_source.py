"""Data-access layer for the dashboard, with HTTP and EMBEDDED backends.

The dashboard never talks to the database or services directly; it goes through
``DataSource``. Two implementations are provided:

* :class:`HttpDataSource`     - calls the Flask REST API over HTTP. This is the
  production-shaped path and what you'd use when the API is deployed separately.
* :class:`EmbeddedDataSource` - imports the service layer and runs queries
  in-process. This lets a single Streamlit Community Cloud container serve the
  whole demo without a reachable external API.

The active backend is chosen by environment: ``EMBEDDED=1`` selects the embedded
source, otherwise the HTTP source pointed at ``API_BASE_URL``.
"""

from __future__ import annotations

import os
from typing import Protocol

import requests


class DataSource(Protocol):
    """Read/admin operations the dashboard needs."""

    def list_users(self) -> list[dict]: ...
    def create_user(self, username: str, email: str, password: str) -> dict: ...
    def set_active(self, user_id: int, is_active: bool) -> dict: ...
    def delete_user(self, user_id: int) -> None: ...
    def list_events(self, user_id: int | None, flagged_only: bool, limit: int) -> list[dict]: ...
    def analytics(self) -> dict: ...


class HttpDataSource:
    """Talks to the Flask API over HTTP."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _get(self, path: str, **params):
        resp = requests.get(f"{self.base_url}{path}", params=params, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload: dict):
        resp = requests.post(f"{self.base_url}{path}", json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def _patch(self, path: str, payload: dict):
        resp = requests.patch(f"{self.base_url}{path}", json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def _delete(self, path: str):
        resp = requests.delete(f"{self.base_url}{path}", timeout=15)
        resp.raise_for_status()
        return resp.json()

    def list_users(self) -> list[dict]:
        return self._get("/api/admin/users")["users"]

    def create_user(self, username: str, email: str, password: str) -> dict:
        return self._post("/api/admin/users", {
            "username": username, "email": email, "password": password,
        })["user"]

    def set_active(self, user_id: int, is_active: bool) -> dict:
        return self._patch(f"/api/admin/users/{user_id}", {"is_active": is_active})["user"]

    def delete_user(self, user_id: int) -> None:
        self._delete(f"/api/admin/users/{user_id}")

    def list_events(self, user_id=None, flagged_only=False, limit=500) -> list[dict]:
        params = {"flagged_only": str(flagged_only).lower(), "limit": limit}
        if user_id is not None:
            params["user_id"] = user_id
        return self._get("/api/admin/events", **params)["events"]

    def analytics(self) -> dict:
        return self._get("/api/admin/analytics")


class EmbeddedDataSource:
    """Runs queries in-process via the service layer (no HTTP)."""

    def __init__(self):
        # Imported lazily so the HTTP path doesn't require the backend package.
        from backend.extensions import SessionLocal, init_db

        init_db()
        self._SessionLocal = SessionLocal

    def _session(self):
        return self._SessionLocal()

    def list_users(self) -> list[dict]:
        from backend.services.users import list_users

        s = self._session()
        try:
            return [u.to_dict() for u in list_users(s)]
        finally:
            self._SessionLocal.remove()

    def create_user(self, username: str, email: str, password: str) -> dict:
        from backend.services.users import create_user

        s = self._session()
        try:
            return create_user(s, username=username, email=email, password=password).to_dict()
        finally:
            self._SessionLocal.remove()

    def set_active(self, user_id: int, is_active: bool) -> dict:
        from backend.services.users import set_active

        s = self._session()
        try:
            return set_active(s, user_id, is_active).to_dict()
        finally:
            self._SessionLocal.remove()

    def delete_user(self, user_id: int) -> None:
        from backend.services.users import delete_user

        s = self._session()
        try:
            delete_user(s, user_id)
        finally:
            self._SessionLocal.remove()

    def list_events(self, user_id=None, flagged_only=False, limit=500) -> list[dict]:
        from backend.services.events import list_events

        s = self._session()
        try:
            return [e.to_dict() for e in list_events(
                s, user_id=user_id, flagged_only=flagged_only, limit=limit
            )]
        finally:
            self._SessionLocal.remove()

    def analytics(self) -> dict:
        from collections import Counter
        from datetime import timezone

        from backend.services.events import list_events

        s = self._session()
        try:
            rows = list_events(s, limit=5000)
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
            return {
                "total_events": total,
                "successes": successes,
                "failures": total - successes,
                "success_ratio": (successes / total) if total else 0.0,
                "flagged": flagged,
                "by_factor": dict(by_factor),
                "by_day": dict(sorted(by_day.items())),
            }
        finally:
            self._SessionLocal.remove()


def get_data_source() -> DataSource:
    """Factory: pick the backend based on the environment."""
    embedded = os.environ.get("EMBEDDED", "0").strip().lower() in {"1", "true", "yes", "on"}
    if embedded:
        return EmbeddedDataSource()
    return HttpDataSource(os.environ.get("API_BASE_URL", "http://localhost:5000"))
