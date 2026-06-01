"""User management service (admin operations + lookups)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..crypto.passwords import hash_password
from ..models import User


class UserError(Exception):
    """Raised for user-facing user-management errors (duplicate, missing)."""


def create_user(
    session: Session,
    *,
    username: str,
    email: str,
    password: str,
    is_admin: bool = False,
) -> User:
    """Create a user with an Argon2id-hashed password."""
    username = username.strip()
    email = email.strip().lower()
    if not username or not email or not password:
        raise UserError("username, email and password are required")

    exists = session.scalar(
        select(User).where((User.username == username) | (User.email == email))
    )
    if exists is not None:
        raise UserError("a user with that username or email already exists")

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_admin=is_admin,
    )
    session.add(user)
    session.commit()
    return user


def get_user(session: Session, user_id: int) -> User | None:
    return session.get(User, user_id)


def get_user_by_username(session: Session, username: str) -> User | None:
    return session.scalar(select(User).where(User.username == username.strip()))


def list_users(session: Session) -> list[User]:
    return list(session.scalars(select(User).order_by(User.id.asc())))


def set_active(session: Session, user_id: int, is_active: bool) -> User:
    """Enable/disable a user account (admin action)."""
    user = session.get(User, user_id)
    if user is None:
        raise UserError("user not found")
    user.is_active = is_active
    session.commit()
    return user
