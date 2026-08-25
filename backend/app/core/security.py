"""JWT issuance and verification. No password ever touches the database."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt
from jwt import InvalidTokenError

from app.core.config import Settings
from app.core.rbac import Role

ISSUER = "adshield"
AUDIENCE = "adshield-web"


class TokenError(Exception):
    """Token missing, expired, malformed, or signed with the wrong key."""


def create_access_token(
    *,
    subject_sid: str,
    sam_account_name: str,
    display_name: str,
    role: Role,
    settings: Settings,
) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.access_token_ttl_minutes)
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": subject_sid,
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "upn": sam_account_name,
        "name": display_name,
        "role": role.value,
    }
    token = jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    return token, expires_at


def decode_access_token(token: str, settings: Settings) -> dict:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "role"]},
        )
    except InvalidTokenError as exc:  # expired, bad signature, wrong aud...
        raise TokenError(str(exc)) from exc
