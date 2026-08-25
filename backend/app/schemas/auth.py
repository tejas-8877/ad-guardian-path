from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.core.rbac import Permission, Role


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=256, examples=["j.doe"])
    password: str = Field(min_length=1, max_length=512, repr=False)


class UserProfile(BaseModel):
    object_sid: str
    sam_account_name: str
    display_name: str
    email: str | None = None
    role: Role
    permissions: list[Permission]


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: UserProfile
