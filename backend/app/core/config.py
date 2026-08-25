"""Runtime configuration. All secrets come from the environment - never code."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ADSHIELD_", extra="ignore")

    environment: Literal["dev", "staging", "prod"] = "dev"

    # --- database ---
    database_url: str = "postgresql+psycopg://adshield:adshield@localhost:5432/adshield"

    # --- JWT session ---
    jwt_secret: SecretStr = SecretStr("change-me-in-env")
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 30

    # --- Active Directory ---
    ad_connector: Literal["mock", "real"] = "mock"
    ad_domain: str = "corp.local"
    ad_domain_dns: str = "corp.local"
    ad_base_dn: str = "DC=corp,DC=local"
    ad_server_uri: str = "ldaps://dc01.corp.local:636"
    ad_use_ssl: bool = True
    ad_ca_cert_path: str | None = None
    # Least-privilege, read-only service account used for collection only.
    ad_service_user: str = "CN=svc-adshield-ro,OU=Service Accounts,DC=corp,DC=local"
    ad_service_password: SecretStr = SecretStr("")

    # --- RBAC mapping: AD group DN/name -> ADShield role ---
    role_security_admin_groups: list[str] = Field(default_factory=lambda: ["ADShield-SOC"])
    role_it_support_groups: list[str] = Field(default_factory=lambda: ["ADShield-Helpdesk"])

    # --- malware engine ---
    yara_rules_dir: str = "rules"
    max_upload_bytes: int = 32 * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
