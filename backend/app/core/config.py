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
    # Either provide a full URI (ad_server_uri) or host/port/protocol; the
    # effective URI is resolved by `ldap_uri` below. Nothing is hardcoded to a
    # specific lab: every value is overridable via ADSHIELD_* env vars.
    ad_server_uri: str | None = None
    ad_host: str | None = None
    ad_port: int | None = None
    ad_protocol: Literal["ldaps", "ldap"] = "ldaps"
    ad_use_ssl: bool = True
    ad_verify_certificate: bool = True
    ad_ca_cert_path: str | None = None
    ad_connect_timeout_seconds: int = 10
    ad_page_size: int = 500
    # Least-privilege, read-only service account used for collection only.
    ad_service_user: str = ""
    ad_service_password: SecretStr = SecretStr("")

    # --- derived helpers ---
    @property
    def ldap_port(self) -> int:
        if self.ad_port:
            return self.ad_port
        return 636 if self.ad_protocol == "ldaps" else 389

    @property
    def ldap_uri(self) -> str:
        """Effective LDAP(S) URI, from ad_server_uri or host/port/protocol."""
        if self.ad_server_uri:
            return self.ad_server_uri
        host = self.ad_host or self.ad_domain_dns
        return f"{self.ad_protocol}://{host}:{self.ldap_port}"

    @property
    def ldap_host(self) -> str:
        uri = self.ldap_uri
        return uri.split("://", 1)[-1].rsplit(":", 1)[0]

    @property
    def use_ssl(self) -> bool:
        return self.ad_use_ssl and self.ldap_uri.startswith("ldaps://")


    # --- RBAC mapping: AD group DN/name -> ADShield role ---
    role_security_admin_groups: list[str] = Field(default_factory=lambda: ["ADShield-SOC"])
    role_it_support_groups: list[str] = Field(default_factory=lambda: ["ADShield-Helpdesk"])

    # --- malware engine ---
    yara_rules_dir: str = "rules"
    max_upload_bytes: int = 32 * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
