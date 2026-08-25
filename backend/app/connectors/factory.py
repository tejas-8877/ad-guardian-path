"""Single switch point between mock and live directory collection."""

from __future__ import annotations

from functools import lru_cache

from app.connectors.base import ADConnector
from app.connectors.mock_ad import MockADConnector
from app.core.config import Settings, get_settings


def build_connector(settings: Settings | None = None) -> ADConnector:
    settings = settings or get_settings()
    if settings.ad_connector == "real":
        from app.connectors.real_ad import RealADConnector  # imported lazily: needs ldap3

        return RealADConnector(settings)
    return MockADConnector(domain=settings.ad_domain)


@lru_cache
def get_connector() -> ADConnector:
    """Process-wide connector instance (bound lazily at first use)."""
    connector = build_connector()
    connector.connect()
    return connector
