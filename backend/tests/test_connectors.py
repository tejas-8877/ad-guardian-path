"""Connector contract tests. No live Active Directory is required."""

from __future__ import annotations

import pytest

from app.connectors.base import ADConnector, PrincipalType
from app.connectors.factory import build_connector
from app.connectors.mock_ad import MockADConnector
from app.core.config import Settings


def test_mock_connector_collects_full_inventory() -> None:
    with MockADConnector() as connector:
        principals, edges = connector.collect_all()

    kinds = {p.principal_type for p in principals}
    assert PrincipalType.USER in kinds
    assert PrincipalType.GROUP in kinds
    assert PrincipalType.COMPUTER in kinds
    assert PrincipalType.GPO in kinds
    assert PrincipalType.OU in kinds
    assert edges, "mock domain must expose abusable relationships"


def test_mock_connector_health_is_non_sensitive() -> None:
    connector = MockADConnector()
    connector.connect()
    health = connector.health()
    assert health.connected is True
    assert health.connector == "mock"
    assert health.protocol == "MOCK"


def test_mock_authentication_rejects_bad_password() -> None:
    from app.connectors.base import ADAuthenticationError

    connector = MockADConnector()
    with pytest.raises(ADAuthenticationError):
        connector.authenticate("j.doe", "wrong")


def test_factory_defaults_to_mock() -> None:
    connector = build_connector(Settings(ad_connector="mock"))
    assert isinstance(connector, MockADConnector)
    assert isinstance(connector, ADConnector)


def test_settings_resolve_ldaps_uri_from_host() -> None:
    s = Settings(ad_host="dc01.lab.test", ad_protocol="ldaps")
    assert s.ldap_uri == "ldaps://dc01.lab.test:636"
    assert s.ldap_port == 636
    assert s.use_ssl is True

    plain = Settings(ad_host="dc01.lab.test", ad_protocol="ldap", ad_use_ssl=False)
    assert plain.ldap_uri == "ldap://dc01.lab.test:389"
    assert plain.use_ssl is False


def test_real_connector_requires_bind_account() -> None:
    pytest.importorskip("ldap3")
    from app.connectors.base import ADConfigurationError
    from app.connectors.real_ad import RealADConnector

    connector = RealADConnector(Settings(ad_connector="real", ad_service_user=""))
    with pytest.raises(ADConfigurationError):
        connector.connect()


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("certificate verify failed", "ADConnectionError"),
        ("socket connection timed out", "ADConnectionError"),
        ("insufficientAccessRights", "ADPermissionError"),
        ("noSuchObject", "ADConfigurationError"),
    ],
)
def test_real_connector_error_translation(message: str, expected: str) -> None:
    pytest.importorskip("ldap3")
    from app.connectors.real_ad import RealADConnector

    connector = RealADConnector(
        Settings(ad_connector="real", ad_service_user="CN=svc,DC=lab", ad_service_password="x")
    )
    translated = connector._translate(RuntimeError(message))
    assert type(translated).__name__ == expected
    assert "x" not in str(translated) or "password" not in str(translated).lower()


def test_real_connector_never_falls_back_to_mock() -> None:
    pytest.importorskip("ldap3")
    from app.connectors.real_ad import RealADConnector

    connector = build_connector(
        Settings(ad_connector="real", ad_service_user="CN=svc,DC=lab", ad_service_password="x")
    )
    assert isinstance(connector, RealADConnector)
