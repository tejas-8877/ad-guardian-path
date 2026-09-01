"""Directory connection health and on-demand collection.

Mode (mock | real) comes from ADSHIELD_AD_CONNECTOR. REAL mode never falls
back to mock: failures are reported verbatim (minus any secret material).
"""

from __future__ import annotations

import logging
import time
from collections import Counter

from fastapi import APIRouter, HTTPException, status

from app.api.deps import RequireAssets, RequireSecurityAdmin, SettingsDep
from app.connectors.base import (
    ADAuthenticationError,
    ADConfigurationError,
    ADConnectionError,
    ADPermissionError,
    PrincipalType,
)
from app.connectors.factory import get_connector
from app.schemas.domain import ADHealthOut, CollectionStatsOut
from app.services import state

router = APIRouter(prefix="/ad", tags=["active-directory"])
log = logging.getLogger("adshield.ad")

_ERROR_STATUS = {
    ADAuthenticationError: status.HTTP_401_UNAUTHORIZED,
    ADPermissionError: status.HTTP_403_FORBIDDEN,
    ADConfigurationError: status.HTTP_400_BAD_REQUEST,
    ADConnectionError: status.HTTP_503_SERVICE_UNAVAILABLE,
}


def _http_error(exc: Exception) -> HTTPException:
    code = next(
        (v for k, v in _ERROR_STATUS.items() if isinstance(exc, k)),
        status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
    # Connector errors are already sanitised (no credentials in the message).
    return HTTPException(code, str(exc) or exc.__class__.__name__)


@router.get("/health", response_model=ADHealthOut)
def ad_health(_user: RequireAssets, settings: SettingsDep) -> ADHealthOut:
    try:
        connector = get_connector()
        health = connector.health()
    except Exception as exc:  # noqa: BLE001 - reported, never swallowed
        log.error("ad.health.failed connector=%s error=%s", settings.ad_connector, exc)
        return ADHealthOut(
            connected=False,
            connector=settings.ad_connector,
            domain=settings.ad_domain,
            server=settings.ldap_host if settings.ad_connector == "real" else settings.ad_domain,
            protocol="LDAPS" if settings.use_ssl else "LDAP",
            port=settings.ldap_port if settings.ad_connector == "real" else 0,
            base_dn=settings.ad_base_dn,
            error=str(exc),
        )

    return ADHealthOut(
        connected=health.connected,
        connector=settings.ad_connector,
        domain=health.domain,
        server=health.server,
        protocol=health.protocol,
        port=health.port,
        base_dn=health.base_dn or settings.ad_base_dn,
        latency_ms=health.latency_ms,
        error=health.error,
    )


@router.post("/collect", response_model=CollectionStatsOut)
def ad_collect(user: RequireSecurityAdmin, settings: SettingsDep) -> CollectionStatsOut:
    started = time.perf_counter()
    try:
        snapshot = state.collect()
    except Exception as exc:  # noqa: BLE001
        log.error(
            "ad.collect.failed user=%s connector=%s error=%s",
            user.sam_account_name, settings.ad_connector, exc,
        )
        raise _http_error(exc) from None

    types = Counter(p.principal_type for p in snapshot.principals)
    duration = int((time.perf_counter() - started) * 1000)
    log.info(
        "ad.collect.success user=%s connector=%s principals=%s edges=%s duration_ms=%s",
        user.sam_account_name, settings.ad_connector,
        len(snapshot.principals), len(snapshot.edges), duration,
    )
    return CollectionStatsOut(
        status="success",
        connector=settings.ad_connector,
        domain=snapshot.domain,
        users=types[PrincipalType.USER],
        groups=types[PrincipalType.GROUP],
        computers=types[PrincipalType.COMPUTER],
        gpos=types[PrincipalType.GPO],
        ous=types[PrincipalType.OU],
        relationships=len(snapshot.edges),
        findings=len(snapshot.findings),
        risk_score=snapshot.risk_score,
        duration_ms=duration,
        collected_at=snapshot.collected_at,
    )
