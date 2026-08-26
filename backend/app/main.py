"""ADShield API entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.routes import assets, attack_paths, auth, dashboard, endpoint, findings
from app.core.config import get_settings
from app.services import state

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.collect()  # warm the first snapshot
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ADShield API",
        version="1.0.0",
        description="Active Directory security assessment and attack-path analysis.",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:8080", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
    if settings.environment == "prod":
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*.corp.local", "localhost"])

    @app.middleware("http")
    async def security_headers(request, call_next):  # noqa: ANN001
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    for router in (
        auth.router,
        dashboard.router,
        assets.router,
        findings.router,
        attack_paths.router,
        endpoint.router,
    ):
        app.include_router(router, prefix="/api")

    @app.get("/api/health", tags=["ops"])
    def health() -> dict:
        return {"status": "ok", "connector": settings.ad_connector}

    return app


app = create_app()
