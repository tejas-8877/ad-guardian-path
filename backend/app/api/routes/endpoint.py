"""Endpoint security: static malware triage of uploaded samples."""

from __future__ import annotations

import logging

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.api.deps import CurrentUserDep, SettingsDep
from app.core.rbac import Permission
from app.schemas.domain import ScanResultOut
from app.services.malware import scan_bytes

router = APIRouter(prefix="/endpoint", tags=["endpoint"])
log = logging.getLogger("adshield.malware")


@router.post("/scan-file", response_model=ScanResultOut)
async def scan_file(
    user: CurrentUserDep,
    settings: SettingsDep,
    file: UploadFile = File(...),
) -> ScanResultOut:
    if not user.can(Permission.SUBMIT_MALWARE_SAMPLE):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not allowed to submit samples")

    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Sample exceeds {settings.max_upload_bytes // (1024 * 1024)} MB limit",
        )
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty file")

    result = scan_bytes(data, file.filename or "sample.bin", settings.yara_rules_dir)
    log.info(
        "malware.scan user=%s sha256=%s verdict=%s score=%s",
        user.sam_account_name,
        result.sha256,
        result.verdict,
        result.score,
    )
    return ScanResultOut(**vars(result))
