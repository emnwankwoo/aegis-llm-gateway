"""API-key authentication with two roles: client (chat) and admin (audit).

* Keys arrive in the `X-API-Key` header — never in the URL, where they'd end up
  in proxy logs and browser history.
* Comparison hashes both sides and uses hmac.compare_digest, so timing doesn't
  leak how many characters matched (or the configured key length).
* Only a short SHA-256 fingerprint of the key is ever logged.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.config import Settings, get_settings
from app.schemas import Action, AuditEvent, Stage

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass(frozen=True)
class Principal:
    key_id: str   # fingerprint, safe to log
    role: str     # "client" | "admin"


def fingerprint(key: str) -> str:
    return "key_" + hashlib.sha256(key.encode()).hexdigest()[:12]


def _matches_any(candidate: str, allowed: list[str]) -> bool:
    cand = hashlib.sha256(candidate.encode()).digest()
    matched = False
    for key in allowed:  # no early exit: constant work regardless of position
        if hmac.compare_digest(cand, hashlib.sha256(key.encode()).digest()):
            matched = True
    return matched


def _reject(request: Request, api_key: str | None, reason: str) -> HTTPException:
    audit = getattr(request.app.state, "audit", None)
    if audit is not None:
        audit.record(AuditEvent(
            request_id=getattr(request.state, "request_id", None),
            client_id=fingerprint(api_key) if api_key else "anonymous",
            stage=Stage.AUTH,
            action=Action.BLOCK,
            risk_score=0.0,
            triggered_rules=["AUTH-001"],
            details={"reason": reason, "path": request.url.path},
        ))
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key",
        headers={"WWW-Authenticate": "APIKey"},
    )


async def require_client(
    request: Request,
    api_key: str | None = Security(api_key_header),
    settings: Settings = Depends(get_settings),
) -> Principal:
    if not api_key or not _matches_any(api_key, settings.client_keys):
        raise _reject(request, api_key, "client key rejected")
    return Principal(key_id=fingerprint(api_key), role="client")


async def require_admin(
    request: Request,
    api_key: str | None = Security(api_key_header),
    settings: Settings = Depends(get_settings),
) -> Principal:
    if not api_key or not _matches_any(api_key, settings.admin_keys):
        raise _reject(request, api_key, "admin key rejected")
    return Principal(key_id=fingerprint(api_key), role="admin")
