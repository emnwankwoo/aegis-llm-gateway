"""AegisGate — FastAPI security gateway in front of an LLM provider.

Request lifecycle for POST /v1/chat:
  auth -> rate limit -> input guard -> upstream LLM -> output guard -> audit -> client
"""

from __future__ import annotations

import hashlib
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, Query, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.config import Settings, get_settings
from app.schemas import (
    Action, AuditEvent, AuditStats, ChatRequest, ChatResponse, Finding, Stage,
)
from app.security.auth import Principal, require_admin, require_client
from app.security.input_guard import InputGuard
from app.security.output_guard import OutputGuard
from app.security.rate_limit import SlidingWindowRateLimiter
from app.services.audit import AuditLogger
from app.services.llm_client import UpstreamError, build_llm_client

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.llm = build_llm_client(settings)
        app.state.audit = AuditLogger(settings.audit_log_path, settings.audit_buffer_size)
        app.state.limiter = SlidingWindowRateLimiter(
            settings.rate_limit_requests, settings.rate_limit_window_seconds
        )
        app.state.input_guard = InputGuard(settings.injection_block_threshold)
        app.state.output_guard = OutputGuard(settings.url_allowlist, settings.system_prompt)
        yield
        await app.state.llm.aclose()

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if settings.expose_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.expose_docs else None,
    )
    app.dependency_overrides[get_settings] = lambda: settings

    # ------------------------------------------------------------ middleware
    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        request.state.request_id = uuid4().hex
        # Reject oversized bodies before they're parsed (cheap DoS protection).
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_body_bytes:
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    # ---------------------------------------------------------------- routes
    @app.get("/health", tags=["ops"])
    async def health() -> dict:
        return {"status": "ok", "version": __version__, "provider": settings.llm_provider}

    @app.post("/v1/chat", response_model=ChatResponse, tags=["gateway"],
              responses={403: {"model": ChatResponse}, 429: {}, 502: {}})
    async def chat(body: ChatRequest, request: Request,
                   principal: Principal = Depends(require_client)):
        state = request.app.state
        request_id: str = request.state.request_id
        started = time.perf_counter()
        prompt_hash = hashlib.sha256(body.prompt.encode()).hexdigest()

        def audit(stage: Stage, action: Action, risk: float, findings: list[Finding],
                  **details) -> None:
            state.audit.record(AuditEvent(
                request_id=request_id, client_id=principal.key_id, stage=stage,
                action=action, risk_score=risk,
                triggered_rules=[f.rule_id for f in findings] + details.pop("extra_rules", []),
                prompt_sha256=prompt_hash,
                latency_ms=round((time.perf_counter() - started) * 1000, 2),
                details=details,
            ))

        # 1. Rate limit (Denial-of-Wallet)
        allowed, retry_after = state.limiter.check(principal.key_id)
        if not allowed:
            audit(Stage.RATE_LIMIT, Action.BLOCK, 0.0, [], extra_rules=["RL-001"],
                  retry_after=retry_after)
            return JSONResponse(
                {"detail": "Rate limit exceeded", "request_id": request_id},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(retry_after)},
            )

        # 2. Input guardrails
        verdict = state.input_guard.inspect(body.prompt)
        audit(Stage.INPUT, verdict.action, verdict.risk_score, verdict.findings,
              redactions=verdict.redactions, prompt_chars=len(body.prompt))

        if verdict.action == Action.BLOCK:
            blocked = ChatResponse(
                request_id=request_id, action=Action.BLOCK, risk_score=verdict.risk_score,
                input_findings=verdict.findings, redactions=verdict.redactions,
                message="Prompt blocked by security policy.",
            )
            return JSONResponse(blocked.model_dump(mode="json"),
                                status_code=status.HTTP_403_FORBIDDEN)

        # 3. Upstream call with a per-request canary planted in the system prompt
        canary = f"AEGIS-CANARY-{secrets.token_hex(8)}"
        system = f"{settings.system_prompt}\n[internal reference id: {canary}]"
        try:
            result = await state.llm.complete(system, verdict.sanitized_prompt,
                                              settings.max_output_tokens)
            flagged = settings.enable_moderation and await state.llm.moderate(result.text)
        except UpstreamError as exc:
            audit(Stage.UPSTREAM, Action.BLOCK, 0.0, [], extra_rules=["UP-001"], error=str(exc))
            return JSONResponse({"detail": "Upstream model unavailable", "request_id": request_id},
                                status_code=status.HTTP_502_BAD_GATEWAY)

        # 4. Output guardrails
        out = state.output_guard.inspect(result.text, canary=canary)
        if flagged:
            out.findings.append(Finding(rule_id="OUT-006", category="harmful_content",
                                        description="Flagged by moderation model", weight=1.0))
            out.action, out.text, out.risk_score = Action.BLOCK, None, 1.0

        audit(Stage.OUTPUT, out.action, out.risk_score, out.findings,
              redactions=out.redactions, model=result.model,
              completion_tokens=result.completion_tokens)

        combined_redactions = dict(verdict.redactions)
        for k, v in out.redactions.items():
            combined_redactions[k] = combined_redactions.get(k, 0) + v

        final_action = (Action.BLOCK if out.action == Action.BLOCK
                        else Action.REDACT if Action.REDACT in (verdict.action, out.action)
                        else Action.ALLOW)
        response = ChatResponse(
            request_id=request_id,
            action=final_action,
            response=out.text,
            risk_score=max(verdict.risk_score, out.risk_score),
            input_findings=verdict.findings,
            output_findings=out.findings,
            redactions=combined_redactions,
            model=result.model,
            message="Response withheld by output policy." if out.action == Action.BLOCK else None,
        )
        code = status.HTTP_403_FORBIDDEN if final_action == Action.BLOCK else status.HTTP_200_OK
        return JSONResponse(response.model_dump(mode="json"), status_code=code)

    @app.get("/v1/audit/events", response_model=list[AuditEvent], tags=["audit"])
    async def audit_events(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
        action: Action | None = None,
        _: Principal = Depends(require_admin),
    ):
        return request.app.state.audit.recent(limit=limit, action=action)

    @app.get("/v1/audit/stats", response_model=AuditStats, tags=["audit"])
    async def audit_stats(request: Request, _: Principal = Depends(require_admin)):
        return request.app.state.audit.stats()

    # -------------------------------------------------------------- frontend
    if FRONTEND_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

        @app.get("/", include_in_schema=False)
        async def index():
            return FileResponse(FRONTEND_DIR / "index.html")

    return app


app = create_app()
