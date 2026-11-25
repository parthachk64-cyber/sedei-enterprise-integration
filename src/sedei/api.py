"""FastAPI surface for the local demo gateway. Binds to 127.0.0.1 by default (see cli `serve`)."""

from __future__ import annotations

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from sedei.system import System

MAX_BODY_BYTES = 8 * 1024


def create_app(system: System) -> FastAPI:
    app = FastAPI(title="SEDEI companion gateway (local demo)", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "demo": True}

    @app.post("/v1/orders")
    async def orders(request: Request, authorization: str | None = Header(default=None),
                     idempotency_key: str | None = Header(default=None)) -> JSONResponse:
        raw = await request.body()
        token = authorization[7:] if authorization and authorization.startswith("Bearer ") else None
        body: dict = {}
        if len(raw) > MAX_BODY_BYTES:
            r = system.gateway.handle("POST", "/v1/orders", token, {"_oversize": True}, idempotency_key)
        else:
            try:
                parsed = await request.json()
                body = parsed if isinstance(parsed, dict) else {"_invalid": True}
            except ValueError:
                body = {"_invalid": True}
            r = system.gateway.handle("POST", "/v1/orders", token, body, idempotency_key)
        return JSONResponse(status_code=r.status, content={
            "decision": r.decision, "reason": r.reason, "correlation_id": r.correlation_id,
            "workflow_id": r.workflow_id})

    return app
