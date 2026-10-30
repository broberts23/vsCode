"""FastAPI entrypoint: static site at / and host APIs under /api."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

from api.host import router as host_router
from auth import extract_bearer_token, validate_tenant_token
from config import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="On-prem lab app", version="0.1.0")
app.include_router(host_router)


@app.middleware("http")
async def require_tenant_for_static(request: Request, call_next) -> Response:
    """Enforce a valid tenant token for the static site when auth is enabled.

    /api routes use role checks via FastAPI dependencies instead.
    """
    settings = get_settings()
    path = request.url.path
    if (
        settings.local_debug
        or path.startswith("/api")
        or path == "/healthz"
        or request.method == "OPTIONS"
    ):
        return await call_next(request)

    token = extract_bearer_token(request, None)
    if not token:
        return JSONResponse(
            status_code=401,
            content={"detail": "Bearer token required."},
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        validate_tenant_token(token, settings)
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=dict(exc.headers or {}),
        )

    return await call_next(request)


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def index() -> FileResponse:
    index_path = STATIC_DIR / "index.html"
    if not index_path.is_file():
        return JSONResponse(
            status_code=500,
            content={"detail": f"Missing static file: {index_path}"},
        )
    return FileResponse(index_path)


app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    logger.info(
        "Starting on-prem app (local_debug=%s) on %s:%s",
        settings.local_debug,
        settings.host,
        settings.port,
    )
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.local_debug,
    )
