"""FastAPI entrypoint: static site at / and host APIs under /api.

Interactive HTML is gated by App Proxy Entra pre-auth (Authorization is not
forwarded to the backend). /api validates Entra JWTs from Authorization Bearer
or X-OnPrem-Access-Token and requires the configured app role.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.host import router as host_router
from config import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="On-prem lab app", version="0.1.0")
app.include_router(host_router)


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
