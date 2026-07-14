"""FastAPI application entry point for the SCIM 2.0 Gateway."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from scim_gateway.config import get_settings
from scim_gateway.database import init_db
from scim_gateway.routes.users import router as users_router

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    init_db()
    logger.info("SCIM Gateway database initialized")
    yield


app = FastAPI(
    title="SCIM 2.0 Gateway",
    description="RFC 7644 compliant SCIM server for Entra ID provisioning",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def bearer_token_auth(request: Request, call_next):
    """Validate SCIM bearer token on every request."""
    settings = get_settings()
    auth_header = request.headers.get("Authorization", "")

    if auth_header != f"Bearer {settings.scim_bearer_token}":
        return JSONResponse(
            status_code=401,
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "401",
                "detail": "Invalid or missing bearer token",
            },
        )

    return await call_next(request)


app.include_router(users_router, prefix="/scim/v2")


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
