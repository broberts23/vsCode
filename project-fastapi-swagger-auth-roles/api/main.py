"""FastAPI entrypoint. Run from project root: uvicorn api.main:app --reload

Open Swagger at http://localhost:8000/docs (localhost required for Entra SPA redirect).
"""

from fastapi import FastAPI

from src.config import get_settings
from src.routes.identities import router as identities_router

settings = get_settings()

app = FastAPI(
    title="Identity API",
    description=(
        "Mock identity API protected by Microsoft Entra app roles "
        "(role.admin or role.service)."
    ),
    version="0.1.0",
    swagger_ui_init_oauth={
        "clientId": settings.openapi_client_id or settings.api_client_id,
        "appName": "Identity API Swagger",
        "usePkceWithAuthorizationCodeGrant": True,
        "scopes": settings.access_as_user_scope if settings.api_client_id else "",
    },
)

app.include_router(identities_router)


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}
