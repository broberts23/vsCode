"""FastAPI entrypoint. Run from project root: uvicorn api.main:app --reload"""

from fastapi import FastAPI

from src.routes.identities import router as identities_router

app = FastAPI(
    title="Identity API",
    description="Mock identity API (Entra auth deferred).",
    version="0.1.0",
)

app.include_router(identities_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
