from fastapi import FastAPI

from api.routes.requests import router as requests_router

app = FastAPI(
    title="Application Registration Vending Machine",
    description="ITSM-facing API for governed Entra app registration, credential, and Conditional Access vending.",
    version="0.1.0",
)

app.include_router(requests_router)


@app.get("/health")
def health():
    return {"status": "ok"}
