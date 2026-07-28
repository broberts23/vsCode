import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG_PATH = PROJECT_ROOT / "catalog" / "app-offerings.json"
DEFAULT_UTCM_OUTPUT_DIR = PROJECT_ROOT / "samples" / "utcm" / "generated"

QUEUE_NAME = "vend-jobs"
TABLE_NAME = "VendRequests"


def get_execution_mode() -> str:
    return os.environ.get("APP_VENDING_EXECUTION_MODE", "DryRun")


def get_storage_connection_string() -> str:
    return os.environ.get("AzureWebJobsStorage", "UseDevelopmentStorage=true")


def get_catalog_path() -> Path:
    raw = os.environ.get("OFFER_CATALOG_PATH")
    if raw:
        path = Path(raw)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path
    return DEFAULT_CATALOG_PATH


def get_utcm_output_dir() -> Path:
    raw = os.environ.get("UTCM_OUTPUT_DIR")
    if raw:
        path = Path(raw)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path
    return DEFAULT_UTCM_OUTPUT_DIR


def get_graph_tenant_id() -> str:
    return os.environ.get("GRAPH_TENANT_ID", "")


def get_required_roles() -> list[str]:
    raw = os.environ.get("REQUIRED_SUBMITTER_ROLES", "AppVending.Submitter,AppVending.Admin")
    return [role.strip() for role in raw.split(",") if role.strip()]


def get_auth_bypass() -> bool:
    return os.environ.get("AUTH_BYPASS", "false").lower() == "true"
