import os
from pathlib import Path


def _detect_project_root() -> Path:
    """Resolve repo root locally (src/app_vending/...) or Azure package root (app_vending/...)."""
    here = Path(__file__).resolve().parent
    for candidate in (here.parent, *here.parents[1:3]):
        if (candidate / "catalog" / "app-offerings.json").exists():
            return candidate
    return here.parents[2]


PROJECT_ROOT = _detect_project_root()
DEFAULT_CATALOG_PATH = PROJECT_ROOT / "catalog" / "app-offerings.json"
DEFAULT_UTCM_OUTPUT_DIR = PROJECT_ROOT / "samples" / "utcm" / "generated"

QUEUE_NAME = "vend-jobs"
TABLE_NAME = "VendRequests"


def get_execution_mode() -> str:
    return os.environ.get("APP_VENDING_EXECUTION_MODE", "DryRun")


def get_storage_connection_string() -> str | None:
    """Return a connection string when using Azurite or an explicit AccountKey string.

    In Azure, identity-based settings omit AzureWebJobsStorage; callers should use
    get_storage_account_name() + DefaultAzureCredential instead.
    """
    raw = os.environ.get("AzureWebJobsStorage", "").strip()
    if raw:
        return raw
    # Local DryRun default when neither a connection string nor account name is set.
    if not get_storage_account_name():
        return "UseDevelopmentStorage=true"
    return None


def uses_storage_connection_string() -> bool:
    """True when local Azurite or a classic connection string should be used."""
    cs = get_storage_connection_string()
    if not cs:
        return False
    if cs == "UseDevelopmentStorage=true":
        return True
    if "AccountKey=" in cs:
        return True
    return False


def get_storage_account_name() -> str:
    return (
        os.environ.get("AzureWebJobsStorage__accountName")
        or os.environ.get("STORAGE_ACCOUNT_NAME")
        or ""
    ).strip()


def get_worker_client_id() -> str:
    """User-assigned MI client ID for Graph (not used for Azure RBAC / storage)."""
    return (
        os.environ.get("WORKER_CLIENT_ID") or os.environ.get("AZURE_CLIENT_ID") or ""
    ).strip()


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
