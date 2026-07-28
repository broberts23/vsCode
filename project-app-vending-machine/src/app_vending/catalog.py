import json
import re
from pathlib import Path
from typing import Any

from app_vending.settings import get_catalog_path

_TEMPLATE_PATTERN = re.compile(r"\{\{parameters\.([a-zA-Z0-9_]+)\}\}")


def load_catalog(catalog_path: Path | None = None) -> dict[str, Any]:
    path = catalog_path or get_catalog_path()
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def get_offering(offering_id: str, catalog_path: Path | None = None) -> dict[str, Any]:
    catalog = load_catalog(catalog_path)
    for offering in catalog.get("offerings", []):
        if offering.get("offeringId") == offering_id:
            return offering
    raise KeyError(f"Offering '{offering_id}' was not found in the catalog.")


def merge_parameters(value: Any, parameters: dict[str, Any]) -> Any:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in parameters:
                raise KeyError(f"Missing required parameter '{key}'.")
            return str(parameters[key])

        return _TEMPLATE_PATTERN.sub(replace, value)
    if isinstance(value, list):
        return [merge_parameters(item, parameters) for item in value]
    if isinstance(value, dict):
        return {key: merge_parameters(item, parameters) for key, item in value.items()}
    return value


def resolve_offering(offering: dict[str, Any], parameters: dict[str, Any]) -> dict[str, Any]:
    return merge_parameters(offering, parameters)
