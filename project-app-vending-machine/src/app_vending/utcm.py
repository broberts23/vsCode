import json
from pathlib import Path
from typing import Any

from app_vending.settings import get_utcm_output_dir


def _load_template(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def render_utcm_monitor(
    offering: dict[str, Any],
    *,
    display_name: str,
    policy_display_name: str,
    project_root: Path,
    request_id: str,
) -> dict[str, Any]:
    utcm_config = offering.get("utcmMonitor", {})
    baseline_ref = utcm_config.get("baselineRef")
    if not baseline_ref:
        return {}

    template_path = project_root / baseline_ref
    monitor = _load_template(template_path)
    monitor["displayName"] = f"{monitor.get('displayName', 'UTCM monitor')} - {display_name}"

    resources = monitor.get("baseline", {}).get("resources", [])
    if resources:
        properties = resources[0].setdefault("properties", {})
        properties["DisplayName"] = policy_display_name
        properties["State"] = offering.get("conditionalAccess", {}).get("state", "enabledForReportingButNotEnforced")

    output_dir = get_utcm_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_name = f"{offering['offeringId']}-{request_id}.monitor.json"
    artifact_path = output_dir / artifact_name
    with artifact_path.open("w", encoding="utf-8") as handle:
        json.dump(monitor, handle, indent=2)

    return {
        "artifactPath": str(artifact_path.relative_to(project_root)).replace("\\", "/"),
        "monitor": monitor,
    }
