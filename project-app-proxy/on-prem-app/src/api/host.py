"""Host / VM fact endpoints. Payload content is intentionally basic."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from auth import require_api_role

router = APIRouter(prefix="/api", tags=["host"])


class HostInfo(BaseModel):
    """Basic facts about the machine running the app."""

    system: str
    release: str
    version: str
    machine: str
    node: str
    python_version: str
    os_release: dict[str, str] = Field(default_factory=dict)


def _read_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.is_file():
        return {}

    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        values[key] = raw.strip().strip('"')
    return values


@router.get("/host", response_model=HostInfo)
def get_host_info(
    _: dict[str, Any] | None = Depends(require_api_role),
) -> HostInfo:
    uname = platform.uname()
    return HostInfo(
        system=uname.system,
        release=uname.release,
        version=uname.version,
        machine=uname.machine,
        node=uname.node,
        python_version=platform.python_version(),
        os_release=_read_os_release(),
    )
