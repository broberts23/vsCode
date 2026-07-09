from dataclasses import asdict, dataclass, is_dataclass
import json
from pathlib import Path
from typing import Any

from shared.config import AppConfig


class PowerShellError(RuntimeError):
    pass


class ScriptTimeoutError(RuntimeError):
    pass


class JsonEncoder(json.JSONEncoder):
    def default(self, value: Any) -> Any:
        if is_dataclass(value):
            return asdict(value)
        return super().default(value)


def to_json(value: Any, status_code: int = 200) -> str:
    return json.dumps(value, cls=JsonEncoder)


def script_path(script_name: str) -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / script_name


@dataclass(frozen=True)
class PowerShellResult:
    stdout: str
    stderr: str
    status_code: int

    @property
    def succeeded(self) -> bool:
        return self.status_code == 0


class WinRMPowerShellRunner:
    def __init__(
        self,
        target_host: str,
        config: AppConfig,
        cert_thumbprint: str | None = None,
    ) -> None:
        import winrm

        endpoint = f"https://{target_host}:5986/wsman"
        self.session = winrm.Session(
            endpoint,
            auth=(config.winrm_username, config.winrm_password),
            transport=config.winrm_transport,
            server_cert_validation="ignore",
        )
        self.target_host = target_host
        self.cert_thumbprint = cert_thumbprint

    def run_script(self, script_name: str, parameters: dict[str, Any] | None = None, timeout: int = 120) -> PowerShellResult:
        import concurrent.futures

        path = script_path(script_name)
        script = path.read_text(encoding="utf-8")
        invocation = _build_invocation(script, parameters or {})

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(self._run_ps, invocation)
            try:
                raw = future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                raise ScriptTimeoutError(
                    f"PowerShell script {script_name} timed out after {timeout}s"
                )
            stdout = raw.std_out.decode("utf-8", errors="replace")
            stderr = raw.std_err.decode("utf-8", errors="replace")
            return PowerShellResult(stdout=stdout, stderr=stderr, status_code=raw.status_code)
        finally:
            executor.shutdown(wait=False)

    def _run_ps(self, invocation: str) -> Any:
        return self.session.run_ps(invocation)


def require_success(result: PowerShellResult) -> None:
    if not result.succeeded:
        raise PowerShellError(result.stderr or result.stdout or f"PowerShell failed with {result.status_code}")


def _build_invocation(script: str, parameters: dict[str, Any]) -> str:
    body = _strip_param_block(script)
    assignments = "; ".join(
        f"${name} = {_format_value(value)}"
        for name, value in parameters.items()
        if value is not None
    )
    if assignments:
        return f"{assignments}; & {{\n{body}\n}}"
    return f"& {{\n{body}\n}}"


def _strip_param_block(script: str) -> str:
    """Remove the param(...) block so we control variable assignment."""
    lines = script.splitlines()
    in_param = False
    result: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("param("):
            in_param = True
            # Check if the closing ')' is on the same line (single-line param block)
            paren_idx = stripped.index("(")
            if ")" in stripped[paren_idx + 1:]:
                in_param = False
            continue
        if in_param and stripped == ")":
            in_param = False
            continue
        if not in_param:
            result.append(line)
    return "\n".join(result).strip()


def _format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, list):
        return "@(" + ", ".join(_format_value(item) for item in value) + ")"
    escaped = str(value).replace("'", "''")
    return f"'{escaped}'"
