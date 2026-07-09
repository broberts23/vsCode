from dataclasses import dataclass
import os


@dataclass(frozen=True)
class AppConfig:
    winrm_username: str
    winrm_password: str
    winrm_transport: str = "ntlm"


def load_config() -> AppConfig:
    return AppConfig(
        winrm_username=os.environ.get("WINRM_USERNAME", ""),
        winrm_password=os.environ.get("WINRM_PASSWORD", ""),
        winrm_transport=os.environ.get("WINRM_TRANSPORT", "ntlm"),
    )


def validate_config(config: AppConfig) -> None:
    missing = [
        name
        for name, value in {
            "WINRM_USERNAME": config.winrm_username,
            "WINRM_PASSWORD": config.winrm_password,
        }.items()
        if not value
    ]
    if missing:
        raise ValueError(f"Missing required settings: {', '.join(missing)}")