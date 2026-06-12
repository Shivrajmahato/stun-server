"""Configuration loading for the STUN server."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from stun.constants import DEFAULT_CONFIG_PATHS
from stun.server import ServerConfig


ENV_PREFIX = "STUN_"


def _bool(value: str | bool | None, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(value: str | int | None, default: int) -> int:
    if value is None:
        return default
    return int(value)


def _list(value: str | list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    return tuple(value)


def _load_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    return dict(data.get("server", data))


def load_config(path: str | None = None) -> ServerConfig:
    """Load config from TOML and environment variables.

    Environment variables override the file:
    STUN_HOST, STUN_PORT, STUN_METRICS_HOST, STUN_METRICS_PORT,
    STUN_LOG_LEVEL, STUN_RATE_LIMIT_PER_MINUTE, STUN_ALLOWLIST,
    STUN_INCLUDE_SOFTWARE, STUN_INCLUDE_FINGERPRINT,
    STUN_REQUIRE_FINGERPRINT, STUN_INTEGRITY_PASSWORD.
    """

    config_data: dict[str, Any] = {}
    candidates = [path] if path else list(DEFAULT_CONFIG_PATHS)
    for candidate in candidates:
        if not candidate:
            continue
        loaded = _load_toml(Path(candidate))
        if loaded:
            config_data.update(loaded)
            break

    env = os.environ
    return ServerConfig(
        host=str(env.get(f"{ENV_PREFIX}HOST", config_data.get("host", "0.0.0.0"))),
        port=_int(env.get(f"{ENV_PREFIX}PORT"), int(config_data.get("port", 3478))),
        metrics_host=str(env.get(f"{ENV_PREFIX}METRICS_HOST", config_data.get("metrics_host", "127.0.0.1"))),
        metrics_port=_int(env.get(f"{ENV_PREFIX}METRICS_PORT"), int(config_data.get("metrics_port", 8080))),
        log_level=str(env.get(f"{ENV_PREFIX}LOG_LEVEL", config_data.get("log_level", "INFO"))),
        rate_limit_per_minute=_int(
            env.get(f"{ENV_PREFIX}RATE_LIMIT_PER_MINUTE"),
            int(config_data.get("rate_limit_per_minute", 600)),
        ),
        allowlist=_list(env.get(f"{ENV_PREFIX}ALLOWLIST", config_data.get("allowlist"))),
        include_software=_bool(env.get(f"{ENV_PREFIX}INCLUDE_SOFTWARE"), bool(config_data.get("include_software", True))),
        include_fingerprint=_bool(
            env.get(f"{ENV_PREFIX}INCLUDE_FINGERPRINT"),
            bool(config_data.get("include_fingerprint", True)),
        ),
        require_fingerprint=_bool(
            env.get(f"{ENV_PREFIX}REQUIRE_FINGERPRINT"),
            bool(config_data.get("require_fingerprint", False)),
        ),
        integrity_password=env.get(f"{ENV_PREFIX}INTEGRITY_PASSWORD", config_data.get("integrity_password")),
    )
