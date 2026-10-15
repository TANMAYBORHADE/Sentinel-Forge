"""config.yaml loading with safe defaults."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Optional

import yaml

DEFAULTS = {
    "target": {"base_url": None, "allowed_hosts": []},
    "http": {"timeout": 10},
    "auth": {"login_route": None, "signup_route": None, "users": []},
    "upload": {"route": None},
    "checks": {"run": ["all"], "skip": []},
    "storage": {"db_path": "sentinelforge.db"},
}


def _merge(base: dict, override: dict) -> dict:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        elif value is not None:
            base[key] = value
    return base


def load_config(path: Optional[str] = None) -> dict:
    """Explicit path must exist. With no path, ./config.yaml is used if present."""
    config = copy.deepcopy(DEFAULTS)
    if path is None:
        default = Path("config.yaml")
        path = str(default) if default.exists() else None
    if path is None:
        return config
    with open(path, encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    return _merge(config, loaded)
