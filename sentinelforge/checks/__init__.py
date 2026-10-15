"""Check registry. Add a check by dropping a module in this package and decorating a function:

    from . import register
    from ..models import Finding

    @register("HDR-001", "Content-Security-Policy present", group="headers", requires="live")
    def csp(ctx):
        result = ctx.http.get("/")
        ...
        return [Finding(...)]
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from typing import Callable

REGISTRY: dict = {}


@dataclass
class Check:
    id: str
    title: str
    group: str
    requires: str          # "live" | "source" | "both"
    fn: Callable


def register(check_id: str, title: str, group: str, requires: str = "live"):
    if requires not in ("live", "source", "both"):
        raise ValueError("requires must be 'live', 'source' or 'both'")

    def decorator(fn):
        REGISTRY[check_id] = Check(check_id, title, group, requires, fn)
        return fn
    return decorator


def load_all() -> None:
    for module in pkgutil.iter_modules(__path__):
        importlib.import_module(f"{__name__}.{module.name}")


def all_checks() -> list:
    load_all()
    return list(REGISTRY.values())
