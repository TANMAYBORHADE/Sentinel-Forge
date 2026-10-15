from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .http import SafeClient


@dataclass
class ScanContext:
    """Everything a check needs. `http` is None when no --url was given."""
    url: Optional[str]
    src: Optional[Path]
    config: dict
    http: Optional[SafeClient]
