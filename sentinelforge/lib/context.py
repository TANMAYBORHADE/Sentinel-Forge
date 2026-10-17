from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .http import HttpResult, SafeClient


@dataclass
class ScanContext:
    """Everything a check needs. `http` is None when no --url was given."""
    url: Optional[str]
    src: Optional[Path]
    config: dict
    http: Optional[SafeClient]
    cache: dict = field(default_factory=dict)

    def home(self) -> HttpResult:
        """GET / once per scan; checks that only need the homepage share this response."""
        if "home" not in self.cache:
            self.cache["home"] = self.http.get("/", note="homepage")
        return self.cache["home"]