"""HTTP wrapper: every request is allowlist-checked and recorded as Evidence."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urljoin

import requests

from .. import __version__
from ..models import MAX_BODY_CHARS, Evidence
from .allowlist import check_target

MAX_REDIRECTS = 5


@dataclass
class HttpResult:
    response: requests.Response
    evidence: Evidence


def _to_text(data, limit: int = MAX_BODY_CHARS) -> Optional[str]:
    if data is None:
        return None
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    return data[:limit]


def _response_headers(resp: requests.Response) -> dict:
    headers = dict(resp.headers)
    try:  # keep multiple Set-Cookie headers separate
        cookies = resp.raw.headers.getlist("Set-Cookie")
        if cookies:
            headers["Set-Cookie"] = "\n".join(cookies)
    except Exception:
        pass
    return headers


class SafeClient:
    def __init__(self, base_url: str, allowed_hosts: Iterable[str] = (), timeout: float = 10):
        self.base_url = base_url.rstrip("/") + "/"
        self.allowed_hosts = list(allowed_hosts)
        self.timeout = timeout
        check_target(self.base_url, self.allowed_hosts)
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"SentinelForge/{__version__} (local security scan)"

    def clone(self) -> "SafeClient":
        """A client with a fresh cookie jar (for 'unauthenticated' or other-user requests)."""
        return SafeClient(self.base_url, self.allowed_hosts, self.timeout)

    def request(self, method: str, path_or_url: str, *, headers: Optional[dict] = None,
                json=None, data=None, params=None, follow_redirects: bool = False,
                note: str = "") -> HttpResult:
        url = urljoin(self.base_url, path_or_url)
        for _ in range(MAX_REDIRECTS + 1):
            check_target(url, self.allowed_hosts)  # every hop, every time
            prepared = self.session.prepare_request(
                requests.Request(method.upper(), url, headers=headers, json=json,
                                 data=data, params=params))
            start = time.perf_counter()
            resp = self.session.send(prepared, timeout=self.timeout, allow_redirects=False)
            elapsed = (time.perf_counter() - start) * 1000

            evidence = Evidence(
                method=prepared.method, url=prepared.url,
                request_headers=dict(prepared.headers),
                request_body=_to_text(prepared.body),
                status_code=resp.status_code,
                response_headers=_response_headers(resp),
                response_body=_to_text(resp.content) or "",
                elapsed_ms=elapsed, note=note,
            )
            location = resp.headers.get("Location")
            if follow_redirects and resp.is_redirect and location:
                url = urljoin(url, location)
                method, json, data, params = "GET", None, None, None
                continue
            return HttpResult(resp, evidence)
        raise requests.TooManyRedirects(f"more than {MAX_REDIRECTS} redirects from {url}")

    def get(self, path, **kw) -> HttpResult:
        return self.request("GET", path, **kw)

    def post(self, path, **kw) -> HttpResult:
        return self.request("POST", path, **kw)
