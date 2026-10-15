"""Target allowlist. SentinelForge refuses to touch anything that isn't yours (Rule 7)."""
from __future__ import annotations

from typing import Iterable
from urllib.parse import urlsplit

DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1", "::1")


class TargetNotAllowed(Exception):
    """Raised when a URL points somewhere the scanner must not go."""


def allowed_hosts(extra: Iterable[str] = ()) -> set:
    return {h.strip().lower() for h in (*DEFAULT_ALLOWED_HOSTS, *extra) if h and h.strip()}


def check_target(url: str, extra_hosts: Iterable[str] = ()) -> str:
    """Return the hostname if the URL is allowed, otherwise raise TargetNotAllowed."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018  (raises ValueError on a bad port)
    except ValueError as exc:
        raise TargetNotAllowed(f"'{url}' is not a valid URL ({exc})") from exc

    if parts.scheme not in ("http", "https"):
        raise TargetNotAllowed(f"'{url}': only http and https targets are supported")
    if not host:
        raise TargetNotAllowed(f"'{url}' has no host")

    allowed = allowed_hosts(extra_hosts)
    if host.lower() not in allowed:
        raise TargetNotAllowed(
            f"host '{host}' is not in the allowlist ({', '.join(sorted(allowed))}). "
            "Only add a host to allowed_hosts in config.yaml if you own it and it is not production."
        )
    return host.lower()
