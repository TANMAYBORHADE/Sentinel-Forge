import pytest

from sentinelforge.lib.allowlist import TargetNotAllowed, check_target


@pytest.mark.parametrize("url", [
    "http://localhost:5000", "http://127.0.0.1:3000/api", "https://localhost", "http://[::1]:8080/",
])
def test_local_targets_allowed(url):
    assert check_target(url)


@pytest.mark.parametrize("url", [
    "https://example.com",
    "http://localhost.evil.com",          # look-alike host
    "http://127.0.0.1@evil.com/",         # userinfo trick: real host is evil.com
    "http://evil.com/?x=localhost",
    "ftp://localhost/",
    "localhost:5000",                     # no scheme
    "http://localhost:notaport",
    "",
])
def test_everything_else_refused(url):
    with pytest.raises(TargetNotAllowed):
        check_target(url)


def test_config_allowlist_extends():
    assert check_target("http://staging.internal:8000", ["staging.internal"]) == "staging.internal"
    with pytest.raises(TargetNotAllowed):
        check_target("http://other.internal", ["staging.internal"])
