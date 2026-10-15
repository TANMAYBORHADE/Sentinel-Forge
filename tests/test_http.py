import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinelforge.lib.allowlist import TargetNotAllowed
from sentinelforge.lib.http import SafeClient


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Set-Cookie", "sid=abc123; HttpOnly")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_request_records_evidence(server):
    result = SafeClient(server).get("/", note="smoke")
    ev = result.evidence
    assert ev.status_code == 200 and ev.response_body == "hello" and ev.note == "smoke"
    assert ev.request_headers["User-Agent"].startswith("SentinelForge/")
    assert "HttpOnly" in ev.response_headers["Set-Cookie"]


def test_absolute_url_to_other_host_is_blocked(server):
    with pytest.raises(TargetNotAllowed):
        SafeClient(server).get("http://example.com/")


def test_redirect_to_other_host_is_blocked(server):
    client = SafeClient(server)
    assert client.get("/redirect-out").evidence.status_code == 302   # not followed by default
    with pytest.raises(TargetNotAllowed):
        client.get("/redirect-out", follow_redirects=True)


def test_client_refuses_non_local_base_url():
    with pytest.raises(TargetNotAllowed):
        SafeClient("https://example.com")
