"""Tiny local HTTP server with a 'bad' (weak) and a 'good' (hardened) personality, for check tests."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TRACE = (b"Traceback (most recent call last):\n"
         b'  File "/srv/app/views.py", line 12, in view\n    raise ValueError\n')


class Handler(BaseHTTPRequestHandler):
    bad = True

    def log_message(self, *args):
        pass

    def send_response(self, code, message=None):   # no automatic Server header
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _reply(self, code, body, extra=()):
        self.send_response(code)
        for key, value in extra:
            self.send_header(key, value)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _common(self):
        origin = self.headers.get("Origin")
        if self.bad:
            h = [("Server", "Apache/2.4.49 (Unix)"), ("X-Powered-By", "Express"),
                 ("Set-Cookie", "sid=abc123; Path=/")]
            if origin:
                h += [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
            return h
        return [("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                ("Set-Cookie", "sid=abc123; Path=/; HttpOnly; SameSite=Strict")]

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self._reply(200, b"home", self._common())
        if self.bad and path == "/.env":
            return self._reply(200, b"DB_PASSWORD=hunter2\nJWT_SECRET=topsecret-value\nPORT=3000\n", self._common())
        if self.bad and path == "/.git/HEAD":
            return self._reply(200, b"ref: refs/heads/main\n", self._common())
        if self.bad and path == "/package.json":
            return self._reply(200, b'{"name": "app", "dependencies": {"express": "4.0.0"}}', self._common())
        self._reply(404, TRACE if self.bad else b"Not found", self._common())

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._reply(500 if self.bad else 400, TRACE if self.bad else b"Bad request", self._common())


def start(bad: bool):
    handler = type("H", (Handler,), {"bad": bad})
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"