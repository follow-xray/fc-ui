import hmac
import json
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from manager import LIMIT
from profiles import TEMPLATES

ASSETS = Path(__file__).parent
PUBLIC_HOST = Path("/etc/fc-ui/public-host")


def start_panel(manager, port):
    secret = json.loads(manager.token.read_text())

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass  # Request targets and sharing links never enter access logs.

        def reply(self, status, value, mime="application/json"):
            body = json.dumps(value, ensure_ascii=False).encode() if mime == "application/json" else value
            self.send_response(status)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def local_request(self):
            host = self.headers.get("Host", "")
            origin = self.headers.get("Origin")
            if not re.fullmatch(r"(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?", host) or (origin and origin != "http://" + host):
                self.reply(403, {"error": "请通过本机 SSH 隧道打开面板"})
                return False
            return True

        def do_GET(self):
            if not self.local_request(): return
            public = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "application/javascript"), "/style.css": ("style.css", "text/css")}
            if self.path not in public:
                self.reply(404, {"error": "未找到"})
                return
            name, mime = public[self.path]
            self.reply(200, (ASSETS/name).read_bytes(), mime)

        def do_POST(self):
            if not self.local_request(): return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer "+secret).encode()):
                self.reply(401, {"error": "管理口令无效"})
                return
            if self.path != "/api" or self.headers.get_content_type() != "application/json":
                self.reply(400, {"error": "请求格式无效"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= LIMIT: raise ValueError("请求大小无效")
                req = json.loads(self.rfile.read(length))
                if not isinstance(req, dict) or not isinstance(req.get("data", {}), dict):
                    raise ValueError("请求必须是对象")
                if req.get("op") == "templates":
                    result = {"templates": {k:t.form() for k,t in TEMPLATES.items()}, "host": PUBLIC_HOST.read_text().strip() if PUBLIC_HOST.exists() else ""}
                else:
                    result = manager.call(req.get("op"), req.get("data", {}))
                self.reply(200, {"result": result})
            except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError) as exc:
                self.reply(400, {"error": str(exc)})

    # Deliberately no configurable HTTP listen address, including via environment.
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
