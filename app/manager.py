"""Unprivileged supervisor. Access is via a mode-0600 Unix socket."""
import contextlib
import errno
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

from profiles import build
from catalog import TEMPLATES

STATE = Path("/var/lib/fc-ui")
XRAY = Path("/opt/fc-ui/xray")
LIMIT = 128 * 1024


def atomic(path, data):
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf8") as f:
            json.dump(data, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


class Manager:
    def __init__(self, state=STATE, xray=XRAY):
        self.state, self.xray = state, xray
        self.db = state / "nodes.json"
        self.nodes = json.loads(self.db.read_text()) if self.db.exists() else {}
        self.children, self.retry = {}, {}
        self.lock = threading.RLock()
        self.panel = None
        self.token = state / "panel-token"
        if not self.token.exists():
            atomic(self.token, secrets.token_urlsafe(32))

    def launch(self, node_id):
        config = self.state / (node_id + ".json")
        cmd = [str(self.xray), "run", "-c", str(config)]
        check = subprocess.run(cmd + ["-test"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if check.returncode:
            raise ValueError("Xray 配置校验失败，请检查协议参数和证书")
        node = self.nodes[node_id]
        family = socket.AF_INET6 if ":" in node["host"] else socket.AF_INET
        bind_ip = "::" if family == socket.AF_INET6 else "0.0.0.0"
        template = TEMPLATES[node["template"]]
        ports = template.ports
        protocols = [socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM for proto in ports]
        target = "::1" if family == socket.AF_INET6 else "127.0.0.1"
        if template.private_only:
            bind_ip = target = node["host"]
        if "tcp" in ports:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.settimeout(.3)
                if probe.connect_ex((target, node["port"])) == 0:
                    raise ValueError("代理 TCP 端口已被占用")
        for protocol in protocols:
            with socket.socket(family, protocol) as probe:
                if protocol == socket.SOCK_STREAM:
                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    probe.bind((bind_ip, node["port"]))
                except OSError as exc:
                    raise ValueError("代理端口已被占用或地址族不可用") from exc
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children[node_id] = p
        try:
            for attempt in range(60):
                time.sleep(.05)
                if p.poll() is not None:
                    break
                if "udp" in ports:
                    with socket.socket(family, socket.SOCK_DGRAM) as probe:
                        try:
                            probe.bind((bind_ip, node["port"]))
                        except OSError as exc:
                            if exc.errno != errno.EADDRINUSE:
                                raise
                        else:
                            continue
                if "tcp" in ports:
                    try:
                        with socket.create_connection((target, node["port"]), timeout=.15):
                            pass
                    except OSError:
                        continue
                if not ports and attempt < 9:
                    continue  # xdrive polls storage, it has no public listening socket.
                if p.poll() is None:
                    return
            raise ValueError("代理未能监听端口，请检查端口占用及系统 IPv6 支持")
        except BaseException:
            self.stop(node_id)
            raise

    def stop(self, node_id):
        child = self.children.pop(node_id, None)
        if child and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=4)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()

    def enable_panel(self, port):
        from panel import start_panel
        if self.panel:
            if port != self.panel.server_port:
                raise ValueError("面板已运行在端口 %s" % self.panel.server_port)
            return
        if not 1024 <= port <= 65535 or any(n["port"] == port for n in self.nodes.values()):
            raise ValueError("面板端口无效或已分配给代理")
        self.panel = start_panel(self, port)
        try:
            atomic(self.state / "panel.json", {"port": port})
        except BaseException:
            self.panel.shutdown()
            self.panel.server_close()
            self.panel = None
            raise

    def call(self, op, data, local=False):
        with self.lock:
            if op == "list":
                return [dict(n, id=i, running=i in self.children and self.children[i].poll() is None) for i,n in self.nodes.items()]
            if op == "panel" and local:
                self.enable_panel(int(data.get("port") or 8787))
                return {"port": self.panel.server_port, "token": json.loads(self.token.read_text())}
            if op == "create":
                cfg, node = build(data, self.xray, self.state)
                if any(n["port"] == node["port"] for n in self.nodes.values()) or (self.panel and self.panel.server_port == node["port"]):
                    raise ValueError("该端口已分配，请选择其他端口")
                node_id = secrets.token_hex(8)
                path = self.state / (node_id + ".json")
                atomic(path, cfg)
                self.nodes[node_id] = dict(node, enabled=True)
                try:
                    self.launch(node_id)
                    atomic(self.db, self.nodes)
                except BaseException:
                    self.stop(node_id)
                    del self.nodes[node_id]
                    path.unlink()
                    raise
                return dict(node, id=node_id)
            node_id = data.get("id")
            if op not in ("start", "stop") or node_id not in self.nodes:
                raise ValueError("未知操作或节点")
            n = self.nodes[node_id]
            previous = n["enabled"]
            if op == "start" and not (node_id in self.children and self.children[node_id].poll() is None):
                self.launch(node_id)
            n["enabled"] = op == "start"
            try:
                atomic(self.db, self.nodes)
            except BaseException:
                n["enabled"] = previous
                if not previous:
                    self.stop(node_id)
                raise
            if op == "stop":
                self.stop(node_id)
            return {"id": node_id}

    def reconcile(self):
        with self.lock:
            for i,n in self.nodes.items():
                if not n["enabled"] or (i in self.children and self.children[i].poll() is None):
                    continue
                if time.monotonic() < self.retry.get(i, 0):
                    continue
                try:
                    self.launch(i)
                except Exception as exc:
                    self.retry[i] = time.monotonic() + 30
                    print("节点 %s 启动失败：%s" % (i, type(exc).__name__), flush=True)


def daemon():
    os.umask(0o077)
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(8)
            try:
                raw = self.rfile.readline(LIMIT+1)
                if len(raw)>LIMIT: raise ValueError("请求过大")
                req = json.loads(raw)
                response = {"result": manager.call(req["op"], req.get("data", {}), local=True)}
            except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
                response = {"error": str(exc)}
            self.wfile.write(json.dumps(response).encode() + b"\n")

    # A second manual launch must not unlink the active manager's control socket.
    import fcntl
    lock = (STATE / "manager.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    manager = Manager()
    path = STATE / "control.sock"
    with contextlib.suppress(FileNotFoundError): path.unlink()
    with socketserver.UnixStreamServer(str(path), Handler) as srv:
        srv.timeout = .5
        done = threading.Event()
        for sig in (signal.SIGINT,signal.SIGTERM):
            signal.signal(sig, lambda *_: done.set())
        try:
            panel_file = STATE / "panel.json"
            if panel_file.exists():
                try: manager.enable_panel(json.loads(panel_file.read_text())["port"])
                except OSError as exc: print("面板未启动：%s" % exc, flush=True)
            while not done.is_set():
                manager.reconcile()
                srv.handle_request()
        finally:
            if manager.panel:
                manager.panel.shutdown()
                manager.panel.server_close()
            with manager.lock:
                for i in list(manager.children): manager.stop(i)
            path.unlink()
