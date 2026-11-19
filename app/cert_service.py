"""Privileged certificate file deployment. ACME runs in a separate Unix account."""
import contextlib
import fcntl
import grp
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

from certificates import LIMIT, SOCKET, STORE, covers, domain_name, inventory, pair, verify_pair

PRIVATE = Path("/var/lib/fc-ui-cert")
ENGINE = Path("/opt/fc-ui/acme")
REV = "5567d7fe7298fd37aca53194885ba444c6678669"
FILES = {"acme.sh": "35bf6b947478666be137f938f77c5089954f120798220e6fff390949c5ea5692",
         "dnsapi/dns_cf.sh": "a908b175d0347c2a5d76d631e509318cb73d1e552fdedb27fd5e83a4354b5dcc"}


def atomic(path, data, mode=0o600, gid=-1):
    with tempfile.NamedTemporaryFile(dir=str(path.parent), delete=False) as tmp:
        try:
            tmp.write(data)
            tmp.flush()
            os.fchown(tmp.fileno(), -1, gid)
            os.fchmod(tmp.fileno(), mode)
            os.fsync(tmp.fileno())
            os.replace(tmp.name, path)
        finally:
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)


def source_file(name):
    path = Path(name)
    if not path.is_absolute():
        raise ValueError("请输入 VPS 上的绝对路径")
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("请输入普通 PEM 文件路径")
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= LIMIT:
            raise ValueError("请输入普通 PEM 文件路径")
        data = f.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("PEM 文件过大")
    return data


def deploy(record, chain, key):
    # Never release extra bytes from a root-readable file alongside a PEM block.
    if not re.fullmatch(rb"(?:\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----)+\s*", chain):
        raise ValueError("证书路径必须指向 PEM 完整证书链")
    if not re.fullmatch(rb"\s*-----BEGIN ((?:RSA |EC )?PRIVATE KEY)-----[A-Za-z0-9+/=\r\n]+-----END \1-----\s*", key):
        raise ValueError("请提供未加密的 PEM 私钥")
    bucket = STORE / record["id"]
    gid = grp.getgrnam("fcxrayd").gr_gid
    bucket.mkdir(mode=0o750, exist_ok=True)
    os.chown(bucket, 0, gid)
    os.chmod(bucket, 0o750)
    stage = Path(tempfile.mkdtemp(dir=str(bucket)))
    try:
        certpath, keypath = stage / "fullchain.pem", stage / "privkey.pem"
        certpath.write_bytes(chain)
        keypath.write_bytes(key)
        facts = verify_pair(certpath, keypath, record["domain"])
        old_cert, old_key = pair(record["id"], STORE)
        if old_cert.exists():
            old = json.loads((old_cert.parent / "info.json").read_text())
            if any(n not in facts["names"] for n in old["names"]):
                raise ValueError("新证书缩小了域名覆盖范围，已保留原证书")
            if (old_cert.read_bytes() == chain and old_key.read_bytes() == key
                    and json.loads((old_cert.parent / "record.json").read_text()) == record):
                return old
        item = dict(id=record["id"], domain=record["domain"], source=record["source"], **facts)
        (stage / "info.json").write_text(json.dumps(item))
        for path in stage.iterdir():
            os.chown(path, 0, gid)
            path.chmod(0o640)
        # Commit renewal ownership with the pair in the same atomic switch.
        atomic(stage / "record.json", json.dumps(record).encode())
        os.chown(stage, 0, gid)
        stage.chmod(0o750)
        temp_link = bucket / ".next"
        if temp_link.is_symlink():
            temp_link.unlink()
        temp_link.symlink_to(stage.name)
        os.replace(temp_link, bucket / "current")
        for previous in bucket.iterdir():
            if previous.is_dir() and not previous.is_symlink() and previous != stage:
                shutil.rmtree(previous)
        return item
    finally:
        if (bucket / "current").resolve() != stage.resolve():
            shutil.rmtree(stage, ignore_errors=True)


def engine():
    for name, digest in FILES.items():
        target = ENGINE / name
        if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.parent.chmod(0o755)
        ENGINE.chmod(0o755)
        url = "https://raw.githubusercontent.com/acmesh-official/acme.sh/" + REV + "/" + name
        with urllib.request.urlopen(url, timeout=35) as response:
            content = response.read(1024 * 1024)
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("acme.sh 下载校验失败")
        atomic(target, content, 0o755)


def drop_privileges():
    user = pwd.getpwnam("fcui-acme")
    os.setgroups([])
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)


@contextlib.contextmanager
def challenge_server(webroot):
    # The child only serves challenge tokens and permanently drops root after bind.
    class Challenge(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            match = re.fullmatch(r"/\.well-known/acme-challenge/([a-zA-Z0-9_-]+)", self.path)
            if not match:
                return self.send_error(404)
            try:
                path = webroot / ".well-known/acme-challenge" / match[1]
                fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as stream:
                    body = stream.read(512) if stat.S_ISREG(os.fstat(fd).st_mode) else b""
                if not re.fullmatch(rb"[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", body):
                    return self.send_error(404)
            except OSError:
                return self.send_error(404)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    servers = []
    children = []
    class IPv6(ThreadingHTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()
    try:
        try:
            servers.append(ThreadingHTTPServer(("", 80), Challenge))
            if socket.has_ipv6 and Path("/proc/net/if_inet6").exists():
                servers.append(IPv6(("::", 80), Challenge))
        except OSError:
            raise ValueError("TCP 80 无法监听，请选择现有网站目录或 DNS 验证")
        for server in servers:
            pid = os.fork()
            if not pid:
                try:
                    drop_privileges()
                    server.serve_forever()
                finally:
                    os._exit(0)
            children.append(pid)
        yield
    finally:
        for pid in children:
            os.kill(pid, 15)
            os.waitpid(pid, 0)
        for server in servers:
            server.server_close()


def acme(record, credentials=None, renew=False):
    engine()
    name = record["domain"]
    account = pwd.getpwnam("fcui-acme")
    home = PRIVATE / "accounts" / record["id"]
    home.mkdir(mode=0o700, exist_ok=True)
    os.chown(home, account.pw_uid, account.pw_gid)
    mode = record["method"]
    args = ["/bin/sh", str(ENGINE / "acme.sh"), "--home", str(ENGINE),
            "--config-home", str(home), "--cert-home", str(home), "--server", "letsencrypt",
            "--renew" if renew else "--issue", "-d", record["identifier"]]
    if renew:
        args.append("--ecc")
    else:
        args += ["--keylength", "ec-256"]
        if record.get("email"):
            args += ["--accountemail", record["email"]]
    ctx = contextlib.nullcontext()
    env = dict(PATH="/usr/local/bin:/usr/bin:/bin", HOME=str(home), LC_ALL="C")
    if mode == "dns":
        if not renew:
            args += ["--dns", "dns_cf"]
            env.update(credentials)
    else:
        if mode == "http":
            webroot = PRIVATE / "challenges" / record["id"]
            webroot.mkdir(mode=0o700, exist_ok=True)
            os.chown(webroot, account.pw_uid, account.pw_gid)
            ctx = challenge_server(webroot)
        else:
            webroot = Path(record["webroot"])
        if not renew:
            args += ["--webroot", str(webroot)]
    if mode != "dns" and not renew:
        try:
            socket.getaddrinfo(name, 80, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError("域名尚未解析，请先设置公网 A/AAAA 记录") from exc
    with ctx:
        result = subprocess.run(args, env=env, cwd=str(home), preexec_fn=drop_privileges,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=540)
    if result.returncode not in (0, 2):
        # acme.sh output can contain secrets. Return only classified errors.
        log = result.stdout.lower()
        if b"rate limit" in log or b"ratelimited" in log:
            raise ValueError("CA 签发限流，请稍后重试")
        if mode == "dns":
            raise ValueError("DNS 验证失败，请检查 Token 的区域权限、Zone ID 和 TXT 传播")
        raise ValueError("HTTP 验证失败，请检查 A/AAAA、公网 TCP 80 和挑战目录的读写权限")
    folder = home / (record["identifier"] + "_ecc")
    def read_output(name):
        result = subprocess.run(["head", "-c", str(LIMIT + 1), str(folder / name)],
                                preexec_fn=drop_privileges, capture_output=True, timeout=10)
        if result.returncode or not 0 < len(result.stdout) <= LIMIT:
            raise ValueError("未找到有效的 ACME 签发产物")
        return result.stdout
    return read_output("fullchain.cer"), read_output(record["identifier"] + ".key")


def status(record, message):
    path = STORE / record["id"]
    if path.is_dir():
        atomic(path / "status", message.encode(), 0o640, grp.getgrnam("fcxrayd").gr_gid)


def candidates(data):
    domain = domain_name(data["domain"])
    found = []
    for root in (Path("/etc/letsencrypt/live"), Path("/root/cert")):
        for cert in root.glob("*/fullchain.pem"):
            key = cert.with_name("privkey.pem")
            try:
                facts = verify_pair(cert, key, domain)
            except (OSError, ValueError):
                continue
            found.append(dict(chainPath=str(cert), keyPath=str(key), expires=facts["expires"]))
    return found


def register(data):
    domain = domain_name(data["domain"])
    for existing in inventory(domain, STORE):
        if not existing["problem"]:
            return existing
    source = data["source"]
    if source not in ("path", "pem", "acme"):
        raise ValueError("未知证书来源")
    # Each source remains the owner of its renewals; retries reuse ACME state.
    identifier = domain_name(data.get("identifier") or domain, wildcard=True)
    if not covers(identifier, domain):
        raise ValueError("签发域名未覆盖节点 SNI")
    cert_id = hashlib.sha256((source + ":" + identifier).encode()).hexdigest()[:32]
    record = dict(id=cert_id, domain=domain, source=source, identifier=identifier)
    if source == "path":
        record.update(chainPath=data["chainPath"], keyPath=data["keyPath"])
        chain, key = source_file(record["chainPath"]), source_file(record["keyPath"])
    elif source == "pem":
        chain, key = data["certificate"].encode(), data["key"].encode()
    else:
        method = data.get("method")
        if method not in ("dns", "http", "webroot") or (identifier.startswith("*.") and method != "dns"):
            raise ValueError("请选择有效的验证方式，通配符需要 DNS-01")
        email = data.get("email", "")
        if email and not re.fullmatch(r"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+", email):
            raise ValueError("ACME 联系邮箱格式无效")
        record.update(method=method, email=email)
        credentials = {}
        if method == "webroot":
            path = data.get("webroot", "")
            if not re.fullmatch(r"/[A-Za-z0-9/._-]+", path) or not Path(path).is_dir():
                raise ValueError("请输入 VPS 上现有网站的绝对目录")
            record["webroot"] = path
        elif method == "dns":
            token = data.get("token", "")
            if data.get("provider") != "cloudflare" or not re.fullmatch(r"[A-Za-z0-9_-]{10,256}", token):
                raise ValueError("请选择 Cloudflare 并填写有效的 DNS API Token")
            credentials["CF_Token"] = token
            for field, variable in (("zone", "CF_Zone_ID"), ("account", "CF_Account_ID")):
                if data.get(field):
                    if not re.fullmatch("[a-fA-F0-9]{32}", data[field]):
                        raise ValueError("Cloudflare 的 Zone ID 或 Account ID 应为 32 位十六进制")
                    credentials[variable] = data[field]
        chain, key = acme(record, credentials)
    result = deploy(record, chain, key)
    status(record, "证书已部署")
    return result


def replace_pem(data):
    cert, _ = pair(data.get("id"), STORE)
    record = json.loads((cert.parent / "record.json").read_text())
    if record["source"] != "pem":
        raise ValueError("托管证书请通过原签发来源更新")
    item = deploy(record, data["certificate"].encode(), data["key"].encode())
    status(record, "已手动更新")
    return item


def maintain():
    for file in STORE.glob("*/current/record.json"):
        record = json.loads(file.read_text())
        try:
            with locked():
                if record["source"] == "pem":
                    continue
                if record["source"] == "acme":
                    cert, _ = pair(record["id"], STORE)
                    expiry = ssl.cert_time_to_seconds(ssl._ssl._test_decode_cert(str(cert))["notAfter"])
                    if expiry - time.time() > 30 * 86400:
                        continue
                    chain, key = acme(record, renew=True)
                else:
                    chain, key = source_file(record["chainPath"]), source_file(record["keyPath"])
                deploy(record, chain, key)
                status(record, "已检查更新 " + time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            status(record, "更新待重试：" + (str(exc) if isinstance(exc, ValueError) else type(exc).__name__))


@contextlib.contextmanager
def locked():
    with (PRIVATE / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def run():
    os.umask(0o077)
    gid = grp.getgrnam("fcxrayd").gr_gid
    for folder, mode in [(PRIVATE, 0o711), (PRIVATE / "accounts", 0o711),
                         (PRIVATE / "challenges", 0o711), (STORE, 0o750),
                         (Path(SOCKET).parent, 0o750)]:
        folder.mkdir(exist_ok=True)
        if folder in (STORE, Path(SOCKET).parent):
            os.chown(folder, 0, gid)
        folder.chmod(mode)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(12)
            try:
                raw = self.rfile.readline(LIMIT + 1)
                if len(raw) > LIMIT:
                    raise ValueError("请求过大")
                req = json.loads(raw)
                if req["op"] == "certCandidates":
                    result = candidates(req["data"])
                elif req["op"] in ("certRegister", "certReplace"):
                    with locked():
                        result = (register if req["op"] == "certRegister" else replace_pem)(req["data"])
                else:
                    raise ValueError("未知证书操作")
                reply = {"result": result}
            except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError) as exc:
                if isinstance(exc, FileNotFoundError):
                    reason = "找不到证书、私钥或所需程序，请核对 VPS 路径"
                elif isinstance(exc, PermissionError):
                    reason = "证书文件或挑战目录访问被拒绝，请核对权限"
                elif isinstance(exc, subprocess.TimeoutExpired):
                    reason = "证书操作超时，请检查 CA 网络或 DNS 记录传播后重试"
                else:
                    reason = str(exc) if isinstance(exc, ValueError) else "证书操作失败：" + type(exc).__name__
                reply = {"error": reason}
            self.wfile.write(json.dumps(reply).encode() + b"\n")

    class Server(socketserver.ForkingMixIn, socketserver.UnixStreamServer):
        max_children = 8
    instance = (PRIVATE / "service.lock").open("a")
    fcntl.flock(instance, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with contextlib.suppress(FileNotFoundError):
        Path(SOCKET).unlink()
    with Server(SOCKET, Handler) as server:
        os.chown(SOCKET, 0, gid)
        os.chmod(SOCKET, 0o660)
        server.timeout = 1
        next_check = 0
        child = None
        while True:
            if child and child.poll() is not None:
                child = None
            if not child and time.monotonic() >= next_check:
                child = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), "maintain"])
                next_check = time.monotonic() + 3600
            server.handle_request()
            server.collect_children()


if __name__ == "__main__":
    if sys.argv[1:] == ["maintain"]:
        maintain()
    else:
        run()
