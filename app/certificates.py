"""Shared certificate inventory and the client's narrow certificate-service API."""
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time

from profiles import hostname

STORE = Path("/etc/fc-ui/certs")
SOCKET = "/run/fc-ui-cert/control.sock"
LIMIT = 128 * 1024


def domain_name(value, wildcard=False):
    value = str(value or "").lower().rstrip(".")
    prefix = "*." if wildcard and value.startswith("*.") else ""
    name = hostname(value[len(prefix):])
    if "." not in name or ":" in name or re.fullmatch(r"[0-9.]+", name):
        raise ValueError("请输入证书对应的 DNS 域名，例如 vpn.example.com")
    return prefix + name


def covers(pattern, name):
    pattern = pattern.lower()
    return pattern == name or (pattern.startswith("*.") and "." in name
                               and pattern[2:] == name.split(".", 1)[1])


def verify_pair(cert, key, domain):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(str(cert), str(key), password=lambda: "")
        info = ssl._ssl._test_decode_cert(str(cert))
    except (OSError, ValueError) as exc:
        raise ValueError("证书链或私钥无法读取、已加密或不配对") from exc
    names = [v.lower() for k, v in info.get("subjectAltName", []) if k == "DNS"]
    if not any(covers(n, domain) for n in names):
        raise ValueError("证书 SAN 未覆盖 " + domain)
    if not ssl.cert_time_to_seconds(info["notBefore"]) <= time.time() < ssl.cert_time_to_seconds(info["notAfter"]):
        raise ValueError("证书未生效或已过期")
    result = subprocess.run(["openssl", "verify", "-purpose", "sslserver", "-untrusted",
                             str(cert), str(cert)], capture_output=True, timeout=10)
    if result.returncode:
        raise ValueError("证书链不完整或不受系统信任")
    return {"names": names, "expires": info["notAfter"]}


def pair(cert_id, root=STORE):
    if not isinstance(cert_id, str) or not re.fullmatch("[a-f0-9]{32}", cert_id):
        raise ValueError("证书 ID 无效")
    current = root / cert_id / "current"
    return current / "fullchain.pem", current / "privkey.pem"


def inventory(domain="", root=STORE):
    if domain:
        domain = domain_name(domain)
    entries = []
    for meta in sorted(root.glob("*/current/info.json")):
        item = json.loads(meta.read_text())
        if domain and not any(covers(n, domain) for n in item["names"]):
            continue
        cert, key = pair(item["id"], root)
        try:
            verify_pair(cert, key, domain or item["domain"])
            item["problem"] = ""
        except (OSError, ValueError) as exc:
            item["problem"] = str(exc)
        status = root / item["id"] / "status"
        item["renewalStatus"] = status.read_text() if status.exists() else ""
        entries.append(item)
    return sorted(entries, key=lambda e: (bool(e["problem"]), domain not in e["names"], -ssl.cert_time_to_seconds(e["expires"])))


def service(op, data):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(650)
        sock.connect(SOCKET)
        sock.sendall(json.dumps({"op": op, "data": data}).encode() + b"\n")
        reply = json.load(sock.makefile("r"))
    if "error" in reply:
        raise ValueError(reply["error"])
    return reply["result"]
