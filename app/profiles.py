"""Build paired Xray inbound configurations and fcxray-compatible sharing URIs."""

import base64
import ipaddress
import json
from pathlib import Path
import re
import secrets
import subprocess
import uuid
from urllib.parse import quote, urlencode

from catalog import TEMPLATES


def hostname(value, allow_loopback=False):
    value = str(value).strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        ip = ipaddress.ip_address(value)
        if (
            ip.is_unspecified
            or (ip.is_loopback and not allow_loopback)
            or ip.is_multicast
            or "%" in value
        ):
            raise ValueError("请填写客户端可达的 VPS 地址")
        return str(ip)
    except ValueError:
        if (
            not re.fullmatch(
                r"(?=.{1,253}$)(?![0-9.]+$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?",
                value,
            )
            or value.lower() == "localhost"
        ):
            raise ValueError("域名或 IP 地址无效")
        return value.lower()


def reality(options, xray, stream, query, sni):
    keys = subprocess.check_output([str(xray), "x25519"], timeout=10, text=True)
    private = re.search(r"^PrivateKey:\s*([\w-]{43})$", keys, re.M)
    public = re.search(r"^Password \(PublicKey\):\s*([\w-]{43})$", keys, re.M)
    if not private or not public:
        raise ValueError("Xray 未返回可用的 X25519 密钥")
    sid = options.get("shortId") or secrets.token_hex(8)
    if not re.fullmatch(r"(?:[a-fA-F0-9]{2}){1,8}", sid):
        raise ValueError("shortId 须为 2–16 位偶数长度十六进制")
    target = "[%s]" % sni if ":" in sni else sni
    stream["realitySettings"] = {
        "target": target + ":443",
        "serverNames": [sni],
        "privateKey": private.group(1),
        "shortIds": [sid],
    }
    query.update(pbk=public.group(1), sid=sid)


def vless_keys(xray):
    output = subprocess.check_output([str(xray), "vlessenc"], timeout=15, text=True)
    pair = re.search(r'"decryption":\s*"([^"]+)"\s*"encryption":\s*"([^"]+)"', output)
    if not pair:
        raise ValueError("Xray 未返回配对的 VLESS Encryption 参数")
    return pair.groups()


def transport(t, options, stream, query, state):
    network = t.network
    if network in ("ws", "xhttp", "httpupgrade"):
        path = options.get("path") or "/fc-ui"
        if not path.startswith("/") or not path.isprintable():
            raise ValueError("请求路径须以 / 开头")
        settings = {"path": path}
        query["path"] = path
        if network == "xhttp":
            mode = options.get("mode") or "auto"
            if mode not in ("auto", "stream-up", "stream-one", "packet-up"):
                raise ValueError("未知 XHTTP 模式")
            settings["mode"] = query["mode"] = mode
        stream[network + "Settings"] = settings
    elif network == "grpc":
        service = options.get("serviceName") or "fcui"
        stream["grpcSettings"] = {"serviceName": service}
        query["serviceName"] = service
    elif network == "hysteria":
        settings = {
            "version": 2,
            "auth": options.get("password") or secrets.token_urlsafe(24),
        }
        stream["hysteriaSettings"] = settings
        query["hysteriaSettings"] = json.dumps(settings, separators=(",", ":"))
    elif network == "xdrive":
        drive = options.get("xdrive")
        if isinstance(drive, str):
            drive = json.loads(drive)
        if (
            not isinstance(drive, dict)
            or drive.get("service") not in ("local", "google-drive", "s3", "template")
            or not drive.get("remoteFolder")
        ):
            raise ValueError(
                "请填写 xdrive 存储配置 JSON，包含 service 和 remoteFolder"
            )
        drive = dict(drive)
        if drive["service"] == "local":
            folder = drive["remoteFolder"]
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", folder):
                raise ValueError("local 目录仅接受字母、数字、下划线或连字符")
            drive["remoteFolder"] = str(state / "xdrive" / folder)
        stream["xdriveSettings"] = drive
        query["xdriveSettings"] = json.dumps(drive, separators=(",", ":"))


def build(options, xray, state=Path("/var/lib/fc-ui")):
    t = TEMPLATES.get(options.get("template"))
    if not t:
        raise ValueError("未知模板")
    host = hostname(options.get("host", ""), allow_loopback=t.private_only)
    if t.private_only:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        ranges = (
            "127.0.0.0/8",
            "::1/128",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fc00::/7",
        )
        if address is None or not any(
            address in ipaddress.ip_network(n) for n in ranges
        ):
            raise ValueError(
                "内网明文模板需要 RFC1918 或 ULA 地址；公网请选择带 Encryption、TLS 或 REALITY 的模板"
            )
    port = int(options.get("port") or t.port)
    if not 1024 <= port <= 65535:
        raise ValueError("代理端口须为 1024–65535")
    name = str(options.get("name") or t.name).strip()
    if not name or len(name) > 100 or not name.isprintable():
        raise ValueError("节点名称无效")
    authority = ("%s:%s" if ":" not in host else "[%s]:%s") % (host, port)
    inbound = {
        "listen": "::" if ":" in host else "0.0.0.0",
        "port": port,
        "protocol": t.protocol,
    }
    if t.private_only:
        inbound["listen"] = host
    if t.protocol == "shadowsocks":
        password = options.get("password") or (
            base64.b64encode(secrets.token_bytes(t.key_bytes)).decode()
            if t.key_bytes
            else secrets.token_urlsafe(24)
        )
        if (
            t.key_bytes
            and len(base64.b64decode(password, validate=True)) != t.key_bytes
        ):
            raise ValueError("该方法需要 %d 字节的 Base64 密钥" % t.key_bytes)
        inbound["settings"] = {
            "method": t.cipher,
            "password": password,
            "network": "tcp,udp",
        }
        auth = (
            base64.urlsafe_b64encode((t.cipher + ":" + password).encode())
            .decode()
            .rstrip("=")
        )
        uri = "ss://%s@%s" % (auth, authority)
    else:
        stream = {"network": t.network, "security": t.security}
        query = {"type": t.network, "security": t.security}
        if t.protocol == "vless":
            user = (
                str(uuid.UUID(options["uuid"]))
                if options.get("uuid")
                else str(uuid.uuid4())
            )
            account = {"id": user}
            if t.vision:
                account["flow"] = query["flow"] = "xtls-rprx-vision"
            decrypt, encrypt = ("none", "none")
            if t.needs_encryption:
                decrypt, encrypt = vless_keys(xray)
            inbound["settings"] = {"clients": [account], "decryption": decrypt}
            query["encryption"] = encrypt
        else:
            user = options.get("password") or secrets.token_urlsafe(24)
            inbound["settings"] = {"clients": [{"password": user}]}
        if t.security != "none":
            sni = hostname(
                options.get("sni")
                or ("www.cloudflare.com" if t.security == "reality" else host)
            )
            if t.network != "xdrive":
                query.update(sni=sni, fp="chrome")
            if t.security == "reality":
                reality(options, xray, stream, query, sni)
            elif t.needs_cert:
                cert, key = options.get("certificate", ""), options.get("key", "")
                if (
                    "-----BEGIN CERTIFICATE-----" not in cert
                    or "PRIVATE KEY-----" not in key
                ):
                    raise ValueError("请提供与 SNI 匹配的完整 PEM 证书链和私钥")
                stream["tlsSettings"] = {
                    "certificates": [
                        {
                            "certificate": cert.strip().splitlines(),
                            "key": key.strip().splitlines(),
                        }
                    ]
                }
            if t.h3 or t.network in ("hysteria", "grpc") and t.security == "tls":
                alpn = "h2" if t.network == "grpc" else "h3"
                stream.setdefault("tlsSettings", {})["alpn"] = [alpn]
                query["alpn"] = alpn
        transport(t, options, stream, query, state)
        inbound["streamSettings"] = stream
        uri = "%s://%s@%s?%s" % (
            t.protocol,
            quote(user, safe=""),
            authority,
            urlencode(query),
        )
    cfg = {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [inbound],
        "outbounds": [{"protocol": "freedom"}],
    }
    return cfg, {
        "name": name,
        "host": host,
        "port": port,
        "template": options["template"],
        "link": uri + "#" + quote(name, safe=""),
    }
