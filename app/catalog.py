"""Supported combinations for the pinned Xray release. IDs persist in nodes.json."""

from dataclasses import asdict, dataclass, replace


@dataclass(frozen=True)
class Template:
    name: str
    port: int
    protocol: str
    network: str = "tcp"
    security: str = "none"
    vision: bool = False
    cipher: str = ""
    key_bytes: int = 0
    h3: bool = False
    encrypt: bool = False
    private_only: bool = False

    @property
    def needs_cert(self):
        return self.security == "tls" and self.network != "xdrive"

    @property
    def ports(self):
        if self.protocol == "shadowsocks":
            return ["tcp", "udp"]
        if self.network == "xdrive":
            return []  # storage transport; Xray still requires a logical port
        return ["udp" if self.h3 or self.network in ("kcp", "hysteria") else "tcp"]

    @property
    def needs_encryption(self):
        return (
            self.protocol == "vless"
            and not self.private_only
            and (
                self.encrypt
                or self.security == "none"
                or self.network == "xdrive"
                or (self.vision and self.network != "tcp")
            )
        )

    def form(self):
        return dict(
            asdict(self),
            needsCert=self.needs_cert,
            ports=self.ports,
            needsEncryption=self.needs_encryption,
        )


# Keep the first four options and the IDs written by the original installer.
TEMPLATES = {
    "reality": Template(
        "VLESS · TCP · REALITY · Vision", 8443, "vless", "tcp", "reality", True
    ),
    "ss2022": Template(
        "SS2022 · AES-128-GCM",
        8388,
        "shadowsocks",
        cipher="2022-blake3-aes-128-gcm",
        key_bytes=16,
    ),
    "ss": Template(
        "SS · ChaCha20-Poly1305", 8389, "shadowsocks", cipher="chacha20-ietf-poly1305"
    ),
    "vision": Template("VLESS · TCP · TLS · Vision", 8444, "vless", "tcp", "tls", True),
    "trojan-tls": Template("Trojan · TCP · TLS", 8445, "trojan", "tcp", "tls"),
}
for cipher, length in [
    ("aes-128-gcm", 0),
    ("aes-256-gcm", 0),
    ("xchacha20-ietf-poly1305", 0),
    ("2022-blake3-aes-256-gcm", 32),
    ("2022-blake3-chacha20-poly1305", 32),
]:
    TEMPLATES["ss-" + cipher] = Template(
        "SS · " + cipher,
        8390 + len(TEMPLATES) - 5,
        "shadowsocks",
        cipher=cipher,
        key_bytes=length,
    )

SECURITY = {
    "tcp": ("none", "tls", "reality"),
    "ws": ("none", "tls"),
    "grpc": ("none", "tls", "reality"),
    "xhttp": ("none", "tls", "reality"),
    "httpupgrade": ("none", "tls"),
    "kcp": ("none", "tls"),
    "hysteria": ("tls",),
    "xdrive": ("none", "tls"),
}
for network, securities in SECURITY.items():
    for security in securities:
        for vision in [False] if network == "xdrive" else [False, True]:
            if vision and network == "tcp" and security != "none":
                continue  # already represented by 'vision' and 'reality'
            for h3 in (
                [False, True]
                if network in ("xhttp", "xdrive") and security == "tls"
                else [False]
            ):
                transport = network.upper() + (" H3" if h3 else "")
                name = "VLESS · %s · %s%s" % (
                    transport,
                    security.upper(),
                    " · Vision" if vision else "",
                )
                key = (
                    "vless-"
                    + network
                    + "-"
                    + security
                    + ("-h3" if h3 else "")
                    + ("-vision" if vision else "")
                )
                TEMPLATES[key] = Template(
                    name,
                    8500 + len(TEMPLATES),
                    "vless",
                    network,
                    security,
                    vision,
                    h3=h3,
                )

# Include explicit encryption choices in the numeric menu, so selecting a
# conventional template never introduces another interactive question.
for key, entry in list(TEMPLATES.items()):
    if entry.protocol != "vless":
        continue
    if entry.needs_encryption:
        TEMPLATES[key] = replace(entry, name=entry.name + " · Encryption")
    else:
        TEMPLATES[key + "-enc"] = replace(
            entry,
            encrypt=True,
            name=entry.name + " · Encryption",
            port=8500 + len(TEMPLATES),
        )
    if entry.security == "none" and not entry.vision and entry.network != "xdrive":
        TEMPLATES[key + "-private"] = replace(
            entry,
            private_only=True,
            name=entry.name + " · 内网明文",
            port=8500 + len(TEMPLATES),
        )
