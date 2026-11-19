"""Install a pinned, digest-verified Linux release executable atomically."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile


def fetch(destination):
    metadata = json.loads(Path(__file__).with_name("core.json").read_text())
    arch = platform.machine().lower()
    arch = {"amd64":"x86_64", "arm64":"aarch64", "i386":"i686", "armv7":"armv7l"}.get(arch,arch)
    if arch not in metadata["assets"]:
        sys.exit("不支持的 CPU 架构：" + arch)
    asset = metadata["assets"][arch]
    exe = destination / "xray"
    marker = destination / "release.sha256"
    if marker.exists() and exe.is_file() and marker.read_text().strip() == asset["sha256"]:
        subprocess.run([str(exe), "version"], check=True, stdout=subprocess.DEVNULL)
        return
    url = "https://github.com/XTLS/Xray-core/releases/download/%s/%s" % (metadata["tag"],asset["name"])
    print("下载 Xray-core %s (%s)" % (metadata["tag"],arch), flush=True)
    with tempfile.TemporaryDirectory(dir=str(destination)) as tmp:
        archive = Path(tmp)/"core.zip"
        with urllib.request.urlopen(url,timeout=45) as response, archive.open("wb") as f:
            digest = hashlib.sha256()
            while True:
                chunk = response.read(1024*1024)
                if not chunk: break
                digest.update(chunk)
                f.write(chunk)
        if digest.hexdigest() != asset["sha256"]:
            sys.exit("Xray-core SHA-256 校验失败")
        new = Path(tmp)/"xray"
        with zipfile.ZipFile(archive) as z, z.open("xray") as src, new.open("wb") as out:
            shutil.copyfileobj(src,out)
        new.chmod(0o755)
        subprocess.run([str(new),"version"],check=True)
        os.replace(new,exe)
        marker.write_text(asset["sha256"]+"\n")


if __name__=="__main__":
    fetch(Path(sys.argv[1]))
