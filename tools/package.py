"""Make the self-contained installer reproducibly with the Python standard library."""
import base64
import gzip
import io
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = """#!/bin/sh
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM
awk 'payload {print} /^__FCXRAY_ARCHIVE__$/ {payload=1}' "$0" | base64 -d > "$work/source.tgz"
tar -xzf "$work/source.tgz" -C "$work"
sh "$work/install.sh" "$@"
exit $?
__FCXRAY_ARCHIVE__
"""


def package():
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in ["install.sh", "LICENSE", "app/cli.py", "app/manager.py", "app/panel.py",
                     "app/profiles.py", "app/catalog.py", "app/fetch_core.py", "app/core.json",
                     "app/index.html", "app/app.js", "app/style.css"]:
            content = (ROOT/name).read_bytes()
            info = tarfile.TarInfo(name)
            info.mode = 0o755 if name == "install.sh" else 0o644
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    output = ROOT / "fcui.run"
    output.write_bytes(HEADER.encode() + base64.encodebytes(gzip.compress(data.getvalue(), mtime=0)))
    output.chmod(0o755)


if __name__ == "__main__":
    package()
