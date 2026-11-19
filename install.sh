#!/bin/sh
set -eu
src=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
[ "$(uname -s)" = Linux ] || { echo "请在 Linux VPS 上运行。" >&2; exit 1; }
[ -r /etc/os-release ] || { echo "缺少 /etc/os-release"; exit 1; }
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*) family=apt ;;
  *" rhel "*|*" fedora "*|*" centos "*) family=rpm ;;
  *" alpine "*) family=apk ;;
  *" arch "*) family=pacman ;;
  *" suse "*|*" opensuse "*) family=zypper ;;
  *) echo "暂不支持 ${PRETTY_NAME:-未知发行版}"; exit 1 ;;
esac
case "$(uname -m)" in x86_64|amd64|aarch64|arm64|armv7l|armv7|i686|i386) ;; *) echo "不支持的架构：$(uname -m)"; exit 1;; esac
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then
    init=systemd
elif command -v rc-service >/dev/null && command -v rc-update >/dev/null && command -v supervise-daemon >/dev/null; then
    init=openrc
else
    echo "需要正在运行的 systemd 或 OpenRC；普通应用容器不提供完整 init。"; exit 1
fi
printf '检测到 %s / %s / %s\n' "${PRETTY_NAME:-$ID}" "$(uname -m)" "$init"
if [ "$(id -u)" != 0 ]; then
    command -v sudo >/dev/null || { echo "请以 root 运行"; exit 1; }
    exec sudo env SSH_CONNECTION="${SSH_CONNECTION:-}" sh "$src/install.sh" "$@"
fi
mode=${1:-}
if [ -z "$mode" ]; then
    printf '1) 安装本地 Web 面板（SSH 隧道访问）\n2) 直接创建 Xray 代理\n选择 [1/2]：'
    read -r mode
fi
case "$mode" in 1|panel) mode=panel;; 2|node) mode=node;; *) echo "请选择 1 或 2"; exit 1;; esac

case "$family" in
    apt) apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y python3 openssl curl ca-certificates passwd ;;
    rpm) pm=$(command -v dnf || command -v yum); "$pm" install -y python3 openssl curl ca-certificates shadow-utils
         if ! python3 -c 'import sys;sys.exit(sys.version_info < (3,8))'; then "$pm" install -y python39; fi ;;
    apk) apk add --no-cache python3 openssl curl ca-certificates coreutils ;;
    pacman) pacman -S --needed --noconfirm python openssl curl ca-certificates shadow ;;
    zypper) zypper --non-interactive install python3 openssl curl ca-certificates shadow
            if ! python3 -c 'import sys;sys.exit(sys.version_info < (3,8))'; then zypper --non-interactive install python311; fi ;;
esac
python=
for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9; do
    if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys;sys.exit(sys.version_info < (3,8))'; then python=$(command -v "$candidate"); break; fi
done
[ -n "$python" ] || { echo "需要 Python 3.8 或更高版本"; exit 1; }
app=/opt/fc-ui
state=/var/lib/fc-ui
account=fcxrayd
for service_user in "$account" fcui-acme; do
    if ! id "$service_user" >/dev/null 2>&1; then
        if [ "$family" = apk ]; then
            addgroup -S "$service_user"
            adduser -S -D -H -h /nonexistent -G "$service_user" -s /sbin/nologin "$service_user"
        else
            useradd --system --user-group --home-dir /nonexistent --no-create-home --shell "$(command -v nologin || echo /sbin/nologin)" "$service_user"
        fi
    fi
done
install -d -m 0755 "$app" /etc/fc-ui /usr/local/bin
# Existing installations keep their original data (including node IDs and keys).
legacy=/var/lib/fcxray-deploy
if [ -d "$legacy" ]; then
    if [ ! -e "$state" ]; then
        ln -s "$legacy" "$state"
    elif [ ! "$state" -ef "$legacy" ]; then
        echo "新旧状态目录同时存在且数据独立。请先备份并选择要沿用的数据目录，再重试。"
        exit 1
    fi
fi
if [ -f /etc/fcxray-deploy/public-host ] && [ ! -e /etc/fc-ui/public-host ]; then
    install -m 0644 /etc/fcxray-deploy/public-host /etc/fc-ui/public-host
fi
install -d -m 0700 -o "$account" -g "$account" "$state"
"$python" "$src/app/fetch_core.py" "$app"
for name in cli.py manager.py catalog.py profiles.py panel.py certificates.py cert_service.py index.html app.js style.css; do install -m 0644 "$src/app/$name" "$app/$name"; done
install -m 0644 "$src/LICENSE" "$app/LICENSE"
cat > /usr/local/bin/fc-ui <<EOF
#!/bin/sh
exec "$python" -B "$app/cli.py" "\$@"
EOF
chmod 0755 /usr/local/bin/fc-ui
if [ "$init" = systemd ]; then
    cat >/etc/systemd/system/fc-ui-cert.service <<EOF
[Unit]
Description=fc-ui certificate deployment and renewal
After=network-online.target
[Service]
ExecStart=$python -B $app/cert_service.py
Restart=on-failure
UMask=0077
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
    cat >/etc/systemd/system/fc-ui.service <<EOF
[Unit]
Description=fc-ui node manager
Wants=fc-ui-cert.service
After=network-online.target fc-ui-cert.service
Wants=network-online.target
[Service]
ExecStart=$python -B $app/cli.py daemon
User=$account
Group=$account
UMask=0077
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$state
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    if systemctl is-active --quiet fcxray-deploy || systemctl is-enabled --quiet fcxray-deploy 2>/dev/null; then
        systemctl disable --now fcxray-deploy
    fi
    systemctl enable fc-ui-cert fc-ui
    systemctl restart fc-ui-cert
    systemctl restart fc-ui
else
    cat >/etc/init.d/fc-ui-cert <<EOF
#!/sbin/openrc-run
description="fc-ui certificate deployment and renewal"
supervisor="supervise-daemon"
command="$python"
command_args="-B $app/cert_service.py"
respawn_delay=3
depend() { need net; }
EOF
    chmod 0755 /etc/init.d/fc-ui-cert
    rc-update add fc-ui-cert default
    if rc-service fc-ui-cert status >/dev/null 2>&1; then rc-service fc-ui-cert stop; fi
    rc-service fc-ui-cert start
    cat >/etc/init.d/fc-ui <<EOF
#!/sbin/openrc-run
description="fc-ui node manager"
supervisor="supervise-daemon"
command="$python"
command_args="-B $app/cli.py daemon"
command_user="$account:$account"
respawn_delay=3
depend() { need net; }
EOF
    chmod 0755 /etc/init.d/fc-ui
    if [ -x /etc/init.d/fcxray-deploy ]; then
        if rc-service fcxray-deploy status >/dev/null 2>&1; then rc-service fcxray-deploy stop; fi
        rc-update del fcxray-deploy default 2>/dev/null || true
    fi
    if rc-service fc-ui status >/dev/null 2>&1; then rc-service fc-ui stop; fi
    rc-update add fc-ui default
    rc-service fc-ui start
fi
/usr/local/bin/fc-ui wait
exec /usr/local/bin/fc-ui "$mode"
