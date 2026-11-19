import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import sys
import time

from manager import STATE, daemon
from profiles import TEMPLATES, hostname

HOST_FILE = Path("/etc/fc-ui/public-host")


def call(op, data=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(25)
        sock.connect(str(STATE / "control.sock"))
        sock.sendall(json.dumps({"op": op, "data": data or {}}).encode()+b"\n")
        response = json.load(sock.makefile("r"))
        if "error" in response:
            raise ValueError(response["error"])
        return response["result"]


def prompt(label, default=""):
    entered = input(label + (" [%s]" % default if default else "") + "：").strip()
    return entered or default


def guess_host(ssh):
    if HOST_FILE.exists():
        return HOST_FILE.read_text().strip()
    if len(ssh) == 4:
        return ssh[2]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("192.0.2.1", 9))  # Route lookup; sends no packet.
            return sock.getsockname()[0]
        except OSError:
            return ""


def ssh_command(host, user, ssh_port, panel_port):
    host = hostname(host)
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", user):
        raise ValueError("SSH 用户名无效")
    if not 1 <= int(ssh_port) <= 65535:
        raise ValueError("SSH 端口无效")
    return " ".join(shlex.quote(str(s)) for s in [
        "ssh", "-N", "-L", "127.0.0.1:%s:127.0.0.1:%s" % (panel_port,panel_port),
        "-o", "ExitOnForwardFailure=yes", "-p", int(ssh_port), user+"@"+host])


def menu(mode):
    ssh = os.environ.get("SSH_CONNECTION", "").split()
    host = hostname(prompt("客户端可达的 VPS IP 或域名（NAT 主机请填对外地址）", guess_host(ssh)), allow_loopback=mode == "node")
    if os.geteuid() == 0:
        HOST_FILE.write_text(host+"\n")
        HOST_FILE.chmod(0o644)
    if mode == "panel":
        ssh_user = prompt("SSH 登录用户", os.environ.get("SUDO_USER") or getpass.getuser())
        ssh_port = prompt("SSH 登录端口（有 NAT 时填写对外端口）", ssh[3] if len(ssh)==4 else "22")
        panel_settings = STATE / "panel.json"
        default_port = str(json.loads(panel_settings.read_text())["port"]) if panel_settings.exists() else "8787"
        port = int(prompt("面板回环端口", default_port))
        command = ssh_command(host, ssh_user, ssh_port, port)
        result = call("panel", {"port":port})
        print("\n面板已监听 VPS 的 127.0.0.1:%d。请在你自己的电脑执行并保持终端开启：\n\n%s" % (port, command))
        print("\n然后用本机浏览器打开 http://127.0.0.1:%d/\n管理口令：%s" % (port, result["token"]))
        return
    nodes = call("list")
    occupied = {n["port"] for n in nodes}
    available = {}
    for i, (kind, template) in enumerate(TEMPLATES.items(), 1):
        name, port = template.name, template.port
        while port in occupied:
            port += 1
        available[str(i)] = (kind, port)
        print("%d) %s · 端口 %d" % (i, name, port))
    choice = prompt("选择模板编号", "1")
    if choice not in available:
        raise ValueError("模板编号无效")
    kind, port = available[choice]
    options = {"template":kind, "host":host, "port":port}
    template = TEMPLATES[kind]
    if template.network == "xdrive":
        options["xdrive"] = Path(prompt("存储参数 JSON 文件路径（含 service 和 remoteFolder）")).read_text()
    if template.needs_cert:
        options.update(sni=prompt("证书对应的服务器域名", host),
                       certificate=Path(prompt("PEM 证书链路径")).read_text(),
                       key=Path(prompt("PEM 私钥路径")).read_text())
    result = call("create", options)
    print("\n节点已启动：%s · %s\n在 fcxray 的“我的节点 → 导入节点”粘贴：\n\n%s" % (result["name"], result["id"], result["link"]))
    if template.ports:
        print("\n请在 VPS 防火墙和云安全组放行 %d/%s。" % (port, "、".join(template.ports).upper()))
    else:
        print("xdrive 通过共享存储收发数据；请确认两端均可访问同一目录或存储服务。")


def main():
    parser = argparse.ArgumentParser(description="fc-ui · Xray 服务端部署")
    parser.add_argument("command", choices=["daemon", "wait", "node", "panel", "list", "start", "stop"])
    parser.add_argument("id", nargs="?")
    args = parser.parse_args()
    if args.command == "daemon":
        daemon()
    elif args.command == "wait":
        for _ in range(40):
            try:
                call("list")
                return
            except (ConnectionError, FileNotFoundError):
                time.sleep(.25)
        raise ValueError("管理服务未启动，请检查服务状态和系统日志")
    elif args.command in ("node","panel"):
        menu(args.command)
    elif args.command == "list":
        for n in call("list"):
            print("%s  %s  %s:%s  %s\n%s" % (n["id"], n["name"], n["host"], n["port"], "运行中" if n["running"] else "已停止", n["link"]))
    else:
        print(call(args.command, {"id":args.id}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, EOFError, KeyboardInterrupt) as exc:
        sys.exit("操作未完成：%s" % exc)
