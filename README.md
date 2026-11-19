# fc-ui

在 Linux VPS 上选择部署回环 Web 面板，或通过数字菜单创建 Xray 服务端。每个节点有独立进程、端口和分享链接。面板及管理代码使用 Python 标准库，Xray 使用 [XTLS 官方 v26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9)。

## 一行启动

在 VPS 终端执行这一行，需要 curl、sha256sum 和访问 GitHub 的网络：

```sh
(shdir=$(mktemp -d) && cd "$shdir" && base=https://github.com/follow-xray/fc-ui/releases/latest/download && curl -fsSL --retry 3 "$base/fcui.run" -o fcui.run && curl -fsSL --retry 3 "$base/fcui.run.sha256" -o fcui.run.sha256 && sha256sum -c fcui.run.sha256 && sh ./fcui.run)
```

安装器从文件执行，因此菜单可以从终端读取输入。首次发布正式 Release 后该地址可用。也可在 [Releases](https://github.com/follow-xray/fc-ui/releases) 下载指定版本。

已有完整源码时也可直接运行 `sh ./install.sh`。单文件包含相同的安装脚本、管理源码、页面和校验清单。安装需要 root 或 sudo、可访问发行版软件源与 GitHub Release 的网络。安装器检查操作系统、CPU 架构和 init，在安装前显示检测结果。通过 NAT 的 VPS 请填写客户端可访问的公网 IP 或域名，本文假定代理端口原样映射到同一外部端口。

## 选择 1：本地管理面板

安装器询问 VPS 地址、SSH 登录用户、SSH 端口和面板端口。默认面板端口为 8787，**监听地址固定为 VPS 上的 127.0.0.1**，并使用独立的随机管理口令。安装器打印实际 SSH 命令、浏览器地址和口令。示例：

1. 在**自己的电脑**打开终端，执行并保持运行：

   ```sh
   ssh -N -L 127.0.0.1:8787:127.0.0.1:8787 -o ExitOnForwardFailure=yes -p 22 admin@vps.example
   ```

2. 在**同一台电脑**的浏览器打开 `http://127.0.0.1:8787/`，输入 VPS 安装终端给出的口令。若本机端口已占用，可把 `-L` 左侧的 8787 改为 18787，并打开 `http://127.0.0.1:18787/`。
3. 选择模板，按需要手动填写节点名、服务器地址、代理端口和对应协议参数，点击“创建并启动”。成功后在节点卡片复制链接。面板支持查看状态、停止和重新启动节点。
4. 在 fcxray 中选择“我的节点 → 导入节点”，粘贴分享链接。管理口令与节点凭据分别使用；再次运行 `sudo fc-ui panel` 可重显 SSH 命令与口令。

管理端口只走 SSH 转发，无需添加面板端口的入站防火墙规则。代理节点需要能够从外部访问其独立代理端口。网页只加载本机静态资源，管理 API 检查 Host、Origin 和 Bearer 口令。口令保留在浏览器标签页的 sessionStorage，点击“锁定面板”会清除。SSH 服务需允许本地端口转发。如果 SSH 显示 `administratively prohibited`，请让 VPS 管理员为该 SSH 账户允许 `AllowTcpForwarding local`，并可用 `PermitOpen 127.0.0.1:8787` 限定转发目的地（按实际端口调整）。安装器不会更改 sshd 配置。

## 选择 2：直接创建代理

填写对外地址并输入编号即可创建节点。CLI 和面板读取同一份目录，原有 1–4 号模板保持原编号。TLS 入站先按域名查找证书，可复用、导入或签发；xdrive 需要配置存储。面板可编辑路径、gRPC 服务名、XHTTP 模式、认证参数和用户凭据。

| 协议 / 传输 | 可选的传输安全 | 补充参数 |
| --- | --- | --- |
| VLESS · TCP/RAW、gRPC、XHTTP | none、TLS、REALITY | TCP 提供传统 Vision；gRPC 提供 serviceName；XHTTP 支持 auto、packet-up、stream-up、stream-one，TLS 另有 H3 模板 |
| VLESS · WebSocket、HTTPUpgrade、mKCP | none、TLS | WS/HTTPUpgrade 可设路径；mKCP 监听 UDP |
| VLESS · Hysteria 2 传输 | TLS | 自动生成独立的传输认证，同时保留 VLESS 用户 ID，使用 UDP |
| VLESS · xdrive | none、TLS（上游存储连接） | 自动生成 VLESS Encryption 密钥对，fcxray 导入时启用 Mux；TLS 可选 H3，配置 local、google-drive、s3 或 template（远端服务须支持所选 HTTP 版本） |
| 原生 Hysteria 2 | TLS | UDP 入站，生成带域名 SNI 和随机密码的 `hy2://` 链接 |
| Trojan · TCP | TLS | 密码自动生成，可在面板自定义。证书须与 SNI 相符 |
| Shadowsocks AEAD | AES-128-GCM、AES-256-GCM、ChaCha20-IETF-Poly1305、XChaCha20-IETF-Poly1305 | TCP + UDP，共用服务端口 |
| Shadowsocks 2022 | BLAKE3 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305 | 密钥按算法生成，分别为 16、32、32 字节的 Base64 编码 |

目录提供 56 个 VLESS 模板，按传输、传输安全、Vision flow 和 VLESS Encryption 组合。公网未配置外层 TLS/REALITY 时会生成 VLESS Encryption；专门的内网明文模板只绑定填写的本机 RFC1918、ULA 或回环地址。非 TCP 的 Vision 模板使用 VLESS Encryption 包装连接。REALITY 仅用于 RAW/TCP、gRPC、XHTTP。xdrive 强制启用 VLESS Encryption 和 Mux，不使用 flow；MASQUE 传输只支持 MASQUE 入站。更多端口、路径、SNI 等取值由用户填写。

xdrive 的存储参数是一个 JSON 对象，必须包含 `service` 和 `remoteFolder`。例如 `{"service":"local","remoteFolder":"shared"}` 会使用状态目录下的 `xdrive/shared`，需要两端能访问同一存储。Google Drive、S3 和 HTTP 模板还需填入该服务对应的 `secrets`、`s3` 或 `template` 参数。此类分享链接包含存储凭据，仅交给授权使用者。服务“已启动”表示进程已启动，云存储实际转发需用自己的账户验证。

创建时先由 Xray 校验配置，再按 TCP、UDP 或存储传输检查启动状态。失败不会保存该节点或返回成功链接。已有节点会保留，数字菜单会跳过本项目已经分配的端口。代理进程使用非 root 账户，支持 1024–65535 端口。默认 IPv4 入站；填写公网 IPv6 字面地址时使用 IPv6 入站。域名默认使用 IPv4，请确保其 A 记录与 VPS 对应。

## TLS 入站证书

CLI 和回环面板共用 VPS 的证书库 `/etc/fc-ui/certs/`。创建 TLS 节点时填写客户端验证的域名（SNI）。连接地址可以单独填公网 IP。系统按证书 SAN 查找精确或单层通配符匹配，检查有效期、系统信任链和私钥配对；同一域名的 Trojan、原生 HY2 和 VLESS TLS 节点可以共用同一张证书。

没有可用证书时，可选择以下来源：

| 来源 | 需要提供的信息 | 后续更新 |
| --- | --- | --- |
| VPS 已有证书 | 选择从 Certbot、按域名部署的 x-ui 目录中发现的匹配项，或输入完整证书链和未加密私钥的绝对路径 | 原签发工具续期，fc-ui 每小时检查源文件并同步 |
| 粘贴 PEM（面板） | 完整证书链及对应私钥 | 在证书库中选择“更新 PEM” |
| ACME HTTP-01 | 域名的 A/AAAA 记录指向可达入口，允许公网 TCP 80；可填联系邮箱 | fc-ui 自动续期 |
| ACME HTTP-01 已有网站 | 网站根目录；请让 `fcui-acme` 可写其中的 `.well-known/acme-challenge/`，并确保公网 80 能访问该目录 | 沿用网站目录 |
| ACME DNS-01 | 首版支持 Cloudflare。输入限定目标区域的 DNS 编辑 Token，按需填 Zone ID 或用于限定账户的 Account ID，可签发 `*.example.com`。自动查找区域时 Token 还需有区域读取权限 | 沿用保存在专用 ACME 账户目录中的凭据 |

使用内部 CA 时，客户端也需要信任对应根证书。

ACME 默认使用 Let's Encrypt。独立的 `fc-ui-cert` 服务部署证书，首次需要签发时获取固定提交、经过 SHA-256 校验的 acme.sh 及 DNS 插件。签发进程使用 `fcui-acme` 账号；节点和面板继续使用 `fcxrayd`。临时 HTTP 验证只在挑战期间监听 80；已有网站占用端口时可选网站目录或 DNS。管理页面仍通过 SSH 转发访问。

证书校验通过后，完整证书链与私钥作为一对原子切换。节点只引用文件路径。当前固定的 Xray 内核默认每小时重新读取证书，可在节点停止、启动后立即加载。源证书或续期校验失败时继续使用上一份已部署证书，面板的证书库显示最近检查结果和引用节点。已有内嵌 PEM 的节点可在节点卡片选择“登记旧证书”，下次启动采用文件引用；若原证书不符合当前校验条件，可先导入该域名的有效证书再迁移。

备份证书和自动续期状态时，妥善保管 `/etc/fc-ui/certs/` 和 `/var/lib/fc-ui-cert/`（含 ACME 账户密钥与 DNS 凭据）。代理节点状态单独保存在 `/var/lib/fc-ui/`。

## 支持环境与管理

| 系统系列 | 包管理器 | 服务管理 |
| --- | --- | --- |
| Debian、Ubuntu 及兼容发行版 | apt | systemd |
| Fedora、Rocky、AlmaLinux、CentOS Stream、Oracle Linux、RHEL 系 | dnf / yum | systemd |
| openSUSE、Arch | zypper / pacman | systemd |
| Alpine | apk | OpenRC + supervise-daemon |

支持 x86_64、aarch64、armv7l、32 位 x86，需 Python 3.8+。发布包 SHA-256 固定在 `app/core.json`，下载并校验后只提取 xray 可执行文件。旧发行版需有仍然可用的软件源。安装器使用系统原生 init，普通无 init 的应用容器不适用。

```sh
sudo fc-ui node              # 继续创建代理
sudo fc-ui panel             # 开启面板或重显访问方式
sudo fc-ui list              # 本机查看节点状态、ID 和链接
sudo fc-ui stop <节点ID>
sudo fc-ui start <节点ID>
```

程序在 `/opt/fc-ui`，命令在 `/usr/local/bin/fc-ui`。管理进程以独立账户 `fcxrayd` 运行，管理套接字、节点配置和面板口令在 `/var/lib/fc-ui` 私有目录内。此目录包含凭据，备份时应保护访问权限。开机或管理服务重启后恢复已启用的节点及已开启的面板；手动停止的节点不会自动启动。异常退出的子进程由管理服务重试启动。

systemd 主机使用 `systemctl status fc-ui`、`journalctl -u fc-ui`；Alpine 使用 `rc-service fc-ui status`。需要停止全部节点及面板时，在 systemd 主机执行 `sudo systemctl disable --now fc-ui`；在 OpenRC 主机执行 `sudo rc-service fc-ui stop && sudo rc-update del fc-ui default`。重新安装不会清空节点数据；更新管理源码后，可在维护窗口重启服务以载入新版。

## 旧版迁移

安装器沿用专用服务账户 `fcxrayd`。检测到 `/var/lib/fcxray-deploy` 时，`/var/lib/fc-ui` 会引用旧数据，保留既有节点、密钥及面板口令；旧的 systemd/OpenRC 服务在交接时停用。升级会短暂重启代理，安装后统一使用 `fc-ui` 命令。

## 发布安装器

将此目录作为仓库根目录推送到 `https://github.com/follow-xray/fc-ui`。推送 tag（例如 `git tag v1.0.0 && git push origin v1.0.0`）会触发 GitHub Actions：用固定版本 Xray 验证模板，生成 `fcui.run` 和 `fcui.run.sha256`，上传两个附件后发布同名 Release。版本号带后缀（如 `v1.0.0-rc.1`）会创建预发布；README 安装命令指向最新正式版本。

## 开发与验证

修改源码后运行 `python3 tools/package.py` 重新生成单文件安装器。

```sh
python3 -m unittest discover -v -s tests
XRAY_TEST_BIN=/path/to/xray FCXRAY_PACKAGE_CONFIG="$PWD/../fcxray/.dart_tool/package_config.json" python3 -m unittest discover -v -s tests
```

第二条会启动真实 Xray 进程，在本机验证整个模板目录、fcxray 链接解析、客户端配置原生校验、端口冲突回滚和恢复。只在测试环境运行。项目按 MPL-2.0 发布，见 LICENSE。
