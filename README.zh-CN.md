# free_proxy

[English](README.md) | 中文

`free_proxy` 会将 Linux 虚拟机本机发起的 IPv4 TCP 流量透明转发到无认证 SOCKS5 代理。它适用于在宿主机运行代理，并希望虚拟机内的 `apt`、`git`、`ssh`、浏览器和编辑器扩展无需逐个设置代理即可使用该代理的场景。

## 快速开始

### 1. 准备宿主机代理

先在宿主机启动 SOCKS5 服务，并确保虚拟机能够访问它。

> **重要：** 必须在宿主机代理客户端中开启“允许局域网连接”（通常叫作 **Allow LAN**），或明确将 SOCKS5 监听在面向虚拟机的宿主机地址 / `0.0.0.0`。只监听 `127.0.0.1` 的代理无法从虚拟机访问。

- SOCKS5 监听地址应是面向虚拟机的宿主机地址或 `0.0.0.0`，不能只监听 `127.0.0.1`。
- 在宿主机防火墙中放行 SOCKS5 端口。
- 使用虚拟机能访问到的宿主机 IP；在 NAT 模式下，它通常是虚拟机的默认网关。
- 当前版本只支持 IPv4、无用户名和密码认证的 SOCKS5 服务。

安装 `free_proxy` 前，请先在虚拟机中确认能直连 SOCKS5：

```sh
curl --socks5-hostname 192.168.3.2:10808 https://api.ipify.org
```

将 `192.168.3.2:10808` 替换为你的宿主机 SOCKS5 地址和端口。

### 2. 安装

在 Ubuntu 或 Debian 上执行：

```sh
sudo apt update
sudo apt install build-essential libncurses-dev iptables
make
sudo make install
```

安装后的命令为 `/usr/local/bin/free_proxy`。

### 3. 配置并启用

打开交互式控制界面：

```sh
sudo free_proxy
```

按 `e`，输入宿主机代理的 `IPv4:端口`，例如 `192.168.3.2:10808`，然后按 Enter。成功后界面应显示：

```text
转发服务  运行中
iptables  已启用
```

按 `q` 退出控制界面。退出界面不会关闭已经启用的代理。

`free_proxy` 只有在新的转发服务已绑定本地监听端口并完整安装防火墙规则后才报告成功。修改代理地址或端口时，会先停止旧转发服务，再启动新服务。

## 交互式控制界面

任何时候执行 `sudo free_proxy` 都可以打开控制界面。

| 按键 | 操作 |
| --- | --- |
| `s` | 直接启用已经保存的代理地址 |
| `e` | 修改 SOCKS5 的 `IPv4:端口` 并启用 |
| `d` | 停用当前代理 |
| `a` | 启用或停用开机自启 |
| `m` | 打开流量与连接监控（实时速率、累计流量、活跃连接） |
| `t` | 打开网络测试页（可选连通性、延迟或测速） |
| `c` | 诊断配置、进程、iptables、SOCKS5、DNS 和透明转发链路 |
| `u` | 卸载，且必须输入完整的 `yes` 确认 |
| `l` | 切换中文或 English 界面 |
| `r` | 立即刷新状态 |
| `q` | 退出控制界面 |

代理输入框支持主键盘和数字小键盘。输入时按 `q` 或 `Esc` 会取消输入并返回主界面，不会修改现有配置。

按 `m` 打开流量监控页。转发服务运行时会显示实时上下行速度、自启动后的累计流量，以及当前活跃目标（`IPv4:端口` 与每连接字节数）。在该页可按 `1` / `2` / `3` 快速做连通性、延迟或测速。

按 `c` 执行只读连接诊断。诊断会在第一处失败步骤停止，并明确指出是配置、转发进程、本地监听、iptables 规则、代理端口、SOCKS5 协议/认证、本地 DNS、代理出站还是透明转发链路的问题。

按 `t` 进入网络测试页，再选择 `1` 网页连通性、`2` 延迟测试或 `3` 下载测速。连通性与延迟会通过 SOCKS5 检测 25 个常见海外网站；测速最多下载 10 MiB，并实时显示 Mbps。测试过程中按 `q` 可取消，菜单中按 `q` 返回主界面。结果页显示成功数量和失败目标。

## 命令行用法

日常推荐使用交互界面。以下命令适合脚本调用：

```sh
sudo free_proxy enable --proxy 192.168.3.2:10808
sudo free_proxy status
sudo free_proxy disable
```

`enable` 会将地址保存至 `/etc/free_proxy/config`，启动本地转发服务并创建专用 iptables NAT 链。`disable` 只会删除 `free_proxy` 创建的规则。

## 升级与卸载

升级时重新编译并安装：

```sh
make
sudo make install
```

在控制界面按 `u` 并输入 `yes` 即可交互式卸载。脚本中可执行：

```sh
sudo free_proxy uninstall --yes
```

卸载会停止转发服务及其连接处理进程、删除 iptables 规则和保存的配置、禁用并删除 systemd unit、重新加载 systemd，然后删除已安装的二进制文件。

## 开机自动启动

请先执行 `sudo make install`，并至少成功配置过一次代理。随后在控制界面中按 `a`，或执行：

```sh
sudo free_proxy autostart enable
```

取消开机自启：

```sh
sudo free_proxy autostart disable
```

## 验证是否生效

在控制界面中确认“转发服务”为“运行中”且“iptables”为“已启用”，或执行：

```sh
sudo free_proxy status
```

还可以测试 HTTP(S) 请求：

```sh
curl -4 https://api.ipify.org
```

请在宿主机代理客户端的面板或连接日志中确认该请求出现。公网 IP 不一定发生变化：当虚拟机直连和宿主机代理使用同一条网络出口时，两者可能显示相同 IP。

## 常见问题

| 问题 | 检查方式 |
| --- | --- |
| 启用后无法联网 | 确认宿主机 IP 和端口，并先执行快速开始中的显式 SOCKS5 `curl` 测试。 |
| 界面显示 `iptables 已禁用` | 执行 `sudo free_proxy`，按 `s` 后确认状态变为已启用。若缺少 `iptables` 命令，请安装该软件包。 |
| 无法开启开机自启 | 在 systemd 主机上先执行 `sudo make install`，并使用 `/usr/local/bin/free_proxy`，不要只运行 `build/free_proxy`。无 systemd 时会干净跳过开机自启。 |
| 停用或卸载失败 | 再执行 `sudo free_proxy disable` 或 `sudo make uninstall`。现已兼容路径不一致或 `(deleted)` 二进制；若仍失败，检查 `12345` 端口和 `FPROXY_OUT` 规则。 |
| `apt` 可用但 `ping` 失败 | 这是预期行为：`ping` 使用 ICMP，当前 TCP 代理无法处理。 |

## 限制

- 仅代理本机发起的 IPv4 TCP 流量。
- DNS、UDP（包括 QUIC）、IPv6 和 ICMP 不走代理。
- 进入虚拟机的入站连接（包括 SSH 登录）不会被重定向。
- 不支持 SOCKS5 用户名/密码认证，也不支持将代理服务器写为域名。
- 转发服务最多同时处理 128 个客户端连接；SOCKS5 连接尝试在 10 秒后超时、握手 I/O 在 30 秒后超时，空闲代理连接在 5 分钟后超时。

如果不能接受 IPv6 绕过，请在虚拟机中禁用 IPv6。
