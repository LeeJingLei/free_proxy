# free_proxy

`free_proxy` 是一个纯 C 实现的 Linux 命令行工具。它会将本机发起的 IPv4 TCP 连接透明转发至无认证 SOCKS5 代理，适合在宿主机开启代理、Linux 虚拟机需要复用该代理的场景。

## 支持范围

当前版本仅代理 IPv4 TCP 流量，适用于常见的 `ssh`、`apt`、`git`、HTTP(S) 及基于 TCP 的编辑器扩展。

以下流量不会走代理：

- DNS
- UDP（包括 QUIC）
- IPv6

如需避免 IPv6 绕过，请在虚拟机中禁用 IPv6。SOCKS5 服务器必须使用可从虚拟机访问的 IPv4 地址，且当前不支持用户名/密码认证。

进入虚拟机的入站连接（包括 SSH 登录）不会被重定向。

## 依赖条件

- 支持 NAT 的 Linux `iptables`
- root 权限
- 虚拟机能够访问的 SOCKS5 代理，例如宿主机在 NAT 或桥接网络中的地址
- C 编译器与 `make`
- ncurses 开发文件：`sudo apt install libncurses-dev`

## 编译与安装

```sh
make
sudo make install
```

安装后的可执行文件位于 `/usr/local/bin/free_proxy`。

## 使用方式

请使用虚拟机可访问的宿主机 IP，而非一定使用宿主机的局域网 IP。

### 交互式终端界面

不传入子命令时会打开全屏管理界面：

```sh
sudo free_proxy
```

界面每秒刷新一次，显示已保存的代理地址、转发进程、iptables 规则及开机自启状态。

| 按键 | 操作 |
| --- | --- |
| `s` | 使用已保存的代理地址直接启用 |
| `e` | 输入 `IPv4:端口` 的 SOCKS5 地址并启用代理 |
| `d` | 停用代理 |
| `a` | 启用或停用开机自启 |
| `l` | 切换中文或 English 界面（会保存选择） |
| `r` | 立即刷新状态 |
| `q` | 退出界面 |

代理地址输入支持主键盘和数字小键盘；退格键可删除已输入的字符。在代理地址输入框中按 `q` 或 `Esc` 会取消输入并返回主界面；主界面中的 `q` 才会退出程序。

### 适合脚本调用的子命令

```sh
sudo free_proxy enable --proxy 192.168.3.1:7891
sudo free_proxy status
sudo free_proxy disable
```

`enable` 会将代理配置保存到 `/etc/free_proxy/config`，启动本地转发进程，并创建专用的 `iptables` NAT 链。`disable` 只会清理本工具创建的链并停止转发进程。

## 开机自动启动

安装完成并至少配置过一次代理后，执行：

```sh
sudo free_proxy autostart enable
```

该命令会安装并启用 systemd 服务，在网络可用后执行 `free_proxy run`。取消开机自启：

```sh
sudo free_proxy autostart disable
```

`disable` 仅停止当前代理，不会取消开机自启；请使用 `autostart disable` 取消。

## 当前验证范围

当前版本已在严格编译警告选项下通过构建，尚未执行真实 SOCKS5、iptables、systemd 或端到端网络验证。
