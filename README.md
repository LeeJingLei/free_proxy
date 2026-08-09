# free_proxy

[English](README.md) | [中文](README.zh-CN.md)

`free_proxy` transparently sends a Linux VM's outbound IPv4 TCP traffic through an unauthenticated SOCKS5 proxy. It is useful when a proxy runs on the host machine and applications inside the VM—including `apt`, `git`, `ssh`, and HTTP(S) clients—should use it without individual proxy settings.

## Quick start

### 1. Prepare the host proxy

Start a SOCKS5 service on the host and make it reachable from the VM.

> **Important:** enable LAN access in the host proxy client (often called **Allow LAN**), or explicitly bind its SOCKS5 listener to the VM-facing host address / `0.0.0.0`. A listener bound only to `127.0.0.1` cannot be reached from the VM.

- Bind the SOCKS5 listener to the host's VM-facing address or `0.0.0.0`, not only `127.0.0.1`.
- Allow the SOCKS5 port through the host firewall.
- Use the host IP visible from the VM. In NAT mode, this is often the VM's default gateway.
- This version supports an IPv4 SOCKS5 server without username/password authentication.

Windows host example:

1. Open Command Prompt and run `ipconfig`. Find a host IPv4 address that the VM can reach—not the VM's own address.
2. Open the host proxy app, note its SOCKS5 port, and enable **Allow LAN**.
3. Record the address as `HOST_IP:SOCKS5_PORT`, for example `192.168.3.2:10808`, for use during configuration.

Before installing `free_proxy`, verify that the VM can reach the proxy directly:

```sh
curl --socks5-hostname 192.168.3.2:10808 https://api.ipify.org
```

Replace `192.168.3.2:10808` with the host SOCKS5 address and port.

### 2. Install

On Ubuntu or Debian:

```sh
make
sudo make install
```

`make` checks for a compiler, the `ncursesw` and `libcurl` development libraries, TLS root certificates, and `iptables`,
then installs missing packages automatically with `sudo apt-get`. GNU make itself
must already be installed. To check without automatic installation, run
`make AUTO_INSTALL_DEPS=0`.

The installed command is `/usr/local/bin/free_proxy`.

### 3. Configure and enable

Open the interactive controller:

```sh
sudo free_proxy
```

Press `e`, enter the host proxy in `IPv4:PORT` form, for example `192.168.3.2:10808`, then press Enter. A successful setup shows:

```text
Forwarder     running
iptables      enabled
```

Press `q` to exit the controller. The proxy remains enabled after the controller exits.

`free_proxy` waits until the replacement forwarder has bound its local listener and installed complete firewall rules before reporting success. When you change the proxy address or port, the old forwarder is stopped before the new one starts.

## Interactive controller

Run `sudo free_proxy` at any time to open the controller.

| Key | Action |
| --- | --- |
| `s` | Enable the previously saved proxy address |
| `e` | Change the SOCKS5 `IPv4:PORT` and enable it |
| `d` | Disable the active proxy |
| `a` | Enable or disable start at boot |
| `m` | Open the traffic monitor (live rates, totals, active connections) |
| `t` | Open the network test page (choose connectivity, latency, or speed) |
| `c` | Diagnose configuration, daemon, iptables, SOCKS5, DNS, and transparent forwarding |
| `u` | Uninstall after typing the exact confirmation `yes` |
| `l` | Switch the controller between English and Chinese |
| `r` | Refresh status |
| `q` | Exit the controller |

The proxy input accepts the main keyboard and numeric keypad. In the input field, press `q` or `Esc` to cancel without changing the configuration.

Press `m` to open the traffic monitor. While the forwarder is running it shows live upload/download speed, totals since daemon start, and active destinations as `IPv4:PORT` with per-connection byte counts. From that page press `1` / `2` / `3` for connectivity, latency, or speed tests.

Press `c` to run a read-only connection diagnosis. It stops at the first failed stage and reports whether the problem is the saved configuration, forwarder, local listener, iptables rules, proxy TCP port, SOCKS5 protocol/authentication, local DNS, proxy outbound connection, or transparent forwarding path.

Press `t` to open the network test page, then choose `1` connectivity, `2` end-to-end response latency, or `3` download speed. Connectivity opens a fresh connection through `free_proxy`, performs a real HTTP(S) request, and requires a valid HTTP response. Latency runs the same request three times per site and reports the median time from request start to the first HTTP response byte, including DNS, TCP, transparent forwarding, SOCKS5, TLS for HTTPS, and server response time. Connectivity and response-latency results appear as soon as each target finishes, followed by a summary after all targets complete. Speed downloads up to 10 MiB and shows live Mbps while running. Press `q` to cancel a running test or leave the menu.

## Command-line usage

The interactive controller is recommended for normal use. The following commands are useful for scripts:

```sh
sudo free_proxy enable --proxy 192.168.3.2:10808
sudo free_proxy status
sudo free_proxy disable
```

`enable` saves the address in `/etc/free_proxy/config`, starts the local forwarder, and installs a dedicated iptables NAT chain. `disable` removes only rules created by `free_proxy`.

## Upgrade and uninstall

To upgrade, rebuild and reinstall:

```sh
make
sudo make install
```

Press `u` in the controller and type `yes` to uninstall interactively. For scripts, use:

```sh
sudo free_proxy uninstall --yes
```

Uninstall stops the forwarder and its connection handlers, removes iptables rules and saved configuration, disables and removes the systemd unit, reloads systemd, and removes the installed binary.

## Start automatically at boot

Install the application with `sudo make install` first. Configure the proxy at least once, then either press `a` in the controller or run:

```sh
sudo free_proxy autostart enable
```

To disable boot startup:

```sh
sudo free_proxy autostart disable
```

## Verify it is working

Use the controller or the following command:

```sh
sudo free_proxy status
```

It should report a running forwarder and enabled iptables rules. You can also run an HTTP(S) request such as:

```sh
curl -4 https://api.ipify.org
```

Check the host proxy dashboard or connection log to confirm that the request reaches the SOCKS5 service. The public IP alone may not change if the VM's direct route and the host proxy use the same internet exit.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| Cannot connect after enabling | Confirm the host IP and port, then run the explicit SOCKS5 `curl` command from the quick start section. |
| Controller shows `iptables disabled` | Run `sudo free_proxy`, press `s`, and confirm it changes to enabled. Install the `iptables` package if the command is missing. |
| Cannot enable start at boot | Install with `sudo make install` on a systemd host and use `/usr/local/bin/free_proxy`, not only `build/free_proxy`. Autostart is skipped cleanly when systemd is unavailable. |
| Disable or uninstall fails | Re-run `sudo free_proxy disable` or `sudo make uninstall`. Cleanup now tolerates path-mismatched or deleted binaries; if it still fails, check port `12345` and the `FPROXY_OUT` iptables chain. |
| Proxy works for `apt` but `ping` fails | Expected: `ping` uses ICMP, which this TCP proxy does not handle. |

## Limitations

- Only locally initiated IPv4 TCP traffic is proxied.
- DNS, UDP (including QUIC), IPv6, and ICMP are not proxied.
- Inbound connections, including SSH sessions into the VM, are not redirected.
- SOCKS5 username/password authentication and proxy hostnames are not supported.
- The forwarder limits active client handlers to 128. SOCKS5 connection attempts time out after 10 seconds, handshake I/O after 30 seconds, and idle proxied connections after 5 minutes.

Disable IPv6 in the guest if IPv6 bypasses are unacceptable.
