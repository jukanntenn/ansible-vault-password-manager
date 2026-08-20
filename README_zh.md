# avpm — Ansible Vault 密码管理器

> [English](README.md) | **中文**

[![CI](https://img.shields.io/badge/CI-View%20Actions-lightgrey)](https://github.com/jukanntenn/ansible-vault-password-manager/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

一个面向 Ansible Vault 密码的**极简系统 keyring 适配器**，并将**端到端加密的多设备同步**作为一等功能。

avpm 将每个 Vault 密码存入操作系统原生 keyring（macOS 钥匙串 / Linux Secret Service），并通过 [vault password client script][ansible-vault] 协议提供给 Ansible 使用。它还支持通过 age 加密的清单文件，经 Git 或 WebDAV 后端在多台机器间同步你的 vault-id。

[ansible-vault]: https://docs.ansible.com/ansible/latest/user_guide/vault.html#providing-vault-passwords

## 功能特性

- **Ansible 即插即用** —— 遵循标准 vault-password-client 协议（`avpm --vault-id <id>`）；stdout 纯净无杂讯，可直接管道使用。
- **零配置上手** —— `set`/`get`/`list`/`rm` 开箱即用，无需任何配置文件。
- **安全为先** —— 密码存于系统 keyring（macOS 钥匙串 / Linux Secret Service）或 age 加密文件存储；`#![forbid(unsafe_code)]`、`deny(unwrap_used, expect_used)`、密码内存即时清零。
- **端到端加密同步** —— age 加密（scrypt + ChaCha20-Poly1305）清单文件，经 **Git 或 WebDAV** 推送/拉取，基于时间戳合并并支持交互式冲突解决。
- **CLI + TUI 一体的单一二进制** —— 密码生成（`-g -L 40`）、按住 Space 才显示的安全视图、全屏交互式管理器。
- **高可观测** —— 结构化 `tracing` 日志输出到 stderr（stdout 保持纯净）；密码绝不写入日志。

## 支持平台

| 平台 | Keyring 后端 |
|---|---|
| Linux（含 WSL2） | Secret Service（GNOME Keyring / KWallet），经 `keyring` v1 的 zbus 后端 |
| macOS | Keychain Services，经 `keyring` v1 的 apple-native 后端 |
| Windows | **不支持**（Ansible 本身不运行在 Windows 上） |

WSL2 / 无头 Linux 环境请参考下方的 [WSL2 环境配置](#wsl2--无头-linux-环境配置)章节。

## WSL2 / 无头 Linux 环境配置

在没有桌面环境的 WSL2 或其他无头 Linux 系统上，Secret Service 守护进程
（`gnome-keyring`）通常未安装。缺少它时，avpm 会回退到加密文件存储，且
**无法跨进程缓存**主口令——这意味着每次都要重新输入，Ansible 的非交互式调用
（`avpm --vault-id <id>`）会以退出码 5 失败。

要解决此问题，请安装并启用 Secret Service 守护进程：

```bash
# 1. 安装所需软件包（Debian/Ubuntu）
sudo apt-get update
sudo apt-get install -y gnome-keyring dbus-x11 libsecret-tools

# 2. 在 WSL2 中启用 systemd —— 在 /etc/wsl.conf 中添加：
#    [boot]
#    systemd=true
# 然后在 Windows PowerShell 中执行：  wsl --shutdown   （之后重新打开 WSL）

# 3. 验证
gdbus call --session \
  --dest org.freedesktop.DBus \
  --object-path /org/freedesktop/DBus \
  --method org.freedesktop.DBus.ListActivatableNames \
  | tr ',' '\n' | grep secret
# 预期输出：'org.freedesktop.secrets'
```

守护进程可用后，`avpm unlock` 会将主口令缓存到 session collection
（非持久化，无需 GUI），后续的 `avpm` 调用——包括 Ansible 的
`avpm --vault-id <id>`——无需提示即可正常工作。

> **想用 keyring 后端（而非文件后端）？** 运行一次 `avpm unlock`：它会在
> **终端里**提示输入 OS keyring 密码，并驱动 gnome-keyring 的 control socket
> （与桌面 PAM 登录相同的机制）——无需 GUI，WSL2 和纯无头环境同样可用。
> 它会创建（缺失时）或解锁（锁定时）默认集合；重启后重新运行一次
> `avpm unlock` 即可（每次会话输入一次密码，与桌面上的登录钥匙串一致）。
> 对于没有 control socket 的 Secret Service 提供者（KeePassXC、KWallet），
> 则改用一次性的 GUI 弹窗。详见
> [troubleshooting](docs/troubleshooting.md#daemon-present-but-default-collection-missing-or-locked)。

完整的诊断步骤、session cache 说明和无头环境替代方案请参见
[`docs/troubleshooting.md`](docs/troubleshooting.md)。

## 安装

**需要 Rust ≥ 1.88**（推荐使用 [rustup](https://rustup.rs)：`rustup update stable`）。

```bash
cargo install --git https://github.com/jukanntenn/ansible-vault-password-manager --locked
```

## 构建

```bash
cargo build --release
# 二进制位于 target/release/avpm
```

## 用法

```bash
# 核心 CRUD（无需配置文件）
avpm set dev               # 交互式设置 vault-id 'dev' 的密码
avpm set dev -g -L 40      # 改为生成 40 位密码
avpm get dev               # 将密码打印到 stdout（单行）
avpm list                  # 列出已知 vault-id（按字母序）
avpm show dev              # 安全 TUI 视图：按住 Space 显示密码
avpm rename dev production # 重命名 vault-id
avpm rm dev prod -f        # 删除一个或多个 vault-id

# TUI
avpm tui                   # 全屏交互式管理器

# 加密同步（需 [sync] 配置，见下文）
avpm sync push             # age 加密本地 vault 并推送
avpm sync pull             # 拉取并按时间戳合并到本地
avpm sync status           # 对比本地与远端，不做修改

# 配置
avpm config init           # 交互式初始化配置
avpm config path           # 打印配置文件路径
avpm config edit           # 用 $EDITOR 打开配置

# 为非交互使用解锁
avpm unlock                # keyring 后端：创建/解锁 OS keyring 集合（终端提示输密码）；
                           # file 后端：为本会话缓存主口令
```

### Ansible 集成

avpm 提供**两个二进制**：

- **`avpm`** —— 完整的密码管理器（CLI + TUI）。
- **`avpm-client`** —— Ansible vault 密码客户端入口。

之所以单独提供 `avpm-client`，是因为 Ansible 只有在脚本文件名以 `-client`
结尾时，才会用 `--vault-id <id>` 参数调用它（见 Ansible 的 `script_is_client`
检测，`lib/ansible/parsing/vault/__init__.py`）。如果文件名没有 `-client`
后缀，Ansible 会**无参数**调用脚本，avpm 就无法知道请求的是哪个 vault-id。
所以**务必用 `avpm-client`（而不是 `avpm`）作为 vault 密码来源。**

`avpm-client --vault-id <id>` 将密码打印到 stdout；vault-id 未知时以退出码
**2** 结束（与 Ansible 的 `VAULT_ID_UNKNOWN_RC = 2` 一致，告知 Ansible
"这个 client 没有该 vault-id"）。

```bash
# 1. ansible.cfg（推荐）
[defaults]
vault_password_file = /path/to/avpm-client

# 2. 环境变量
export ANSIBLE_VAULT_PASSWORD_FILE=/path/to/avpm-client

# 3. 命令行 —— 单 vault-id
ansible-playbook --vault-password-file /path/to/avpm-client site.yml

# 4. 多 vault-id（label@client）
ansible-playbook --vault-id dev@/path/to/avpm-client site.yml
ansible-playbook --vault-id dev@/path/to/avpm-client --vault-id prod@/path/to/avpm-client site.yml
```

`avpm-client` 的 stdout 是**纯净的**——只有密码，单行——因此可以安全地
通过管道传给 Ansible。

### 存储后端

avpm 将 vault 存入以下两个后端之一，由 `[storage].backend` 选择（默认为 `auto`）：

- **`keyring`** —— 操作系统原生 keyring（macOS 钥匙串 / Linux Secret Service）。
- **`file`** —— age 加密文件存储（`store.age`，scrypt + armored ASCII），适用于无 keyring 环境（无头 WSL2 / CI 容器）。每次会话需先执行一次 `avpm unlock` 缓存主口令；未缓存时非交互调用以退出码 **5**（`Locked`）结束。
- **`auto`**（默认）—— 用只读探测检查 OS keyring 是否可达；可达则用 keyring，否则回退到文件存储。探测纯粹基于可用性——即使存在残留的 `store.age`，只要 keyring 可达就优先用 keyring，macOS/桌面用户永远不会被意外拽离 keyring。

### 同步配置

`~/.config/avpm/config.toml`（除 sync 后端外所有键均可选）：

```toml
[default]
service = "avpm"   # keyring 服务名；默认 "avpm"

# 存储后端："auto"（默认）、"keyring" 或 "file"
[storage]
backend = "auto"

# 同步可选。配置一个后端：
[sync]
backend = "git"    # 或 "webdav"

[sync.git]
remote = "git@github.com:me/vault-sync.git"
# path = "vault.age"   # 默认：仓库内加密清单文件的路径
# branch = "main"      # 默认

# [sync.webdav]
# url = "https://nextcloud.example.com/remote.php/dav/files/me/avpm/"
# username = "me"
# （密码首次使用时提示输入，并存入 keyring，绝不落盘）
```

同步清单使用 [age] 加密，口令每次使用需手动输入（`scrypt` + ChaCha20-Poly1305 STREAM）。口令**绝不存储**。

[age]: https://age-encryption.org

## 开发

```bash
cargo fmt
cargo clippy --all-targets --features testing -- -D warnings
cargo test --features testing                       # 跳过 #[ignore] 的真实系统测试
cargo test --features testing -- --ignored          # 真实 keyring + git（需要 D-Bus）
```

标有 `#[ignore]` 的测试需要可用的 keyring（D-Bus 会话）和/或系统 git；CI 的 `ignored-tests` job 会搭建这些环境。

## 许可证

基于 [MIT License](LICENSE) 授权。
