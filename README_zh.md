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

WSL2 需在 `/etc/wsl.conf` 中启用 systemd 并安装 `gnome-keyring`。

## 安装

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

# 文件存储后端（无 keyring 环境，如无头 WSL2）
avpm unlock                # 每次会话一次：缓存主口令
```

### Ansible 集成

avpm 遵循 Ansible vault-password-client 协议：`avpm --vault-id <id>`
将密码打印到 stdout；当 vault-id 未知时以退出码 **2** 结束（与上游
keyring client 的 `KEYNAME_UNKNOWN_RC` 一致）。

```bash
# 1. 环境变量
export ANSIBLE_VAULT_PASSWORD_FILE=/path/to/avpm

# 2. 命令行
ansible-playbook --vault-password-file /path/to/avpm site.yml

# 3. ansible.cfg
[defaults]
vault_password_file = /path/to/avpm

# 多 vault-id：
ansible-playbook --vault-id dev@/path/to/avpm site.yml
```

`get` 的 stdout 是**纯净的**——只有密码本身——因此可以安全地通过管道传给 Ansible。

### 存储后端

avpm 将 vault 存入以下两个后端之一，由 `[storage].backend` 选择（默认为 `auto`）：

- **`keyring`** —— 操作系统原生 keyring（macOS 钥匙串 / Linux Secret Service）。
- **`file`** —— age 加密文件存储（`store.age`，scrypt + armored ASCII），适用于无 keyring 环境（无头 WSL2 / CI 容器）。每次会话需先执行一次 `avpm unlock` 缓存主口令；未缓存时非交互调用以退出码 **5**（`Locked`）结束。
- **`auto`**（默认）—— keyring 可用时使用 keyring，否则回退到文件存储。

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
