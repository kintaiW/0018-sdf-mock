# sdf-mock — GM/T 0018-2023 Cryptographic Device Interface

> Part of [gm-agent-stack](../gm-agent-stack/) — AI-native GM cryptography toolkit

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![GM/T](https://img.shields.io/badge/GM%2FT-0018--2023-red.svg)](docs/)
[![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-green.svg)](http://localhost:18000/mcp)

Pure-software mock of a GM/T 0018-2023 server-side cryptographic device (加密机/HSM). Ships as a **dynamic library** (`.so`/`.dll`) for FFI and a standalone **MCP Server** binary for AI agent use.

纯软件实现的 GM/T 0018-2023 密码设备接口，提供动态库（供 C/Rust 程序链接）和 MCP Server（供 AI Agent 调用），无需真实加密机。

---

## Quick Start / 快速开始

### MCP Server (for AI agents / 供 AI Agent)

```bash
cargo build --release --bin sdf-mcp
./target/release/sdf-mcp --port 18000
claude mcp add sdf-mock --url http://localhost:18000/mcp
```

### Dynamic Library (for C/Rust programs / 供程序链接)

```bash
cargo build --release
# → target/release/libsdf_mock.so
```

```c
#include "sdf.h"
void *hDevice, *hSession;
SDF_OpenDevice(&hDevice);
SDF_OpenSession(hDevice, &hSession);
// SM2/SM3/SM4 operations...
SDF_CloseSession(hSession);
SDF_CloseDevice(hDevice);
```

## MCP Tools / MCP 工具

| Tool | Description |
|------|-------------|
| `sdf_device_info` | Device info + random number generation |
| `sdf_gen_sm2_keypair` | Generate SM2 key pair |
| `sdf_export_pub_key` | Export built-in signing/encryption public key |
| `sdf_sm2_sign` | SM2 sign — `scope:"external"` or `"internal"` |
| `sdf_sm2_verify` | SM2 verify |
| `sdf_sm2_crypt` | SM2 asymmetric encrypt/decrypt |
| `sdf_sm4_crypt` | SM4 symmetric encrypt/decrypt (ECB/CBC) |
| `sdf_sm4_mac` | SM4 CBC-MAC |
| `sdf_sm3_hash` | SM3 hash (with optional Z-value prefix) |
| `sdf_key_wrap` | Key wrap/unwrap with KEK |

All binary I/O uses **hex-encoded strings**.

## Key Formats / 密钥格式

- **SM2 public key**: `04||x(32)||y(32)` hex — 130 hex chars
- **SM2 private key**: scalar `k` hex — 64 hex chars
- **SM2 ciphertext**: `04||x||y||hash(32)||C` hex (C1||C3||C2 per GM/T 0009)

## Configuration / 配置

`mock_keys.toml` pre-configures test key pairs. `config.toml` must exist for `SDF_OpenDevice`.

```toml
[device]
name = "SDF Mock Device"

[[key_pairs]]
index = 1
type = "sign"
private_key = "..."   # 64 hex chars
public_key  = "..."   # 130 hex chars
```

> ⚠️ **For development and testing only. Not for production use.**  
> ⚠️ **仅供学习和开发测试使用，严禁用于生产环境。**
