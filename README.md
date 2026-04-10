# SDF Mock SDK

**GM/T 0018-2023 密码设备应用接口纯软件模拟库**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-brightgreen)](https://kintaiw.github.io/0018-sdf-mock/)

无需真实密码硬件，即可在开发和测试环境中调用标准 SDF 接口。输出标准动态库（Linux `.so` / Windows `.dll`），与 C、Rust 等语言无缝集成。

> **⚠️ 警告**：本项目**仅供学习和开发测试使用**。配置文件中的示例密钥为公开测试值，**严禁用于生产环境**。

**文档站点**：https://kintaiw.github.io/0018-sdf-mock/

---

## 特性

- **完整 SDF 接口**：覆盖设备管理、密钥管理、非对称运算、对称运算、哈希运算共 20+ 个标准函数
- **国密算法支持**：SM2（签名/加密/密钥交换）、SM3（哈希/HMAC）、SM4（ECB/CBC/CFB/OFB/CTR/GCM/CCM）
- **标准 C ABI**：`extern "C"` 导出，头文件 `sdf.h` 与任意 C/C++ 项目直接集成
- **预设密钥配置**：通过 `mock_keys.toml` 预置 KEK、SM2 签名/加密密钥对，模拟硬件设备密钥区
- **零硬件依赖**：基于 [libsmx](https://crates.io/crates/libsmx) 纯软件实现国密算法

---

## 快速开始

### 1. 编译动态库

```bash
cargo build --release
# 输出：target/release/libsdf_mock.so（Linux）
#       target/release/sdf_mock.dll（Windows）
```

### 2. 准备配置文件

**`config.toml`**（必须存在，`SDF_OpenDevice` 启动时自动查找）

```toml
[log]
level = "info"      # debug / info / warn / error / off
directory = "./"
```

`config.toml` 查找优先级（从高到低）：

| 优先级 | 方式 | 说明 |
|--------|------|------|
| 1 | 环境变量 `OSR_HSM_CONFIG` | 指定配置文件绝对路径 |
| 2 | `/etc/osr/config.toml` | 系统固定路径 |
| 3 | 当前工作目录 `config.toml` | 启动进程时 shell 的 `pwd` |

> 若 `OSR_HSM_CONFIG` 已设置但文件不存在，直接报 `SDR_CONFIGERR`，不继续查找低优先级路径。

`config.toml` 查找优先级（从高到低）：

| 优先级 | 方式 | 说明 |
|--------|------|------|
| 1 | 环境变量 `OSR_HSM_CONFIG` | 指定配置文件绝对路径 |
| 2 | `/etc/osr/config.toml` | 系统固定路径 |
| 3 | 当前工作目录 `config.toml` | 启动进程时 shell 的 `pwd` |

> 若 `OSR_HSM_CONFIG` 已设置但文件不存在，直接报 `SDR_CONFIGERR`，不继续查找低优先级路径。

**`mock_keys.toml`**（可选，提供预置密钥）
```toml
[device]
manufacturer = "MockDevice"
device_name  = "SDF_MOCK_V1"
device_serial = "MOCK20250101"

[root_key]
value = "0123456789ABCDEF0123456789ABCDEF"

[[kek_keys]]
index = 1
value = "FEDCBA9876543210FEDCBA9876543210"

[[sign_keys]]
index = 1
private_key = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
public_key  = "04BB34D0B28F49ABAFAD1AEE5E44B489B730B8B2A2CB6CC068C8B9DABE7C1F0D0..."
```

密钥文件（`mock_keys.toml`）搜索顺序：`SDF_MOCK_CONFIG_DIR` 环境变量 → 当前工作目录。

### 3. C 程序集成

```c
#include "sdf.h"

void *hDevice = NULL, *hSession = NULL;

SDF_OpenDevice(&hDevice);
SDF_OpenSession(hDevice, &hSession);

// ... 密码运算 ...

SDF_CloseSession(hSession);
SDF_CloseDevice(hDevice);
```

编译：
```bash
gcc -o myapp myapp.c -I/path/to/sdf-mock -L/path/to/target/release \
    -lsdf_mock -Wl,-rpath,/path/to/target/release
```

### 4. 运行 C 示例

```bash
cd examples/c_caller
make        # 自动编译 Rust 库 + C demo
./demo
```

---

## 接口总览

### 调用流程

```
SDF_OpenDevice
    └── SDF_OpenSession
            ├── SDF_GenerateRandom
            ├── 密钥管理
            │     ├── SDF_GenerateKeyPair_ECC
            │     ├── SDF_GenerateKeyWithKEK / SDF_ImportKeyWithKEK
            │     ├── SDF_GenerateKeyWithIPK_ECC / SDF_ImportKeyWithISK_ECC
            │     └── SDF_DestroyKey
            ├── 非对称运算
            │     ├── SDF_ExternalSign_ECC / SDF_ExternalVerify_ECC
            │     ├── SDF_InternalSign_ECC / SDF_InternalVerify_ECC
            │     └── SDF_ExternalEncrypt_ECC / SDF_ExternalDecrypt_ECC
            ├── 对称运算
            │     ├── SDF_Encrypt / SDF_Decrypt
            │     └── SDF_CalculateMAC
            └── 哈希运算
                  ├── SDF_HashInit / SDF_HashUpdate / SDF_HashFinal
                  └── SDF_HMACInit / SDF_HMACUpdate / SDF_HMACFinal
    └── SDF_CloseSession
SDF_CloseDevice
```

### 支持的算法标识

| 常量 | 值 | 说明 |
|------|----|------|
| `SGD_SM2_1` | `0x00020200` | SM2 签名 |
| `SGD_SM2_3` | `0x00020800` | SM2 加密 |
| `SGD_SM3`   | `0x00000001` | SM3 哈希 |
| `SGD_SM4_ECB` | `0x00000401` | SM4 ECB |
| `SGD_SM4_CBC` | `0x00000402` | SM4 CBC |
| `SGD_SM4_CFB` | `0x00000404` | SM4 CFB |
| `SGD_SM4_OFB` | `0x00000408` | SM4 OFB |
| `SGD_SM4_CTR` | `0x00000420` | SM4 CTR |
| `SGD_SM4_GCM` | `0x00000440` | SM4 GCM（AEAD）|
| `SGD_SM4_CCM` | `0x00000480` | SM4 CCM（AEAD）|

---

## 项目结构

```
├── src/
│   ├── ffi/          # C ABI 导出层（指针安全检查、类型转换）
│   ├── sdf_impl/     # GM/T 0018 业务逻辑
│   ├── crypto/       # 算法封装（对接 libsmx）
│   ├── key_mgr/      # 内存密钥仓库 + 设备/会话上下文
│   └── config/       # TOML 配置解析
├── tests/
│   └── integration_test.rs   # 端到端集成测试（37个）
├── examples/c_caller/
│   ├── main.c        # C 调用示例
│   └── Makefile
├── sdf.h             # C 头文件（接口声明）
├── config.toml       # 日志配置（必须存在）
└── mock_keys.toml    # 预置密钥配置
```

---

## 开发

```bash
cargo test                        # 全量测试
cargo test test_sm3_hash          # 运行单个测试
RUST_LOG=debug cargo test -- --nocapture  # 显示日志
```

---

## 依赖

- [libsmx](https://crates.io/crates/libsmx) 0.3：国密算法 SM2/SM3/SM4 实现（与 0016-skf-mock、0029-svs-mock 一致）
- Rust 1.70+

---

## 许可

本项目基于 [Apache License 2.0](LICENSE) 开源。

> **⚠️ 警告**：本项目**仅供学习和开发测试使用**。配置文件中的示例密钥为公开测试值，**严禁用于生产环境**。如需在生产环境使用密码设备接口，请使用经过认证的硬件密码设备及其原厂 SDK。
