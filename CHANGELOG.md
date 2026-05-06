# Changelog

本项目版本号遵循 [SemVer 2.0](https://semver.org/lang/zh-CN/)，变更记录遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

## [0.2.0] - 2026-05-06

> **BREAKING 变更**：`ECCCipher.C` 字段从 `[u8; 136]` 改为 `[u8; 128]`；错误码数值重新对齐（见下）。
> 从 0.1.x 升级的调用方**必须重新编译**。

### Added

- **流式对称加解密**：`SDF_EncryptInit/Update/Final`、`SDF_DecryptInit/Update/Final`（CBC 含 PKCS#7）
- **流式 CBC-MAC**：`SDF_CalculateMACInit/Update/Final`
- **流式 AEAD（SM4-GCM）**：`SDF_AuthEncInit/Update/Final`、`SDF_AuthDecInit/Update/Final`
- **HMAC-SM3**：`SDF_HMACInit/Update/Final`
- **ECC 密钥协商**：`SDF_GenerateAgreementDataWithECC`、`SDF_GenerateKeyWithECC`、`SDF_GenerateAgreementDataAndKeyWithECC`、`SDF_GenerateKeyWithEPK_ECC`
- **ECC 内部加解密**：`SDF_InternalEncrypt_ECC`、`SDF_InternalDecrypt_ECC`
- **RSA 真实化**：`SDF_GenerateKeyPair_RSA` 实际生成 RSA-2048/4096 密钥对（使用 `rsa 0.9` crate）
- **设备自检**：`SDF_Test`（内部执行 SM3 哈希自检）
- **双轨对照测试基础设施**：`tests/sdk_compat/`（`compat_main.c`、`vectors.json`、`compare.py`、`Makefile`）
- **算法标识补全**：`SGD_RSA`、`SGD_SM4_XTS`、`SGD_SHA224/384/512`
- **RSA 密钥配置**：`mock_keys.toml` 支持 `[[rsa_sign_keys]]` 和 `[[rsa_enc_keys]]` 段

### Changed

- `sdf.h` 头文件补充新增 19+ 个函数声明，并对齐真实 SDK 结构体定义
- 配置加载：`RawConfig` 静默接受真实 SDK `config.toml` 中的 `connection_pool`/`platform`/`tls` 段

### Fixed

- 日志写文件 bug：之前 log file 打开后即 drop，实际写到 stderr；现已使用 `flexi_logger` 修复
- 错误码注释错位：`SDR_PARDENY`、`SDR_ALGNOTSUPPORT`、`SDR_SYMOPERR` 等注释已修正

### Breaking

- **`ECCCipher.C: [u8; 136]` → `[u8; 128]`**：ABI 变化，0.1.x 编译的 C 调用方必须重新编译
- **错误码新增**：`SDR_MACERR`、`SDR_FILEEXISTS`、`SDR_FILEWERR`、`SDR_NOBUFFER`、`SDR_INARGERR`、`SDR_OUTARGERR`、`SDR_MARSHALERR`、`SDR_UNMARSHALERR`、`SDR_STEPERR`
- **错误码移除**：`SDR_PRNGERR`（保留别名）、`SDR_KEYINDEX`（改为 `SDR_KEYNOTEXIST`）、`SDR_INVALIDHANDLE`（改为 `SDR_INARGERR`）

## [0.1.0] - 2025-xx-xx

初始版本，实现 GM/T 0018-2023 核心接口（设备/SM2/SM3/SM4 ECB-CTR + KEK + HMAC + MCP Server）。
