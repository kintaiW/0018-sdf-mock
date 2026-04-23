/// SDF MCP Server — GM/T 0018-2023 国密设备接口 MCP 工具集（Streamable HTTP 传输）
///
/// 启动方式：
///   sdf-mcp --port 18000 --mode mcp
///
/// 提供 10 个 MCP tool，覆盖 SM2/SM3/SM4 的常见密码运算。
/// 所有输入输出均用 hex 编码，结果以 JSON 字符串返回。
use clap::{Parser, ValueEnum};
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
};
use tracing::info;

// ── 引入 sdf-mock lib 中的业务函数 ───────────────────────────────────────────
use sdf_mock::sdf_impl::device::{
    sdf_open_device, sdf_open_session, sdf_close_session, sdf_get_device_info,
};
use sdf_mock::sdf_impl::key_manage::{
    sdf_generate_random, sdf_generate_key_pair_ecc,
    sdf_export_sign_public_key_ecc, sdf_export_enc_public_key_ecc,
    sdf_import_key, sdf_generate_key_with_kek, sdf_import_key_with_kek,
    sdf_get_private_key_access_right,
};
use sdf_mock::sdf_impl::asymmetric::{
    sdf_external_sign_ecc, sdf_external_verify_ecc,
    sdf_internal_sign_ecc, sdf_internal_verify_ecc,
    sdf_external_encrypt_ecc, sdf_external_decrypt_ecc,
};
use sdf_mock::sdf_impl::symmetric::{sdf_encrypt, sdf_decrypt, sdf_calculate_mac};
use sdf_mock::sdf_impl::hash::{sdf_hash_init, sdf_hash_update, sdf_hash_final,
    sdf_hmac_init, sdf_hmac_update, sdf_hmac_final};
use sdf_mock::types::{
    DEVICEINFO, ECCrefPublicKey, ECCrefPrivateKey, ECCCipher, ECCSignature, alg_id,
};

// ── CLI 参数 ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(version, about = "SDF Mock MCP Server — GM/T 0018-2023 国密设备接口")]
struct Cli {
    /// 监听端口（默认 18000）
    #[arg(long, default_value = "18000")]
    port: u16,

    /// 运行模式：rest（空实现）、mcp（仅 MCP）、both（默认，等同 mcp）
    #[arg(long, default_value = "both")]
    mode: Mode,
}

#[derive(Clone, ValueEnum)]
enum Mode {
    Rest,
    Mcp,
    Both,
}

// ── MCP 参数结构体 ────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DeviceInfoParams {
    #[schemars(description = "生成随机数的字节数（默认32，最大1024）")]
    pub length: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExportPubKeyParams {
    #[schemars(description = "公钥类型：\"sign\"（签名公钥）或 \"enc\"（加密公钥）")]
    pub key_type: String,
    #[schemars(description = "内置密钥索引（默认 1）")]
    pub key_index: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm2SignParams {
    #[schemars(description = "模式：\"external\"（提供私钥 hex）或 \"internal\"（内置私钥索引）")]
    pub scope: String,
    #[schemars(description = "待签名原始数据，hex 编码")]
    pub data_hex: String,
    #[schemars(description = "external 模式时必须提供：私钥（32字节）hex 编码")]
    pub private_key_hex: Option<String>,
    #[schemars(description = "internal 模式时使用的密钥索引（默认 1）")]
    pub key_index: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm2VerifyParams {
    #[schemars(description = "模式：\"external\"（提供公钥 hex）或 \"internal\"（内置公钥索引）")]
    pub scope: String,
    #[schemars(description = "原始数据，hex 编码")]
    pub data_hex: String,
    #[schemars(description = "签名值，hex 编码（r||s 各 64 字节，共128字节）")]
    pub signature_hex: String,
    #[schemars(description = "external 模式时必须提供：公钥（65字节 04||x||y）hex 编码")]
    pub public_key_hex: Option<String>,
    #[schemars(description = "internal 模式时使用的密钥索引（默认 1）")]
    pub key_index: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm2CryptParams {
    #[schemars(description = "操作：\"encrypt\"（加密，需公钥）或 \"decrypt\"（解密，需私钥）")]
    pub action: String,
    #[schemars(description = "待处理数据，hex 编码")]
    pub data_hex: String,
    #[schemars(description = "公钥（加密，65字节 04||x||y hex）或私钥（解密，32字节 hex）")]
    pub key_hex: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm4CryptParams {
    #[schemars(description = "操作：\"encrypt\" 或 \"decrypt\"")]
    pub action: String,
    #[schemars(description = "模式：\"ECB\" 或 \"CBC\"（其他模式暂不支持）")]
    pub mode: String,
    #[schemars(description = "SM4 密钥（16字节=32个 hex 字符）")]
    pub key_hex: String,
    #[schemars(description = "初始向量（CBC 时必须，16字节=32个 hex 字符；ECB 忽略）")]
    pub iv_hex: Option<String>,
    #[schemars(description = "待处理数据，hex 编码（需为16字节的整数倍）")]
    pub data_hex: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm4MacParams {
    #[schemars(description = "SM4 密钥（16字节=32个 hex 字符）")]
    pub key_hex: String,
    #[schemars(description = "待计算 MAC 的数据，hex 编码（需为16字节整数倍）")]
    pub data_hex: String,
    #[schemars(description = "初始向量（16字节 hex；不提供则用全零）")]
    pub iv_hex: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm3HashParams {
    #[schemars(description = "待哈希数据，hex 编码")]
    pub data_hex: String,
    #[schemars(description = "模式：\"hash\"（普通 SM3）或 \"hmac\"（HMAC-SM3）")]
    pub mode: String,
    #[schemars(description = "hmac 模式时必须提供：HMAC 密钥（16字节=32个 hex 字符）")]
    pub hmac_key_hex: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct KeyWrapParams {
    #[schemars(description = "操作：\"wrap\"（包裹生成新密钥）或 \"unwrap\"（解包裹密文密钥）")]
    pub action: String,
    #[schemars(description = "KEK 索引（默认 1）")]
    pub kek_index: Option<u32>,
    #[schemars(description = "unwrap 时提供：密文密钥（16字节=32个 hex 字符）")]
    pub cipher_hex: Option<String>,
}

// ── MCP Server 结构体 ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SdfMcpServer {
    tool_router: ToolRouter<Self>,
}

impl SdfMcpServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

// ── 辅助函数 ─────────────────────────────────────────────────────────────────

/// 统一错误 JSON 格式
fn err_json(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

/// hex 解码，返回 Result<Vec<u8>>，失败时带字段名提示
fn decode_hex(s: &str, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("{field} hex 解码失败: {e}"))
}

/// 打开会话，返回 (session_handle, close_fn) 或错误字符串
/// Reason: 每个 tool 调用都是无状态的，开会话→操作→关会话
fn open_session() -> Result<u32, String> {
    let mut handle = 0u32;
    let rc = sdf_open_session(&mut handle);
    if rc != 0 {
        return Err(format!("SDF_OpenSession 失败 (错误码: {rc:#010x})"));
    }
    Ok(handle)
}

/// 将 ECCrefPublicKey（x/y 各 64 字节右对齐）转为 65 字节 04||x||y
fn ecc_pub_to_bytes(pub_key: &ECCrefPublicKey) -> Vec<u8> {
    // Reason: GM/T 0018 中 x/y 各 64 字节，高 32 字节为补零；SM2 实际坐标为后 32 字节
    let mut out = vec![0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&pub_key.x[32..64]);
    out[33..65].copy_from_slice(&pub_key.y[32..64]);
    out
}

/// 将 65 字节 04||x||y 转为 ECCrefPublicKey（x/y 右对齐 64 字节）
fn bytes_to_ecc_pub(bytes: &[u8]) -> Result<ECCrefPublicKey, String> {
    if bytes.len() == 65 && bytes[0] == 0x04 {
        // 直接用 ecc_ref_to_pub_key 逆操作
        let pk_65 = bytes.to_vec();
        // ecc_ref_to_pub_key 接受 65 字节 Vec<u8>，返回 65 字节 Vec<u8>（libsmx 格式）
        // 我们需要反向：从 65 字节构造 ECCrefPublicKey
        let mut ecc_pub = ECCrefPublicKey::default();
        ecc_pub.bits = 256;
        // x/y 填入低 32 字节（64 字节数组的后 32 字节）
        ecc_pub.x[32..64].copy_from_slice(&pk_65[1..33]);
        ecc_pub.y[32..64].copy_from_slice(&pk_65[33..65]);
        Ok(ecc_pub)
    } else if bytes.len() == 64 {
        // 无 04 前缀的裸坐标
        let mut ecc_pub = ECCrefPublicKey::default();
        ecc_pub.bits = 256;
        ecc_pub.x[32..64].copy_from_slice(&bytes[0..32]);
        ecc_pub.y[32..64].copy_from_slice(&bytes[32..64]);
        Ok(ecc_pub)
    } else {
        Err(format!("公钥长度不正确：期望 65(04||x||y) 或 64(x||y) 字节，实际 {} 字节", bytes.len()))
    }
}

/// 将 32 字节私钥填入 ECCrefPrivateKey（K[32..64]）
fn bytes_to_ecc_pri(bytes: &[u8]) -> Result<ECCrefPrivateKey, String> {
    if bytes.len() != 32 {
        return Err(format!("私钥长度不正确：期望 32 字节，实际 {} 字节", bytes.len()));
    }
    let mut pri = ECCrefPrivateKey::default();
    pri.bits = 256;
    pri.K[32..64].copy_from_slice(bytes);
    Ok(pri)
}

/// 将 ECCrefPrivateKey 转回 32 字节（K[32..64]）
fn ecc_pri_to_bytes(pri: &ECCrefPrivateKey) -> Vec<u8> {
    pri.K[32..64].to_vec()
}

/// 将 ECCCipher 序列化为 hex：x||y||M||C（各字段展平）
fn ecc_cipher_to_hex(c: &ECCCipher) -> String {
    // Reason: 只取 x/y 的低 32 字节（有效坐标），与 C1(04||x||y) 编码规则保持一致
    let mut buf = Vec::with_capacity(65 + 32 + c.L as usize);
    buf.push(0x04);
    buf.extend_from_slice(&c.x[32..64]);
    buf.extend_from_slice(&c.y[32..64]);
    buf.extend_from_slice(&c.M);
    buf.extend_from_slice(&c.C[..c.L as usize]);
    hex::encode(buf)
}

/// 从 hex 还原 ECCCipher（04||x(32)||y(32)||M(32)||C(变长)）
fn hex_to_ecc_cipher(hex_str: &str) -> Result<ECCCipher, String> {
    let bytes = decode_hex(hex_str, "cipher_hex")?;
    // 最小长度：1(04) + 32(x) + 32(y) + 32(M) = 97
    if bytes.len() < 97 || bytes[0] != 0x04 {
        return Err(format!("密文格式不正确：期望 04||x(32)||y(32)||M(32)||C，实际 {} 字节", bytes.len()));
    }
    let mut cipher = ECCCipher::default();
    cipher.x[32..64].copy_from_slice(&bytes[1..33]);
    cipher.y[32..64].copy_from_slice(&bytes[33..65]);
    cipher.M.copy_from_slice(&bytes[65..97]);
    let c_len = bytes.len() - 97;
    if c_len > 136 {
        return Err(format!("密文 C 段过长：{c_len} > 136 字节"));
    }
    cipher.L = c_len as u32;
    cipher.C[..c_len].copy_from_slice(&bytes[97..]);
    Ok(cipher)
}

/// ECCSignature 转 hex（r(32)||s(32) 各取低32字节）
fn ecc_sig_to_hex(sig: &ECCSignature) -> String {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&sig.r[32..64]);
    buf.extend_from_slice(&sig.s[32..64]);
    hex::encode(buf)
}

/// hex 还原 ECCSignature（r(32)||s(32)，共 64 字节）
fn hex_to_ecc_sig(hex_str: &str) -> Result<ECCSignature, String> {
    let bytes = decode_hex(hex_str, "signature_hex")?;
    if bytes.len() != 64 {
        return Err(format!("签名长度不正确：期望 64 字节(r||s)，实际 {} 字节", bytes.len()));
    }
    let mut sig = ECCSignature::default();
    sig.r[32..64].copy_from_slice(&bytes[0..32]);
    sig.s[32..64].copy_from_slice(&bytes[32..64]);
    Ok(sig)
}

// ── 10 个 MCP Tool 实现 ───────────────────────────────────────────────────────

#[tool_router]
impl SdfMcpServer {
    /// 工具1：获取 SDF 设备信息并生成随机数
    #[tool(
        description = "获取 SDF 设备信息（GM/T 0018-2023 SDF_GetDeviceInfo）并生成随机数。\
                       返回 JSON：{\"device_name\":\"...\",\"manufacturer\":\"...\",\
                       \"firmware_version\":\"...\",\"random_hex\":\"...\"}"
    )]
    async fn sdf_device_info(&self, Parameters(p): Parameters<DeviceInfoParams>) -> String {
        let length = p.length.unwrap_or(32).min(1024);
        let session = match open_session() {
            Ok(h) => h,
            Err(e) => return err_json(&e),
        };

        let mut info = DEVICEINFO::default();
        let rc = sdf_get_device_info(session, &mut info);
        if rc != 0 {
            let _ = sdf_close_session(session);
            return err_json(&format!("SDF_GetDeviceInfo 失败 (错误码: {rc:#010x})"));
        }

        let mut random = Vec::new();
        let rc = sdf_generate_random(session, length, &mut random);
        if rc != 0 {
            let _ = sdf_close_session(session);
            return err_json(&format!("SDF_GenerateRandom 失败 (错误码: {rc:#010x})"));
        }

        let _ = sdf_close_session(session);

        // 从 C 字节数组提取 UTF-8 字符串（截断空字节）
        let device_name = String::from_utf8_lossy(
            &info.DeviceName[..info.DeviceName.iter().position(|&b| b == 0).unwrap_or(16)]
        ).to_string();
        let manufacturer = String::from_utf8_lossy(
            &info.IssuerName[..info.IssuerName.iter().position(|&b| b == 0).unwrap_or(40)]
        ).to_string();

        serde_json::json!({
            "device_name": device_name,
            "manufacturer": manufacturer,
            "firmware_version": format!("{:#010x}", info.DeviceVersion),
            "random_hex": hex::encode(&random)
        }).to_string()
    }

    /// 工具2：生成 SM2 密钥对
    #[tool(
        description = "生成 SM2 密钥对（GM/T 0018-2023 SDF_GenerateKeyPair_ECC）。\
                       返回 JSON：{\"private_key_hex\":\"...\",\"public_key_hex\":\"...\"}\
                       （公钥 65 字节 04||x||y hex，私钥 32 字节 hex）"
    )]
    async fn sdf_gen_sm2_keypair(&self, _p: Parameters<serde_json::Value>) -> String {
        let session = match open_session() {
            Ok(h) => h,
            Err(e) => return err_json(&e),
        };

        let mut pub_key = ECCrefPublicKey::default();
        let mut pri_key = ECCrefPrivateKey::default();
        // Reason: alg_id=0x00040002 对应 SM2（部分实现用此值），_alg 参数在 mock 中被忽略
        let rc = sdf_generate_key_pair_ecc(session, 0x00040002, 256, &mut pub_key, &mut pri_key);
        let _ = sdf_close_session(session);

        if rc != 0 {
            return err_json(&format!("SDF_GenerateKeyPair_ECC 失败 (错误码: {rc:#010x})"));
        }

        serde_json::json!({
            "private_key_hex": hex::encode(ecc_pri_to_bytes(&pri_key)),
            "public_key_hex": hex::encode(ecc_pub_to_bytes(&pub_key))
        }).to_string()
    }

    /// 工具3：导出内置 SM2 公钥
    #[tool(
        description = "导出内置 SM2 公钥（签名公钥或加密公钥）。\
                       key_type: \"sign\" 或 \"enc\"，key_index 默认 1。\
                       返回 JSON：{\"public_key_hex\":\"...\",\"key_type\":\"...\",\"key_index\":1}"
    )]
    async fn sdf_export_pub_key(&self, Parameters(p): Parameters<ExportPubKeyParams>) -> String {
        let key_index = p.key_index.unwrap_or(1);
        let session = match open_session() {
            Ok(h) => h,
            Err(e) => return err_json(&e),
        };

        let mut pub_key = ECCrefPublicKey::default();
        let rc = match p.key_type.as_str() {
            "sign" => sdf_export_sign_public_key_ecc(session, key_index, &mut pub_key),
            "enc" => sdf_export_enc_public_key_ecc(session, key_index, &mut pub_key),
            other => {
                let _ = sdf_close_session(session);
                return err_json(&format!("key_type 无效：\"{other}\"，应为 \"sign\" 或 \"enc\""));
            }
        };
        let _ = sdf_close_session(session);

        if rc != 0 {
            return err_json(&format!("导出公钥失败 (错误码: {rc:#010x})"));
        }

        serde_json::json!({
            "public_key_hex": hex::encode(ecc_pub_to_bytes(&pub_key)),
            "key_type": p.key_type,
            "key_index": key_index
        }).to_string()
    }

    /// 工具4：SM2 签名
    #[tool(
        description = "SM2 签名（GM/T 0018-2023）。\
                       scope=\"external\"：提供 private_key_hex（32字节hex），对数据 SM3 哈希后签名；\
                       scope=\"internal\"：使用内置密钥（key_index 默认1，需先在 mock_keys.toml 配置）。\
                       返回 JSON：{\"signature_hex\":\"...\",\"scope\":\"external|internal\"}\
                       （签名 64 字节 r||s hex）"
    )]
    async fn sdf_sm2_sign(&self, Parameters(p): Parameters<Sm2SignParams>) -> String {
        let data = match decode_hex(&p.data_hex, "data_hex") {
            Ok(d) => d,
            Err(e) => return err_json(&e),
        };
        let session = match open_session() {
            Ok(h) => h,
            Err(e) => return err_json(&e),
        };

        let mut sig = ECCSignature::default();

        match p.scope.as_str() {
            "external" => {
                let pri_hex = match &p.private_key_hex {
                    Some(h) => h,
                    None => {
                        let _ = sdf_close_session(session);
                        return err_json("external 模式需提供 private_key_hex");
                    }
                };
                let pri_bytes = match decode_hex(pri_hex, "private_key_hex") {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = sdf_close_session(session);
                        return err_json(&e);
                    }
                };
                let pri_key = match bytes_to_ecc_pri(&pri_bytes) {
                    Ok(k) => k,
                    Err(e) => {
                        let _ = sdf_close_session(session);
                        return err_json(&e);
                    }
                };
                // Reason: SDF External Sign 接收预哈希的32字节 e 值，需先 SM3 哈希原始数据
                let hash = compute_sm3_hash(session, &data);
                let hash = match hash {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = sdf_close_session(session);
                        return err_json(&e);
                    }
                };
                let rc = sdf_external_sign_ecc(session, alg_id::SGD_SM2_1, &pri_key, &hash, &mut sig);
                let _ = sdf_close_session(session);
                if rc != 0 {
                    return err_json(&format!("SDF_ExternalSign_ECC 失败 (错误码: {rc:#010x})"));
                }
            }
            "internal" => {
                let key_index = p.key_index.unwrap_or(1);
                // Reason: 内部签名需先获取私钥访问权限（mock 场景不验密码，直接授权）
                let _ = sdf_get_private_key_access_right(session, key_index, b"");
                let rc = sdf_internal_sign_ecc(session, key_index, &data, &mut sig);
                let _ = sdf_close_session(session);
                if rc != 0 {
                    return err_json(&format!("SDF_InternalSign_ECC 失败 (错误码: {rc:#010x})，请检查 mock_keys.toml 是否配置了对应签名密钥"));
                }
            }
            other => {
                let _ = sdf_close_session(session);
                return err_json(&format!("scope 无效：\"{other}\"，应为 \"external\" 或 \"internal\""));
            }
        }

        serde_json::json!({
            "signature_hex": ecc_sig_to_hex(&sig),
            "scope": p.scope
        }).to_string()
    }

    /// 工具5：SM2 验签
    #[tool(
        description = "SM2 验签（GM/T 0018-2023）。\
                       scope=\"external\"：提供 public_key_hex（65字节04||x||y hex），对数据 SM3 哈希后验签；\
                       scope=\"internal\"：使用内置公钥（key_index 默认1）。\
                       signature_hex 为 64 字节 r||s hex。\
                       返回 JSON：{\"valid\":true} 或 {\"error\":\"...\"}"
    )]
    async fn sdf_sm2_verify(&self, Parameters(p): Parameters<Sm2VerifyParams>) -> String {
        let data = match decode_hex(&p.data_hex, "data_hex") {
            Ok(d) => d,
            Err(e) => return err_json(&e),
        };
        let sig = match hex_to_ecc_sig(&p.signature_hex) {
            Ok(s) => s,
            Err(e) => return err_json(&e),
        };
        let session = match open_session() {
            Ok(h) => h,
            Err(e) => return err_json(&e),
        };

        match p.scope.as_str() {
            "external" => {
                let pub_hex = match &p.public_key_hex {
                    Some(h) => h,
                    None => {
                        let _ = sdf_close_session(session);
                        return err_json("external 模式需提供 public_key_hex");
                    }
                };
                let pub_bytes = match decode_hex(pub_hex, "public_key_hex") {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = sdf_close_session(session);
                        return err_json(&e);
                    }
                };
                let pub_key = match bytes_to_ecc_pub(&pub_bytes) {
                    Ok(k) => k,
                    Err(e) => {
                        let _ = sdf_close_session(session);
                        return err_json(&e);
                    }
                };
                // Reason: External Verify 同样接收预哈希数据
                let hash = compute_sm3_hash(session, &data);
                let hash = match hash {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = sdf_close_session(session);
                        return err_json(&e);
                    }
                };
                let rc = sdf_external_verify_ecc(session, alg_id::SGD_SM2_1, &pub_key, &hash, &sig);
                let _ = sdf_close_session(session);
                if rc == 0 {
                    serde_json::json!({ "valid": true }).to_string()
                } else {
                    err_json(&format!("验签失败 (错误码: {rc:#010x})"))
                }
            }
            "internal" => {
                let key_index = p.key_index.unwrap_or(1);
                let rc = sdf_internal_verify_ecc(session, key_index, &data, &sig);
                let _ = sdf_close_session(session);
                if rc == 0 {
                    serde_json::json!({ "valid": true }).to_string()
                } else {
                    err_json(&format!("验签失败 (错误码: {rc:#010x})，请检查 mock_keys.toml 签名密钥配置"))
                }
            }
            other => {
                let _ = sdf_close_session(session);
                err_json(&format!("scope 无效：\"{other}\"，应为 \"external\" 或 \"internal\""))
            }
        }
    }

    /// 工具6：SM2 非对称加解密
    #[tool(
        description = "SM2 非对称加解密（external 模式，GM/T 0018-2023 SDF_ExternalEncrypt/Decrypt_ECC）。\
                       action=\"encrypt\"：key_hex 为公钥（65字节04||x||y hex），data_hex 为明文（最大136字节）；\
                       action=\"decrypt\"：key_hex 为私钥（32字节hex），data_hex 为密文（04||x||y||M||C hex）。\
                       返回 JSON：{\"result_hex\":\"...\",\"action\":\"encrypt|decrypt\"}"
    )]
    async fn sdf_sm2_crypt(&self, Parameters(p): Parameters<Sm2CryptParams>) -> String {
        let session = match open_session() {
            Ok(h) => h,
            Err(e) => return err_json(&e),
        };

        match p.action.as_str() {
            "encrypt" => {
                let data = match decode_hex(&p.data_hex, "data_hex") {
                    Ok(d) => d,
                    Err(e) => { let _ = sdf_close_session(session); return err_json(&e); }
                };
                let pub_bytes = match decode_hex(&p.key_hex, "key_hex") {
                    Ok(b) => b,
                    Err(e) => { let _ = sdf_close_session(session); return err_json(&e); }
                };
                let pub_key = match bytes_to_ecc_pub(&pub_bytes) {
                    Ok(k) => k,
                    Err(e) => { let _ = sdf_close_session(session); return err_json(&e); }
                };
                let mut cipher = ECCCipher::default();
                let rc = sdf_external_encrypt_ecc(session, alg_id::SGD_SM2_3, &pub_key, &data, &mut cipher);
                let _ = sdf_close_session(session);
                if rc != 0 {
                    return err_json(&format!("SM2 加密失败 (错误码: {rc:#010x})"));
                }
                serde_json::json!({
                    "result_hex": ecc_cipher_to_hex(&cipher),
                    "action": "encrypt"
                }).to_string()
            }
            "decrypt" => {
                let cipher = match hex_to_ecc_cipher(&p.data_hex) {
                    Ok(c) => c,
                    Err(e) => { let _ = sdf_close_session(session); return err_json(&e); }
                };
                let pri_bytes = match decode_hex(&p.key_hex, "key_hex") {
                    Ok(b) => b,
                    Err(e) => { let _ = sdf_close_session(session); return err_json(&e); }
                };
                let pri_key = match bytes_to_ecc_pri(&pri_bytes) {
                    Ok(k) => k,
                    Err(e) => { let _ = sdf_close_session(session); return err_json(&e); }
                };
                let mut plaintext = Vec::new();
                let rc = sdf_external_decrypt_ecc(session, alg_id::SGD_SM2_3, &pri_key, &cipher, &mut plaintext);
                let _ = sdf_close_session(session);
                if rc != 0 {
                    return err_json(&format!("SM2 解密失败 (错误码: {rc:#010x})"));
                }
                serde_json::json!({
                    "result_hex": hex::encode(&plaintext),
                    "action": "decrypt"
                }).to_string()
            }
            other => {
                let _ = sdf_close_session(session);
                err_json(&format!("action 无效：\"{other}\"，应为 \"encrypt\" 或 \"decrypt\""))
            }
        }
    }

    /// 工具7：SM4 对称加解密（ECB/CBC）
    #[tool(
        description = "SM4 对称加解密（GM/T 0018-2023 SDF_Encrypt/Decrypt）。\
                       支持 ECB 和 CBC 模式（其他模式暂不支持）。\
                       key_hex 为 16 字节（32 hex 字符），iv_hex CBC 时必须提供（16字节），\
                       data_hex 需为16字节整数倍。\
                       返回 JSON：{\"result_hex\":\"...\",\"mode\":\"...\",\"action\":\"...\"}"
    )]
    async fn sdf_sm4_crypt(&self, Parameters(p): Parameters<Sm4CryptParams>) -> String {
        let alg = match p.mode.as_str() {
            "ECB" => alg_id::SGD_SM4_ECB,
            "CBC" => alg_id::SGD_SM4_CBC,
            other => return err_json(&format!("mode \"{other}\" 暂不支持，请使用 ECB 或 CBC")),
        };

        let key_bytes = match decode_hex(&p.key_hex, "key_hex") {
            Ok(b) => b,
            Err(e) => return err_json(&e),
        };
        if key_bytes.len() != 16 {
            return err_json(&format!("key_hex 长度不正确：期望16字节，实际{}字节", key_bytes.len()));
        }

        let data = match decode_hex(&p.data_hex, "data_hex") {
            Ok(d) => d,
            Err(e) => return err_json(&e),
        };

        // CBC 需要 IV，ECB 用全零 IV（被忽略）
        let iv_bytes = if alg == alg_id::SGD_SM4_ECB {
            vec![0u8; 16]
        } else {
            match &p.iv_hex {
                Some(iv_hex) => match decode_hex(iv_hex, "iv_hex") {
                    Ok(b) => b,
                    Err(e) => return err_json(&e),
                },
                None => return err_json("CBC 模式需要提供 iv_hex"),
            }
        };
        if iv_bytes.len() != 16 {
            return err_json(&format!("iv_hex 长度不正确：期望16字节，实际{}字节", iv_bytes.len()));
        }
        let iv: [u8; 16] = iv_bytes.try_into().unwrap();

        let session = match open_session() {
            Ok(h) => h,
            Err(e) => return err_json(&e),
        };

        // 先导入密钥，拿到 key_handle
        let mut key_handle = 0u32;
        let rc = sdf_import_key(session, &key_bytes, &mut key_handle);
        if rc != 0 {
            let _ = sdf_close_session(session);
            return err_json(&format!("SDF_ImportKey 失败 (错误码: {rc:#010x})"));
        }

        let mut result = Vec::new();
        let rc = match p.action.as_str() {
            "encrypt" => sdf_encrypt(session, key_handle, alg, &iv, &data, &mut result),
            "decrypt" => sdf_decrypt(session, key_handle, alg, &iv, &data, &mut result),
            other => {
                let _ = sdf_close_session(session);
                return err_json(&format!("action \"{other}\" 无效，应为 \"encrypt\" 或 \"decrypt\""));
            }
        };
        let _ = sdf_close_session(session);

        if rc != 0 {
            return err_json(&format!("SM4 {} 失败 (错误码: {rc:#010x})", p.action));
        }

        serde_json::json!({
            "result_hex": hex::encode(&result),
            "mode": p.mode,
            "action": p.action
        }).to_string()
    }

    /// 工具8：计算 SM4 CBC-MAC
    #[tool(
        description = "计算 SM4 CBC-MAC（GM/T 0018-2023 SDF_CalculateMAC）。\
                       key_hex 为16字节（32 hex），data_hex 需为16字节整数倍，\
                       iv_hex 不提供则用全零16字节。\
                       返回 JSON：{\"mac_hex\":\"...\"}"
    )]
    async fn sdf_sm4_mac(&self, Parameters(p): Parameters<Sm4MacParams>) -> String {
        let key_bytes = match decode_hex(&p.key_hex, "key_hex") {
            Ok(b) => b,
            Err(e) => return err_json(&e),
        };
        if key_bytes.len() != 16 {
            return err_json(&format!("key_hex 长度不正确：期望16字节，实际{}字节", key_bytes.len()));
        }

        let data = match decode_hex(&p.data_hex, "data_hex") {
            Ok(d) => d,
            Err(e) => return err_json(&e),
        };

        let iv_bytes = match &p.iv_hex {
            Some(iv_hex) => match decode_hex(iv_hex, "iv_hex") {
                Ok(b) => b,
                Err(e) => return err_json(&e),
            },
            None => vec![0u8; 16],
        };
        if iv_bytes.len() != 16 {
            return err_json(&format!("iv_hex 长度不正确：期望16字节，实际{}字节", iv_bytes.len()));
        }
        let iv: [u8; 16] = iv_bytes.try_into().unwrap();

        let session = match open_session() {
            Ok(h) => h,
            Err(e) => return err_json(&e),
        };

        let mut key_handle = 0u32;
        let rc = sdf_import_key(session, &key_bytes, &mut key_handle);
        if rc != 0 {
            let _ = sdf_close_session(session);
            return err_json(&format!("SDF_ImportKey 失败 (错误码: {rc:#010x})"));
        }

        let mut mac = [0u8; 16];
        let rc = sdf_calculate_mac(session, key_handle, &iv, &data, &mut mac);
        let _ = sdf_close_session(session);

        if rc != 0 {
            return err_json(&format!("SDF_CalculateMAC 失败 (错误码: {rc:#010x})"));
        }

        serde_json::json!({ "mac_hex": hex::encode(&mac) }).to_string()
    }

    /// 工具9：SM3 哈希（支持 HMAC 模式）
    #[tool(
        description = "计算 SM3 哈希（GM/T 0018-2023 SDF_HashInit/Update/Final），\
                       支持 HMAC-SM3 模式（SDF_HMACInit/Update/Final）。\
                       mode=\"hash\"：普通 SM3 哈希；\
                       mode=\"hmac\"：HMAC-SM3（hmac_key_hex 为16字节hex，必须提供）。\
                       返回 JSON：{\"hash_hex\":\"...\",\"mode\":\"hash|hmac\"}"
    )]
    async fn sdf_sm3_hash(&self, Parameters(p): Parameters<Sm3HashParams>) -> String {
        let data = match decode_hex(&p.data_hex, "data_hex") {
            Ok(d) => d,
            Err(e) => return err_json(&e),
        };
        let session = match open_session() {
            Ok(h) => h,
            Err(e) => return err_json(&e),
        };

        match p.mode.as_str() {
            "hash" => {
                let rc = sdf_hash_init(session, alg_id::SGD_SM3, None, b"");
                if rc != 0 {
                    let _ = sdf_close_session(session);
                    return err_json(&format!("SDF_HashInit 失败 (错误码: {rc:#010x})"));
                }
                let rc = sdf_hash_update(session, &data);
                if rc != 0 {
                    let _ = sdf_close_session(session);
                    return err_json(&format!("SDF_HashUpdate 失败 (错误码: {rc:#010x})"));
                }
                let mut hash = [0u8; 32];
                let rc = sdf_hash_final(session, &mut hash);
                let _ = sdf_close_session(session);
                if rc != 0 {
                    return err_json(&format!("SDF_HashFinal 失败 (错误码: {rc:#010x})"));
                }
                serde_json::json!({ "hash_hex": hex::encode(&hash), "mode": "hash" }).to_string()
            }
            "hmac" => {
                let hmac_key_hex = match &p.hmac_key_hex {
                    Some(h) => h,
                    None => {
                        let _ = sdf_close_session(session);
                        return err_json("hmac 模式需提供 hmac_key_hex");
                    }
                };
                let key_bytes = match decode_hex(hmac_key_hex, "hmac_key_hex") {
                    Ok(b) => b,
                    Err(e) => { let _ = sdf_close_session(session); return err_json(&e); }
                };
                if key_bytes.len() != 16 {
                    let _ = sdf_close_session(session);
                    return err_json(&format!("hmac_key_hex 长度不正确：期望16字节，实际{}字节", key_bytes.len()));
                }

                let mut key_handle = 0u32;
                let rc = sdf_import_key(session, &key_bytes, &mut key_handle);
                if rc != 0 {
                    let _ = sdf_close_session(session);
                    return err_json(&format!("SDF_ImportKey 失败 (错误码: {rc:#010x})"));
                }

                let rc = sdf_hmac_init(session, key_handle, alg_id::SGD_SM3);
                if rc != 0 {
                    let _ = sdf_close_session(session);
                    return err_json(&format!("SDF_HMACInit 失败 (错误码: {rc:#010x})"));
                }
                let rc = sdf_hmac_update(session, &data);
                if rc != 0 {
                    let _ = sdf_close_session(session);
                    return err_json(&format!("SDF_HMACUpdate 失败 (错误码: {rc:#010x})"));
                }
                let mut mac = [0u8; 32];
                let rc = sdf_hmac_final(session, &mut mac);
                let _ = sdf_close_session(session);
                if rc != 0 {
                    return err_json(&format!("SDF_HMACFinal 失败 (错误码: {rc:#010x})"));
                }
                serde_json::json!({ "hash_hex": hex::encode(&mac), "mode": "hmac" }).to_string()
            }
            other => {
                let _ = sdf_close_session(session);
                err_json(&format!("mode 无效：\"{other}\"，应为 \"hash\" 或 \"hmac\""))
            }
        }
    }

    /// 工具10：KEK 密钥包裹/解包裹
    #[tool(
        description = "使用 KEK（密钥加密密钥）包裹/解包裹对称密钥（GM/T 0018-2023）。\
                       action=\"wrap\"：生成新的随机 SM4 会话密钥并用 KEK 加密，返回密文和密钥句柄；\
                       action=\"unwrap\"：用 KEK 解密 cipher_hex 得到会话密钥句柄。\
                       kek_index 默认 1（需在 mock_keys.toml 中配置 KEK）。\
                       返回 JSON：{\"key_handle\":u32,\"cipher_hex\":\"...\"} 或 {\"key_handle\":u32}"
    )]
    async fn sdf_key_wrap(&self, Parameters(p): Parameters<KeyWrapParams>) -> String {
        let kek_index = p.kek_index.unwrap_or(1);
        let session = match open_session() {
            Ok(h) => h,
            Err(e) => return err_json(&e),
        };

        match p.action.as_str() {
            "wrap" => {
                let mut cipher_key = Vec::new();
                let mut key_handle = 0u32;
                // Reason: bits=128 表示生成 SM4（128位）会话密钥
                let rc = sdf_generate_key_with_kek(session, 128, kek_index, &mut cipher_key, &mut key_handle);
                let _ = sdf_close_session(session);
                if rc != 0 {
                    return err_json(&format!("SDF_GenerateKeyWithKEK 失败 (错误码: {rc:#010x})，请检查 mock_keys.toml 是否配置了 KEK"));
                }
                serde_json::json!({
                    "key_handle": key_handle,
                    "cipher_hex": hex::encode(&cipher_key)
                }).to_string()
            }
            "unwrap" => {
                let cipher_hex = match &p.cipher_hex {
                    Some(h) => h,
                    None => {
                        let _ = sdf_close_session(session);
                        return err_json("unwrap 模式需提供 cipher_hex");
                    }
                };
                let cipher_bytes = match decode_hex(cipher_hex, "cipher_hex") {
                    Ok(b) => b,
                    Err(e) => { let _ = sdf_close_session(session); return err_json(&e); }
                };
                let mut key_handle = 0u32;
                let rc = sdf_import_key_with_kek(session, alg_id::SGD_SM4_ECB, kek_index, &cipher_bytes, &mut key_handle);
                let _ = sdf_close_session(session);
                if rc != 0 {
                    return err_json(&format!("SDF_ImportKeyWithKEK 失败 (错误码: {rc:#010x})"));
                }
                serde_json::json!({ "key_handle": key_handle }).to_string()
            }
            other => {
                let _ = sdf_close_session(session);
                err_json(&format!("action 无效：\"{other}\"，应为 \"wrap\" 或 \"unwrap\""))
            }
        }
    }
}

#[tool_handler]
impl ServerHandler for SdfMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "SDF Mock MCP Server — 提供符合 GM/T 0018-2023 的密码设备接口（SDF）能力。\
                 支持 SM2 密钥生成/签名/验签/加解密、SM3 哈希/HMAC、SM4 对称加解密/MAC、\
                 密钥管理（KEK 包裹/解包裹）。\
                 所有输入输出均使用 hex 编码字符串，结果以 JSON 返回。\
                 需要 config.toml 和 mock_keys.toml 配置文件，仅供开发测试使用。",
            )
    }
}

// ── 内部辅助：SM3 哈希计算（用于 external sign/verify 的预哈希）─────────────

/// 在给定 session 中计算 SM3 哈希，返回32字节结果
/// Reason: SDF External Sign/Verify 接口接收预哈希数据（e值），需要在调用前先哈希
fn compute_sm3_hash(session: u32, data: &[u8]) -> Result<Vec<u8>, String> {
    let rc = sdf_hash_init(session, alg_id::SGD_SM3, None, b"");
    if rc != 0 {
        return Err(format!("SM3 HashInit 失败 (错误码: {rc:#010x})"));
    }
    let rc = sdf_hash_update(session, data);
    if rc != 0 {
        return Err(format!("SM3 HashUpdate 失败 (错误码: {rc:#010x})"));
    }
    let mut hash = [0u8; 32];
    let rc = sdf_hash_final(session, &mut hash);
    if rc != 0 {
        return Err(format!("SM3 HashFinal 失败 (错误码: {rc:#010x})"));
    }
    Ok(hash.to_vec())
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string())
        )
        .init();

    info!("{} v{} starting", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    // 初始化 SDF 设备（全局单例，需 config.toml 存在）
    let rc = sdf_open_device();
    if rc != 0 {
        anyhow::bail!(
            "SDF_OpenDevice 失败 (错误码: {rc:#010x})。\
             请确认 config.toml 存在（OSR_HSM_CONFIG 环境变量 / /etc/osr/config.toml / CWD）"
        );
    }
    info!("SDF Mock 设备已开启");

    let mut router = axum::Router::new();

    match cli.mode {
        Mode::Rest => {
            // Rest 模式在 sdf-mock 中无实际路由，仅启动空服务
            info!("模式：REST only（无实际路由）");
        }
        Mode::Mcp | Mode::Both => {
            info!("模式：MCP（/mcp）");
            use rmcp::transport::streamable_http_server::{
                StreamableHttpServerConfig, StreamableHttpService,
                session::local::LocalSessionManager,
            };
            let config = StreamableHttpServerConfig::default()
                .with_stateful_mode(false);
            let mcp_svc: StreamableHttpService<SdfMcpServer, LocalSessionManager> =
                StreamableHttpService::new(
                    move || Ok(SdfMcpServer::new()),
                    Default::default(),
                    config,
                );
            router = router.nest_service("/mcp", mcp_svc);
        }
    }

    let addr = format!("0.0.0.0:{}", cli.port);
    info!("SDF MCP Server 启动，监听 {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
