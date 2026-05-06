// mock_keys.toml 解析 — Mock 专属密钥配置
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// 设备信息配置
#[derive(Debug, Deserialize, Clone)]
pub struct DeviceConfig {
    #[serde(default = "default_manufacturer")]
    pub manufacturer: String,
    #[serde(default = "default_device_name")]
    pub device_name: String,
    #[serde(default = "default_device_serial")]
    pub device_serial: String,
    #[serde(default = "default_firmware_version")]
    pub firmware_version: String,
}

fn default_manufacturer() -> String { "MockDevice".to_string() }
fn default_device_name() -> String { "SDF_MOCK_V1".to_string() }
fn default_device_serial() -> String { "MOCK20250101".to_string() }
fn default_firmware_version() -> String { "1.0.0".to_string() }

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            manufacturer: default_manufacturer(),
            device_name: default_device_name(),
            device_serial: default_device_serial(),
            firmware_version: default_firmware_version(),
        }
    }
}

/// 设备根密钥（SM4，16字节）
#[derive(Debug, Deserialize, Clone)]
pub struct RootKeyConfig {
    /// 十六进制字符串，32字符
    pub value: String,
}

/// KEK（密钥加密密钥，SM4）
#[derive(Debug, Deserialize, Clone)]
pub struct KekKeyConfig {
    pub index: u32,
    #[serde(default = "default_sm4")]
    pub algorithm: String,
    pub value: String,
}
fn default_sm4() -> String { "SM4".to_string() }

/// SM2 签名密钥对
#[derive(Debug, Deserialize, Clone)]
pub struct SignKeyConfig {
    pub index: u32,
    /// 私钥：十六进制，64字符（32字节）
    pub private_key: String,
    /// 公钥：十六进制，130字符（65字节，04||x||y）
    pub public_key: String,
}

/// SM2 加密密钥对
#[derive(Debug, Deserialize, Clone)]
pub struct EncKeyConfig {
    pub index: u32,
    pub private_key: String,
    pub public_key: String,
}

/// RSA 签名密钥（PKCS#8 PEM 格式）
#[derive(Debug, Deserialize, Clone)]
pub struct RsaSignKeyConfig {
    pub index: u32,
    pub private_key_pem: String,
}

/// RSA 加密密钥（PKCS#8 PEM 格式）
#[derive(Debug, Deserialize, Clone)]
pub struct RsaEncKeyConfig {
    pub index: u32,
    pub private_key_pem: String,
}

/// mock_keys.toml 顶层结构
#[derive(Debug, Deserialize, Clone)]
pub struct MockConfigRaw {
    #[serde(default)]
    pub device: DeviceConfig,
    pub root_key: Option<RootKeyConfig>,
    #[serde(default)]
    pub kek_keys: Vec<KekKeyConfig>,
    #[serde(default)]
    pub sign_keys: Vec<SignKeyConfig>,
    #[serde(default)]
    pub enc_keys: Vec<EncKeyConfig>,
    #[serde(default)]
    pub rsa_sign_keys: Vec<RsaSignKeyConfig>,
    #[serde(default)]
    pub rsa_enc_keys: Vec<RsaEncKeyConfig>,
}

/// 解码后的密钥数据（已转为字节数组）
#[derive(Debug, Clone)]
pub struct KekKey {
    pub index: u32,
    pub key: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct SignKey {
    pub index: u32,
    pub private_key: [u8; 32],
    /// 65字节公钥（04||x||y）
    pub public_key: [u8; 65],
}

#[derive(Debug, Clone)]
pub struct EncKey {
    pub index: u32,
    pub private_key: [u8; 32],
    pub public_key: [u8; 65],
}

#[derive(Debug, Clone)]
pub struct RsaKeyEntry {
    pub index: u32,
    /// PKCS#8 PEM 私钥原文（由 key_store 解析为 RsaPrivateKey）
    pub private_key_pem: String,
}

#[derive(Debug, Clone)]
pub struct MockConfig {
    pub device: DeviceConfig,
    pub root_key: [u8; 16],
    pub kek_keys: Vec<KekKey>,
    pub sign_keys: Vec<SignKey>,
    pub enc_keys: Vec<EncKey>,
    pub rsa_sign_keys: Vec<RsaKeyEntry>,
    pub rsa_enc_keys: Vec<RsaKeyEntry>,
}

#[derive(Debug)]
pub enum ConfigError {
    IoError(String),
    ParseError(String),
    ValidationError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(s) => write!(f, "IO错误: {}", s),
            Self::ParseError(s) => write!(f, "解析错误: {}", s),
            Self::ValidationError(s) => write!(f, "校验错误: {}", s),
        }
    }
}

fn decode_hex_16(s: &str, field: &str) -> Result<[u8; 16], ConfigError> {
    let bytes = hex::decode(s).map_err(|e| {
        ConfigError::ValidationError(format!("{} 十六进制解码失败: {}", field, e))
    })?;
    if bytes.len() != 16 {
        return Err(ConfigError::ValidationError(format!(
            "{} 长度必须为16字节，实际{}字节", field, bytes.len()
        )));
    }
    Ok(bytes.try_into().unwrap())
}

fn decode_hex_32(s: &str, field: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = hex::decode(s).map_err(|e| {
        ConfigError::ValidationError(format!("{} 十六进制解码失败: {}", field, e))
    })?;
    if bytes.len() != 32 {
        return Err(ConfigError::ValidationError(format!(
            "{} 长度必须为32字节，实际{}字节", field, bytes.len()
        )));
    }
    Ok(bytes.try_into().unwrap())
}

fn decode_hex_65(s: &str, field: &str) -> Result<[u8; 65], ConfigError> {
    let bytes = hex::decode(s).map_err(|e| {
        ConfigError::ValidationError(format!("{} 十六进制解码失败: {}", field, e))
    })?;
    if bytes.len() != 65 {
        return Err(ConfigError::ValidationError(format!(
            "{} 长度必须为65字节，实际{}字节", field, bytes.len()
        )));
    }
    if bytes[0] != 0x04 {
        return Err(ConfigError::ValidationError(format!(
            "{} 公钥必须以04开头（非压缩格式）", field
        )));
    }
    Ok(bytes.try_into().unwrap())
}

impl MockConfig {
    /// 从文件加载并校验 mock_keys.toml
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::IoError(format!("文件不存在: {}", path.display())));
        }
        let content = fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(e.to_string()))?;
        let raw: MockConfigRaw = toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;

        // 解析根密钥
        let root_key = match &raw.root_key {
            Some(rk) => decode_hex_16(&rk.value, "root_key.value")?,
            None => [0u8; 16], // 无根密钥时使用全零（Mock 场景允许）
        };

        // 解析 KEK 密钥
        let mut kek_keys = Vec::new();
        for k in &raw.kek_keys {
            let key = decode_hex_16(&k.value, &format!("kek_keys[{}].value", k.index))?;
            kek_keys.push(KekKey { index: k.index, key });
        }

        // 解析签名密钥对
        let mut sign_keys = Vec::new();
        for k in &raw.sign_keys {
            let private_key = decode_hex_32(&k.private_key, &format!("sign_keys[{}].private_key", k.index))?;
            let public_key = decode_hex_65(&k.public_key, &format!("sign_keys[{}].public_key", k.index))?;
            sign_keys.push(SignKey { index: k.index, private_key, public_key });
        }

        // 解析加密密钥对
        let mut enc_keys = Vec::new();
        for k in &raw.enc_keys {
            let private_key = decode_hex_32(&k.private_key, &format!("enc_keys[{}].private_key", k.index))?;
            let public_key = decode_hex_65(&k.public_key, &format!("enc_keys[{}].public_key", k.index))?;
            enc_keys.push(EncKey { index: k.index, private_key, public_key });
        }

        Ok(MockConfig { device: raw.device, root_key, kek_keys, sign_keys, enc_keys,
            rsa_sign_keys: raw.rsa_sign_keys.iter().map(|k| RsaKeyEntry {
                index: k.index, private_key_pem: k.private_key_pem.clone(),
            }).collect(),
            rsa_enc_keys: raw.rsa_enc_keys.iter().map(|k| RsaKeyEntry {
                index: k.index, private_key_pem: k.private_key_pem.clone(),
            }).collect(),
        })
    }

    /// 尝试多个路径加载配置，全部失败时使用空配置（Mock场景下可接受）
    /// 搜索顺序：
    ///   1. 环境变量 SDF_MOCK_CONFIG_DIR 指定的目录
    ///   2. 可执行文件所在目录（current_exe 能正常解析时）
    ///   3. 当前工作目录
    pub fn load_from_env_or_default() -> Self {
        // 1. 环境变量指定目录
        if let Ok(dir) = std::env::var("SDF_MOCK_CONFIG_DIR") {
            let p = Path::new(&dir).join("mock_keys.toml");
            if let Ok(cfg) = Self::load(&p) {
                log::info!("从环境变量路径加载 mock_keys.toml: {}", p.display());
                return cfg;
            }
        }
        // 2. 可执行文件所在目录
        // Reason: 动态库被 C 程序加载时，CWD 是调用方的工作目录，不一定是配置文件所在位置；
        // 而可执行文件与配置文件通常放在同一目录，此路径更可靠。
        if let Ok(exe) = std::env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                let p = exe_dir.join("mock_keys.toml");
                if let Ok(cfg) = Self::load(&p) {
                    log::info!("从可执行文件目录加载 mock_keys.toml: {}", p.display());
                    return cfg;
                }
            }
        }
        // 3. 当前工作目录
        if let Ok(cwd) = std::env::current_dir() {
            let p = cwd.join("mock_keys.toml");
            if let Ok(cfg) = Self::load(&p) {
                log::info!("从当前目录加载 mock_keys.toml: {}", p.display());
                return cfg;
            }
        }
        // 4. 返回空配置（无预设密钥，仅动态生成）
        log::warn!("未找到 mock_keys.toml，使用空密钥配置（所有密钥需运行时生成）");
        MockConfig {
            device: DeviceConfig::default(),
            root_key: [0u8; 16],
            kek_keys: vec![],
            sign_keys: vec![],
            enc_keys: vec![],
            rsa_sign_keys: vec![],
            rsa_enc_keys: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::fs;

    fn write_toml(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mock_keys.toml");
        fs::write(&p, content).unwrap();
        (dir, p)
    }

    #[test]
    fn test_load_valid_config() {
        let content = r#"
[device]
manufacturer = "TestCo"
device_name = "TEST_DEV"
device_serial = "SN001"
firmware_version = "2.0.0"

[root_key]
value = "0123456789ABCDEF0123456789ABCDEF"

[[kek_keys]]
index = 1
algorithm = "SM4"
value = "FEDCBA9876543210FEDCBA9876543210"

[[sign_keys]]
index = 1
private_key = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
public_key = "04BB34D0B28F49ABAFAD1AEE5E44B489B730B8B2A2CB6CC068C8B9DABE7C1F0D0809DBAAD5D932A64D5FF9C5C4B5E3B2CE1DB05E3F7B2F16EAEF87AAA6E9B07C0A"
"#;
        let (_dir, path) = write_toml(content);
        let cfg = MockConfig::load(&path).expect("应成功加载");
        assert_eq!(cfg.device.manufacturer, "TestCo");
        assert_eq!(cfg.kek_keys.len(), 1);
        assert_eq!(cfg.kek_keys[0].index, 1);
        assert_eq!(cfg.sign_keys.len(), 1);
    }

    #[test]
    fn test_invalid_key_length() {
        let content = r#"
[root_key]
value = "AABBCC"
"#;
        let (_dir, path) = write_toml(content);
        let result = MockConfig::load(&path);
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_missing_file() {
        let result = MockConfig::load(Path::new("/nonexistent/mock_keys.toml"));
        assert!(matches!(result, Err(ConfigError::IoError(_))));
    }
}
