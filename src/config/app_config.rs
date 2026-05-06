// config.toml 解析（仅日志段生效）
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct LogConfig {
    /// 日志级别：debug, info, warn, error, off
    pub level: String,
    /// 日志输出目录
    pub directory: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            directory: "./".to_string(),
        }
    }
}

/// config.toml 的顶层结构。
/// connection_pool / platform / tls 段被静默接受（用 toml::Value），
/// 便于把真实 SDK 的 config.toml 直接用于 Mock 开发环境而不报错。
#[derive(Debug, Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    pub log: LogConfig,
    /// 兼容真实 SDK config.toml，不解析，仅接受不报错
    #[serde(default)]
    pub connection_pool: Option<toml::Value>,
    #[serde(default)]
    pub platform: Option<toml::Value>,
    #[serde(default)]
    pub tls: Option<toml::Value>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub log: LogConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self { log: LogConfig::default() }
    }
}

impl AppConfig {
    /// 从文件路径加载配置。
    /// 文件不存在或解析失败时返回 Err（含描述信息），供调用方决定是否中止。
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Err(format!("config.toml 不存在: {}", path.display()));
        }
        let content = fs::read_to_string(path)
            .map_err(|e| format!("读取 config.toml 失败: {}", e))?;
        let raw: RawConfig = toml::from_str(&content)
            .map_err(|e| format!("解析 config.toml 失败: {}", e))?;
        Ok(Self { log: raw.log })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_load_log_config() {
        let f = make_toml(r#"
[log]
level = "debug"
directory = "/tmp"
"#);
        let cfg = AppConfig::load(f.path()).unwrap();
        assert_eq!(cfg.log.level, "debug");
        assert_eq!(cfg.log.directory, "/tmp");
    }

    #[test]
    fn test_missing_file_returns_err() {
        let result = AppConfig::load(Path::new("/nonexistent/path/config.toml"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("config.toml 不存在"));
    }

    /// 验证真实 SDK 的 config.toml 格式（含 connection_pool/platform/tls）被静默接受
    #[test]
    fn test_real_sdk_config_compatible() {
        let f = make_toml(r#"
[connection_pool]
max_connections = 10
timeout = 30

[platform]
address = "www.sdfserver_rsa.com"
port = 9010

[tls]
ca_cert_path = "./client_ca_rsa.cert.pem"

[log]
level = "info"
directory = "/tmp"
"#);
        let cfg = AppConfig::load(f.path()).unwrap();
        assert_eq!(cfg.log.level, "info");
    }
}

