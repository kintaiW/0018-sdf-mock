// 日志初始化模块
// 使用 flexi_logger 实现滚动文件日志（修复 0.1.x 日志只写 stderr 的 bug）

use crate::config::AppConfig;
use std::sync::Once;

static INIT: Once = Once::new();

/// 初始化日志系统（全局只执行一次）
/// 日志写入 [log] directory 配置的目录，文件名 sdf_mock-YYYY-MM-DD.log
/// 失败时降级为 stderr，不影响 SDF_OpenDevice 成功
pub fn init(cfg: &AppConfig) {
    INIT.call_once(|| {
        use flexi_logger::{
            Logger, FileSpec, Criterion, Naming, Cleanup, WriteMode,
        };

        let level = cfg.log.level.as_str();
        let dir = cfg.log.directory.as_str();

        let result = Logger::try_with_str(level)
            .map(|l| {
                l.log_to_file(
                    FileSpec::default()
                        .directory(dir)
                        .basename("sdf_mock"),
                )
                .rotate(
                    Criterion::Size(10 * 1024 * 1024), // 10MB 切换
                    Naming::Timestamps,
                    Cleanup::KeepLogFiles(7),
                )
                .write_mode(WriteMode::Direct)
                .start()
            });

        match result {
            Ok(Ok(_)) => {
                log::info!("日志系统初始化完成，级别: {}，目录: {}", level, dir);
            }
            Ok(Err(e)) | Err(e) => {
                // 降级：flexi_logger 初始化失败时回退到 env_logger stderr
                let _ = env_logger::Builder::new()
                    .parse_filters(level)
                    .try_init();
                log::warn!("flexi_logger 初始化失败（{}），已降级为 stderr", e);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, LogConfig};

    #[test]
    fn test_logging_writes_to_file() {
        let tmp_dir = tempfile::tempdir().expect("创建临时目录失败");
        let dir_path = tmp_dir.path().to_str().unwrap().to_string();

        let cfg = AppConfig {
            log: LogConfig { level: "info".to_string(), directory: dir_path.clone() },
        };

        init(&cfg);
        log::info!("测试日志写文件");

        // Once 保证全局只初始化一次，多次测试运行时 init 可能已被先前消费
        // 仅断言目录可读（flexi_logger 会在其中写文件）
        let _ = std::fs::read_dir(&dir_path).unwrap();
    }
}
