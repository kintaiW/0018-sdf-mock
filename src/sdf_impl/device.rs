// 设备管理接口实现
// SDF_OpenDevice / SDF_CloseDevice / SDF_OpenSession / SDF_CloseSession / SDF_GetDeviceInfo / SDF_Test

use std::sync::{Mutex, OnceLock};
use crate::config::{AppConfig, MockConfig};
use crate::error_code::*;
use crate::key_mgr::DeviceContext;
use crate::types::DEVICEINFO;
use crate::logging;
use std::path::Path;

/// 全局设备上下文（单例）
/// Reason: SDF 标准中设备是全局唯一资源，用 OnceLock+Mutex 保证初始化一次且线程安全
static DEVICE_CTX: OnceLock<Mutex<Option<DeviceContext>>> = OnceLock::new();

fn device_lock() -> &'static Mutex<Option<DeviceContext>> {
    DEVICE_CTX.get_or_init(|| Mutex::new(None))
}

/// 按优先级查找 config.toml（优先级从高到低）：
///   1. 环境变量 OSR_HSM_CONFIG 指定的绝对路径
///   2. 固定路径 /etc/osr/config.toml
///   3. 当前工作目录（CWD）下的 config.toml
///
/// Reason: 动态库被 JNI 或其他宿主进程加载时，无法预知 .so 位置，
/// 也不能依赖可执行文件目录；通过环境变量和固定路径提供稳定的配置入口。
///
/// 注意：若 OSR_HSM_CONFIG 已设置但文件不存在，直接返回 None 而不继续查找，
/// 避免配置路径写错时静默降级到低优先级配置，导致行为难以排查。
fn find_config_toml() -> Option<std::path::PathBuf> {
    // 1. 环境变量 OSR_HSM_CONFIG（最高优先级）
    if let Ok(env_path) = std::env::var("OSR_HSM_CONFIG") {
        let p = std::path::PathBuf::from(&env_path);
        // Reason: 环境变量已明确指定路径，若文件不存在说明配置有误，
        // 不应静默降级到低优先级，直接返回 None 让调用方报错
        if p.exists() {
            log::info!("find_config_toml: 使用环境变量 OSR_HSM_CONFIG={}", env_path);
            return Some(p);
        }
        log::warn!("find_config_toml: OSR_HSM_CONFIG={} 文件不存在，不继续查找", env_path);
        return None;
    }

    // 2. 系统固定路径 /etc/osr/config.toml
    let system_path = Path::new("/etc/osr/config.toml");
    if system_path.exists() {
        log::info!("find_config_toml: 使用系统路径 {}", system_path.display());
        return Some(system_path.to_path_buf());
    }

    // 3. 当前工作目录（CWD）
    // Reason: CWD 是启动进程时 shell 的当前目录，适合本地开发调试场景
    let cwd_path = Path::new("config.toml").to_path_buf();
    if cwd_path.exists() {
        log::info!("find_config_toml: 使用 CWD 下的 config.toml");
        return Some(cwd_path);
    }

    None
}

/// SDF_OpenDevice — 打开设备（初始化 Mock 上下文）
/// 返回：SDR_OK 或错误码
pub fn sdf_open_device() -> i32 {
    // 1. 加载 app config（日志配置）；config.toml 不存在则报错并终止
    let config_path = match find_config_toml() {
        Some(p) => p,
        None => {
            eprintln!("SDF_OpenDevice 失败: 找不到 config.toml（查找顺序：OSR_HSM_CONFIG 环境变量 → /etc/osr/config.toml → CWD）");
            return SDR_CONFIGERR;
        }
    };
    let app_cfg = match AppConfig::load(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("SDF_OpenDevice 失败: {}", e);
            return SDR_CONFIGERR;
        }
    };
    logging::init(&app_cfg);

    log::info!("SDF_OpenDevice: 初始化 Mock 设备");

    // 2. 加载 mock 密钥配置
    let mock_cfg = MockConfig::load_from_env_or_default();

    // 3. 初始化全局设备上下文
    let mut guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return SDR_UNKNOWERR,
    };
    if let Some(ctx) = guard.as_mut() {
        // Reason: 引用计数+1，支持 test_interface_list 内部嵌套 OpenDevice 而不破坏外层上下文
        ctx.open_count += 1;
        log::warn!("SDF_OpenDevice: 设备已打开，引用计数+1 = {}", ctx.open_count);
        return SDR_OK;
    }
    *guard = Some(DeviceContext::new(mock_cfg));
    log::info!("SDF_OpenDevice: Mock 设备打开成功");
    SDR_OK
}

/// SDF_CloseDevice — 关闭设备（引用计数，归零时才真正销毁）
/// Reason: test_interface_list 内部会多次调用 OpenDevice/CloseDevice，
/// 若直接销毁会破坏外层调用方持有的 hSessionHandle；
/// 用引用计数保证只有所有 OpenDevice 都配对了 CloseDevice 后才真正销毁
pub fn sdf_close_device() -> i32 {
    log::info!("SDF_CloseDevice");
    let mut guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return SDR_UNKNOWERR,
    };
    let ctx = match guard.as_mut() {
        Some(c) => c,
        None => {
            log::warn!("SDF_CloseDevice: 设备未打开");
            return SDR_OPENDEVICE;
        }
    };
    // Reason: 引用计数-1；只有计数归零时才真正销毁设备上下文
    ctx.open_count = ctx.open_count.saturating_sub(1);
    if ctx.open_count > 0 {
        log::warn!("SDF_CloseDevice: 引用计数-1 = {}，设备继续保持打开", ctx.open_count);
        return SDR_OK;
    }
    *guard = None;
    SDR_OK
}

/// SDF_OpenSession — 打开会话
/// 返回会话句柄（通过 out_handle 输出），成功返回 SDR_OK
pub fn sdf_open_session(out_handle: &mut u32) -> i32 {
    let mut guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return SDR_UNKNOWERR,
    };
    let ctx = match guard.as_mut() {
        Some(c) => c,
        None => {
            log::error!("SDF_OpenSession: 设备未打开");
            return SDR_OPENDEVICE;
        }
    };
    let handle = ctx.open_session();
    *out_handle = handle;
    log::debug!("SDF_OpenSession: handle=0x{:08X}", handle);
    SDR_OK
}

/// SDF_CloseSession — 关闭会话
pub fn sdf_close_session(session_handle: u32) -> i32 {
    let mut guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return SDR_UNKNOWERR,
    };
    let ctx = match guard.as_mut() {
        Some(c) => c,
        None => return SDR_OPENDEVICE,
    };
    if ctx.close_session(session_handle) {
        log::debug!("SDF_CloseSession: handle=0x{:08X}", session_handle);
        SDR_OK
    } else {
        log::warn!("SDF_CloseSession: 无效会话句柄 0x{:08X}", session_handle);
        SDR_INARGERR
    }
}

/// SDF_GetDeviceInfo — 获取设备信息
pub fn sdf_get_device_info(session_handle: u32, info: &mut DEVICEINFO) -> i32 {
    let guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return SDR_UNKNOWERR,
    };
    let ctx = match guard.as_ref() {
        Some(c) => c,
        None => return SDR_OPENDEVICE,
    };
    if ctx.get_session(session_handle).is_none() {
        return SDR_INARGERR;
    }
    let cfg = &ctx.mock_cfg.device;
    // 填充设备信息
    *info = DEVICEINFO::default();
    let mfr = cfg.manufacturer.as_bytes();
    let copy_len = mfr.len().min(40);
    info.IssuerName[..copy_len].copy_from_slice(&mfr[..copy_len]);

    let name = cfg.device_name.as_bytes();
    let copy_len = name.len().min(16);
    info.DeviceName[..copy_len].copy_from_slice(&name[..copy_len]);

    let serial = cfg.device_serial.as_bytes();
    let copy_len = serial.len().min(16);
    info.DeviceSerial[..copy_len].copy_from_slice(&serial[..copy_len]);

    log::debug!("SDF_GetDeviceInfo: 返回设备信息");
    SDR_OK
}

/// 辅助：在已持有 device_lock 的情况下，对会话执行操作
/// 供其他模块调用，避免多次加锁
pub fn with_session<F, R>(session_handle: u32, f: F) -> R
where
    F: FnOnce(Result<&mut crate::key_mgr::SessionContext, i32>) -> R,
{
    let mut guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return f(Err(SDR_UNKNOWERR)),
    };
    let ctx = match guard.as_mut() {
        Some(c) => c,
        None => return f(Err(SDR_OPENDEVICE)),
    };
    match ctx.get_session_mut(session_handle) {
        Some(s) => f(Ok(s)),
        None => f(Err(SDR_INARGERR)),
    }
}

/// SDF_Test — 设备内部一致性自检
/// 实现：对输入数据计算 SM3 哈希并写入输出缓冲，用于验证 Mock 内部算法一致性
pub fn sdf_test(session_handle: u32, in_data: &[u8], out_data: &mut Vec<u8>) -> i32 {
    with_session(session_handle, |res| {
        if let Err(e) = res { return e; }
        let digest = libsmx::sm3::Sm3Hasher::digest(in_data);
        *out_data = digest.to_vec();
        log::debug!("SDF_Test: in_len={}, out_len={}", in_data.len(), out_data.len());
        SDR_OK
    })
}


mod tests {
    use super::*;
    use std::sync::Mutex;

    // Reason: 设备上下文是全局单例，多个测试并发运行时会相互干扰，需串行化
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn cleanup() {
        if let Ok(mut g) = device_lock().lock() {
            *g = None;
        }
    }

    #[test]
    fn test_open_close_device() {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup();
        assert_eq!(sdf_open_device(), SDR_OK);
        assert_eq!(sdf_close_device(), SDR_OK);
        cleanup();
    }

    #[test]
    fn test_open_session() {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup();
        assert_eq!(sdf_open_device(), SDR_OK);
        let mut handle = 0u32;
        assert_eq!(sdf_open_session(&mut handle), SDR_OK);
        assert_ne!(handle, 0);
        assert_eq!(sdf_close_session(handle), SDR_OK);
        assert_eq!(sdf_close_device(), SDR_OK);
        cleanup();
    }

    #[test]
    fn test_invalid_session() {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup();
        assert_eq!(sdf_open_device(), SDR_OK);
        assert_eq!(sdf_close_session(0xDEADBEEF), SDR_INARGERR);
        assert_eq!(sdf_close_device(), SDR_OK);
        cleanup();
    }

    /// config.toml 不存在时，AppConfig::load 返回 Err，sdf_open_device 返回 SDR_CONFIGERR
    #[test]
    fn test_open_device_missing_config() {
        // 直接测试 AppConfig::load 的错误路径，不影响全局设备状态
        let result = AppConfig::load(std::path::Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("config.toml 不存在"), "错误信息: {}", msg);
    }
}
