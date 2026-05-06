// GM/T 0018-2023 标准错误码定义
// 数值严格对齐真实 SDK（sdf-sdk/sdf.h §SDR_* 定义）
// BREAKING(0.2.0): SDR_CONFIGERR 数值从 0x01000101 改为 SDR_BASE+80
//                  删除 SDR_PRNGERR/KEYINDEX/INVALIDHANDLE/PARAMERR/MEMERR（真实 SDK 不含这些码）

const SDR_BASE: u32 = 16_777_216; // 0x01000000

/// 操作成功
pub const SDR_OK: i32 = 0x00000000;

/// 设备内部未知错误
pub const SDR_UNKNOWERR: i32 = (SDR_BASE + 1) as i32;
/// 通用错误（与 SDR_UNKNOWERR 数值相同）
pub const SDR_GENERAL_ERROR: i32 = SDR_UNKNOWERR;
/// 设备不支持该功能
pub const SDR_NOTSUPPORT: i32 = (SDR_BASE + 2) as i32;
/// 通讯失败
pub const SDR_COMMFAIL: i32 = (SDR_BASE + 3) as i32;
/// 硬件故障
pub const SDR_HARDFAIL: i32 = (SDR_BASE + 4) as i32;
/// 打开设备失败
pub const SDR_OPENDEVICE: i32 = (SDR_BASE + 5) as i32;
/// 打开密码设备会话句柄失败
pub const SDR_OPENSESSION: i32 = (SDR_BASE + 6) as i32;
/// 无私钥使用权限
pub const SDR_PARDENY: i32 = (SDR_BASE + 7) as i32;
/// 密钥不存在
pub const SDR_KEYNOTEXIST: i32 = (SDR_BASE + 8) as i32;
/// 不支持的算法
pub const SDR_ALGNOTSUPPORT: i32 = (SDR_BASE + 9) as i32;
/// 不支持的算法模式
pub const SDR_ALGMODNOTSUPPORT: i32 = (SDR_BASE + 10) as i32;
/// 公钥运算失败
pub const SDR_PKOPERR: i32 = (SDR_BASE + 11) as i32;
/// 私钥运算失败
pub const SDR_SKOPERR: i32 = (SDR_BASE + 12) as i32;
/// 签名失败
pub const SDR_SIGNERR: i32 = (SDR_BASE + 13) as i32;
/// 验签失败
pub const SDR_VERIFYERR: i32 = (SDR_BASE + 14) as i32;
/// 对称运算失败
pub const SDR_SYMOPERR: i32 = (SDR_BASE + 15) as i32;
/// 步骤错误（未先 Init 即 Update/Final 等）
pub const SDR_STEPERR: i32 = (SDR_BASE + 16) as i32;
/// 文件长度超出限制
pub const SDR_FILESIZEERR: i32 = (SDR_BASE + 17) as i32;
/// 文件不存在
pub const SDR_FILENOEXIST: i32 = (SDR_BASE + 18) as i32;
/// 文件偏移量错误
pub const SDR_FILEOFSERR: i32 = (SDR_BASE + 19) as i32;
/// SDR_FILEOFSET 是 0.1.x 旧名，保留别名以免调用方编译报错
#[allow(non_upper_case_globals)]
pub const SDR_FILEOFSET: i32 = SDR_FILEOFSERR;
/// 密钥类型错误
pub const SDR_KEYTYPEERR: i32 = (SDR_BASE + 20) as i32;
/// 密钥错误
pub const SDR_KEYERR: i32 = (SDR_BASE + 21) as i32;
/// ECC 加密数据错误
pub const SDR_ENCDATAERR: i32 = (SDR_BASE + 22) as i32;
/// 随机数产生失败
pub const SDR_RANDERR: i32 = (SDR_BASE + 23) as i32;
/// 私钥运算错误
pub const SDR_PRKRERR: i32 = (SDR_BASE + 24) as i32;
/// MAC 运算错误
pub const SDR_MACERR: i32 = (SDR_BASE + 25) as i32;
/// 文件已存在
pub const SDR_FILEEXISTS: i32 = (SDR_BASE + 26) as i32;
/// 文件写错误
pub const SDR_FILEWERR: i32 = (SDR_BASE + 27) as i32;
/// 缓冲区不足
pub const SDR_NOBUFFER: i32 = (SDR_BASE + 28) as i32;
/// 输入参数错误（指针为空、长度非法等）
pub const SDR_INARGERR: i32 = (SDR_BASE + 29) as i32;
/// 输出参数错误
pub const SDR_OUTARGERR: i32 = (SDR_BASE + 30) as i32;
/// 配置文件错误（BREAKING: 0.1.x 为 0x01000101，0.2.0 改为 SDR_BASE+80）
pub const SDR_CONFIGERR: i32 = (SDR_BASE + 80) as i32;
/// 序列化失败
pub const SDR_MARSHALERR: i32 = (SDR_BASE + 81) as i32;
/// 反序列化失败
pub const SDR_UNMARSHALERR: i32 = (SDR_BASE + 82) as i32;
