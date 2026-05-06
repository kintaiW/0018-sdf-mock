// GM/T 0018-2023 标准数据结构定义
// 所有结构体使用 #[repr(C)] 确保与 C 语言内存布局一致

/// 设备信息结构（GM/T 0018 §6.2.1）
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DEVICEINFO {
    /// 发行厂商名称（UTF-8，40字节）
    pub IssuerName: [u8; 40],
    /// 设备名称（UTF-8，16字节）
    pub DeviceName: [u8; 16],
    /// 设备序列号（UTF-8，16字节）
    pub DeviceSerial: [u8; 16],
    /// 设备版本号
    pub DeviceVersion: u32,
    /// 标准版本号
    pub StandardVersion: u32,
    /// 非对称算法能力（[签名类, 加解密类]）
    pub AsymAlgAbility: [u32; 2],
    /// 对称算法能力
    pub SymAlgAbility: u32,
    /// 哈希算法能力
    pub HashAlgAbility: u32,
    /// 支持的最大文件存储空间（字节）
    pub BufferSize: u32,
}

impl Default for DEVICEINFO {
    fn default() -> Self {
        Self {
            IssuerName: [0u8; 40],
            DeviceName: [0u8; 16],
            DeviceSerial: [0u8; 16],
            DeviceVersion: 0x00020000,   // v2.0 (0.2.0)
            StandardVersion: 0x00020000, // GM/T 0018-2023
            AsymAlgAbility: [0x00000400, 0x00000400], // SM2
            SymAlgAbility: 0x00000400,   // SM4
            HashAlgAbility: 0x00000400,  // SM3
            BufferSize: 64 * 1024,       // 64KB
        }
    }
}

/// ECC 公钥（GM/T 0018 §6.2.2.4）
/// bits 指定密钥长度（SM2 = 256）
/// x, y 为 64 字节右对齐大端坐标（高位补零）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCrefPublicKey {
    pub bits: u32,
    pub x: [u8; 64],
    pub y: [u8; 64],
}

impl Default for ECCrefPublicKey {
    fn default() -> Self {
        Self { bits: 256, x: [0u8; 64], y: [0u8; 64] }
    }
}

/// ECC 私钥（GM/T 0018 §6.2.2.4）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCrefPrivateKey {
    pub bits: u32,
    pub K: [u8; 64],
}

impl Default for ECCrefPrivateKey {
    fn default() -> Self {
        Self { bits: 256, K: [0u8; 64] }
    }
}

/// ECC 密文结构（GM/T 0018 §6.2.2.5）
/// 对应 SM2 加密输出：C1（点坐标）‖ C3（SM3哈希）‖ C2（密文）
/// BREAKING(0.2.0): C 数组长度由 136 改为 128，与真实 SDK ABI 对齐
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ECCCipher {
    /// C1.x（64字节，右对齐大端）
    pub x: [u8; 64],
    /// C1.y（64字节，右对齐大端）
    pub y: [u8; 64],
    /// C3 = SM3(x2‖M‖y2)（32字节）
    pub M: [u8; 32],
    /// C2 密文数据长度（字节）
    pub L: u32,
    /// C2 密文数据（最大128字节）
    pub C: [u8; 128],
}

impl Default for ECCCipher {
    fn default() -> Self {
        Self { x: [0u8; 64], y: [0u8; 64], M: [0u8; 32], L: 0, C: [0u8; 128] }
    }
}

/// ECC 签名结构（GM/T 0018 §6.2.2.5）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCSignature {
    pub r: [u8; 64],
    pub s: [u8; 64],
}

impl Default for ECCSignature {
    fn default() -> Self {
        Self { r: [0u8; 64], s: [0u8; 64] }
    }
}

/// SM2 密钥交换数据（GM/T 0018 §6.2.2.6）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCrefExchangeData {
    /// 临时公钥
    pub tmpPubKey: ECCrefPublicKey,
    /// Z 值（SM3 摘要）
    pub z: [u8; 32],
}

/// RSA 公钥结构（GM/T 0018 §6.2.2.3，对齐真实 SDK）
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RSArefPublicKey {
    pub bits: u32,
    /// 模数 n（256字节，大端右对齐）
    pub m: [u8; 256],
    /// 公钥指数 e（256字节，大端右对齐）
    pub e: [u8; 256],
}

impl Default for RSArefPublicKey {
    fn default() -> Self {
        Self { bits: 2048, m: [0u8; 256], e: [0u8; 256] }
    }
}

/// RSA 私钥结构（GM/T 0018 §6.2.2.3，对齐真实 SDK）
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RSArefPrivateKey {
    pub bits: u32,
    /// 模数 n
    pub m: [u8; 256],
    /// 公钥指数 e
    pub e: [u8; 256],
    /// 私钥指数 d
    pub d: [u8; 256],
    /// 素数 p, q（各128字节）
    pub prime: [[u8; 128]; 2],
    /// p, q 对应的指数（各128字节）
    pub pexp: [[u8; 128]; 2],
    /// 系数 CRT coef（128字节）
    pub coef: [u8; 128],
}

impl Default for RSArefPrivateKey {
    fn default() -> Self {
        Self {
            bits: 2048,
            m: [0u8; 256],
            e: [0u8; 256],
            d: [0u8; 256],
            prime: [[0u8; 128]; 2],
            pexp: [[0u8; 128]; 2],
            coef: [0u8; 128],
        }
    }
}

/// 算法标识常量（GM/T 0018 §5.2，数值严格对齐 sdf-sdk/sdf.h）
pub mod alg_id {
    // 算法基础标识
    pub const SGD_SM1: u32 = 0x00000100;
    pub const SGD_SM4: u32 = 0x00000400;
    pub const SGD_RSA: u32 = 65536;        // 0x00010000
    pub const SGD_SM2: u32 = 0x00020100;   // SM2 通用标识（sign/verify/keygen）
    pub const SGD_SM9: u32 = 262400;       // 0x00040100

    // 加密模式
    pub const MODE_ECB: u32 = 1;
    pub const MODE_CBC: u32 = 2;
    pub const MODE_CFB: u32 = 4;
    pub const MODE_OFB: u32 = 8;
    pub const MODE_MAC: u32 = 16;
    pub const MODE_CTR: u32 = 32;
    pub const MODE_XTS: u32 = 64;
    pub const MODE_GCM: u32 = 128;

    // SM1 模式
    pub const SGD_SM1_ECB: u32 = SGD_SM1 | MODE_ECB; // 0x00000101
    pub const SGD_SM1_CBC: u32 = SGD_SM1 | MODE_CBC; // 0x00000102
    pub const SGD_SM1_CFB: u32 = SGD_SM1 | MODE_CFB; // 0x00000104
    pub const SGD_SM1_OFB: u32 = SGD_SM1 | MODE_OFB; // 0x00000108
    pub const SGD_SM1_MAC: u32 = SGD_SM1 | MODE_MAC; // 0x00000110

    // SM4 模式
    pub const SGD_SM4_ECB: u32 = SGD_SM4 | MODE_ECB; // 0x00000401
    pub const SGD_SM4_CBC: u32 = SGD_SM4 | MODE_CBC; // 0x00000402
    pub const SGD_SM4_CFB: u32 = SGD_SM4 | MODE_CFB; // 0x00000404
    pub const SGD_SM4_OFB: u32 = SGD_SM4 | MODE_OFB; // 0x00000408
    pub const SGD_SM4_MAC: u32 = SGD_SM4 | MODE_MAC; // 0x00000410
    pub const SGD_SM4_CTR: u32 = SGD_SM4 | MODE_CTR; // 0x00000420
    pub const SGD_SM4_XTS: u32 = SGD_SM4 | MODE_XTS; // 0x00000440
    // Reason: sdfc 标准 GCM=0x00000480，CCM 在真实 SDK 中沿用 XTS 位，此处保留别名
    pub const SGD_SM4_GCM: u32 = SGD_SM4 | MODE_GCM; // 0x00000480
    pub const SGD_SM4_CCM: u32 = SGD_SM4_XTS;         // 兼容旧代码

    // SM2 子类型
    pub const SGD_SM2_1: u32 = 0x00020200; // SM2 签名
    pub const SGD_SM2_2: u32 = 0x00020400; // SM2 密钥交换
    pub const SGD_SM2_3: u32 = 0x00020800; // SM2 加密

    // 哈希算法标识
    pub const SGD_SM3: u32 = 0x00000001;
    pub const SGD_SHA1: u32 = 0x00000002;
    pub const SGD_SHA256: u32 = 0x00000004;
    pub const SGD_SHA512: u32 = 0x00000008;
    pub const SGD_SHA384: u32 = 0x00000010;
    pub const SGD_SHA224: u32 = 0x00000020;
}
