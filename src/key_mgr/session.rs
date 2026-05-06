// 设备/会话上下文管理
// 每个 SDF_OpenDevice 创建一个 DeviceContext
// 每个 SDF_OpenSession 创建一个 SessionContext

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::key_mgr::KeyStore;
use crate::config::MockConfig;
use crate::crypto::sm3_ops::Sm3State;

static SESSION_HANDLE_COUNTER: AtomicU32 = AtomicU32::new(1);

/// 哈希运算上下文（每次 HashInit 创建一个）
#[derive(Debug, Clone)]
pub struct HashCtx {
    pub state: Sm3State,
    pub alg_id: u32,
    /// SM2 Hash with Z 时存储公钥（用于 SM3withSM2）
    pub pub_key: Option<[u8; 65]>,
}

/// HMAC 运算上下文
#[derive(Debug, Clone)]
pub struct HmacCtx {
    pub key_handle: u32,
    pub buffer: Vec<u8>,
}

/// 密钥协商中间态数据
#[derive(Debug, Clone)]
pub struct AgreementData {
    /// 本端临时私钥
    pub tmp_private: [u8; 32],
    /// 本端临时公钥
    pub tmp_public: [u8; 65],
    /// 本端长期私钥索引
    pub isk_index: u32,
    /// ID
    pub id: Vec<u8>,
}

/// 流式对称加解密方向
#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

/// 流式对称操作上下文（EncryptInit/Update/Final 和 DecryptInit/Update/Final 共用）
#[derive(Debug, Clone)]
pub struct SymStreamCtx {
    pub key_handle: u32,
    pub alg_id: u32,
    /// 当前 IV（CBC/OFB/CFB 每个 Update 后更新）
    pub iv: [u8; 16],
    /// 边界缓冲（ECB/CBC 需要16字节对齐时暂存不完整块）
    pub buffer: Vec<u8>,
    pub direction: Direction,
}

/// 流式 MAC 上下文（CalculateMACInit/Update/Final）
#[derive(Debug, Clone)]
pub struct MacStreamCtx {
    pub key_handle: u32,
    pub iv: [u8; 16],
    /// 累积数据（Final 时一次性计算）
    pub buffer: Vec<u8>,
}

/// 流式 AEAD 上下文（AuthEncInit/Update/Final 和 AuthDecInit/Update/Final 共用）
/// Reason: GCM 简化为全累积模式，Final 时一次性出密文+tag，与真机行为等价
#[derive(Debug, Clone)]
pub struct AeadStreamCtx {
    pub key_handle: u32,
    pub nonce: [u8; 12],
    pub aad: Vec<u8>,
    /// 累积的明文（Encrypt）或密文（Decrypt）
    pub buffer: Vec<u8>,
    pub direction: Direction,
    /// Decrypt 时存储 auth tag
    pub auth_tag: Option<[u8; 16]>,
}

/// 会话上下文（每个 SDF_OpenSession 独立一个）
pub struct SessionContext {
    pub handle: u32,
    pub key_store: KeyStore,
    /// 当前活跃的哈希上下文（每次 HashInit 覆盖）
    pub hash_ctx: Option<HashCtx>,
    /// 当前活跃的 HMAC 上下文
    pub hmac_ctx: Option<HmacCtx>,
    /// 密钥协商中间态
    pub agreement_data: Option<AgreementData>,
    /// 私钥访问授权集合（已授权的密钥索引）
    pub authorized_keys: std::collections::HashSet<u32>,
    /// 流式对称加解密上下文
    pub sym_stream: Option<SymStreamCtx>,
    /// 流式 MAC 上下文
    pub mac_stream: Option<MacStreamCtx>,
    /// 流式 AEAD 上下文
    pub aead_stream: Option<AeadStreamCtx>,
}

impl SessionContext {
    pub fn new(mock_cfg: &MockConfig) -> Self {
        let handle = SESSION_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut key_store = KeyStore::new();
        key_store.load_from_config(mock_cfg);
        Self {
            handle,
            key_store,
            hash_ctx: None,
            hmac_ctx: None,
            agreement_data: None,
            authorized_keys: std::collections::HashSet::new(),
            sym_stream: None,
            mac_stream: None,
            aead_stream: None,
        }
    }
}

/// 设备上下文（全局唯一，包含所有会话）
pub struct DeviceContext {
    pub mock_cfg: MockConfig,
    pub sessions: HashMap<u32, SessionContext>,
    /// Reason: 引用计数——记录 SDF_OpenDevice 被调用的次数，
    /// 只有减到0时 SDF_CloseDevice 才真正销毁上下文，
    /// 避免 test_interface_list 内部 Close 破坏外层调用方的会话
    pub open_count: u32,
}

impl DeviceContext {
    pub fn new(mock_cfg: MockConfig) -> Self {
        Self { mock_cfg, sessions: HashMap::new(), open_count: 1 }
    }

    /// 创建新会话，返回会话句柄
    pub fn open_session(&mut self) -> u32 {
        let session = SessionContext::new(&self.mock_cfg);
        let handle = session.handle;
        self.sessions.insert(handle, session);
        log::debug!("打开会话: handle=0x{:08X}", handle);
        handle
    }

    /// 关闭会话
    pub fn close_session(&mut self, handle: u32) -> bool {
        let removed = self.sessions.remove(&handle).is_some();
        if removed {
            log::debug!("关闭会话: handle=0x{:08X}", handle);
        }
        removed
    }

    /// 获取会话（可变引用）
    pub fn get_session_mut(&mut self, handle: u32) -> Option<&mut SessionContext> {
        self.sessions.get_mut(&handle)
    }

    /// 获取会话（不可变引用）
    pub fn get_session(&self, handle: u32) -> Option<&SessionContext> {
        self.sessions.get(&handle)
    }
}

