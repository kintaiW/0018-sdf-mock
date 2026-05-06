// 内存密钥仓库
// 管理所有类型的密钥：预设密钥（来自配置）+ 运行时生成的会话密钥

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

/// 密钥类型
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    /// SM4 对称密钥
    Symmetric,
    /// SM2 签名密钥对（私钥 + 公钥）
    EccSign,
    /// SM2 加密密钥对（私钥 + 公钥）
    EccEnc,
    /// 临时 SM2 密钥对（密钥协商用）
    EccTemp,
}

/// 密钥数据载体
#[derive(Debug, Clone)]
pub enum KeyData {
    /// SM4 对称密钥（16字节）
    Symmetric(Vec<u8>),
    /// ECC 密钥对（私钥32字节，公钥65字节）
    EccPair { private_key: [u8; 32], public_key: [u8; 65] },
    /// 仅公钥（外部导入）
    EccPublicOnly([u8; 65]),
}

impl KeyData {
    pub fn key_type(&self) -> KeyType {
        match self {
            KeyData::Symmetric(_) => KeyType::Symmetric,
            KeyData::EccPair { .. } => KeyType::EccSign,
            KeyData::EccPublicOnly(_) => KeyType::EccSign,
        }
    }
}

/// 存储的密钥条目
#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub key_type: KeyType,
    pub data: KeyData,
    /// 是否为预设密钥（来自配置文件）
    pub is_preset: bool,
}

static HANDLE_COUNTER: AtomicU32 = AtomicU32::new(0x10000001);

/// 内存密钥仓库（线程安全由调用层的 Mutex 保证）
#[derive(Debug, Default)]
pub struct KeyStore {
    /// 会话密钥：句柄 -> 密钥
    session_keys: HashMap<u32, KeyEntry>,
    /// 预设 KEK 密钥：索引 -> SM4 密钥
    kek_keys: HashMap<u32, [u8; 16]>,
    /// 预设签名密钥对：索引 -> ECC 密钥对
    sign_keys: HashMap<u32, ([u8; 32], [u8; 65])>,
    /// 预设加密密钥对：索引 -> ECC 密钥对
    enc_keys: HashMap<u32, ([u8; 32], [u8; 65])>,
    /// 设备根密钥
    root_key: [u8; 16],
    /// RSA 签名私钥：索引 -> PEM 字符串（懒解析）
    rsa_sign_pem: HashMap<u32, String>,
    /// RSA 加密私钥：索引 -> PEM 字符串（懒解析）
    rsa_enc_pem: HashMap<u32, String>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 从 MockConfig 中加载预设密钥
    pub fn load_from_config(&mut self, cfg: &crate::config::MockConfig) {
        self.root_key = cfg.root_key;
        for k in &cfg.kek_keys {
            self.kek_keys.insert(k.index, k.key);
        }
        for k in &cfg.sign_keys {
            self.sign_keys.insert(k.index, (k.private_key, k.public_key));
        }
        for k in &cfg.enc_keys {
            self.enc_keys.insert(k.index, (k.private_key, k.public_key));
        }
        for k in &cfg.rsa_sign_keys {
            self.rsa_sign_pem.insert(k.index, k.private_key_pem.clone());
        }
        for k in &cfg.rsa_enc_keys {
            self.rsa_enc_pem.insert(k.index, k.private_key_pem.clone());
        }
        log::info!("密钥仓库已加载: KEK={}, 签名密钥={}, 加密密钥={}, RSA签名={}, RSA加密={}",
            self.kek_keys.len(), self.sign_keys.len(), self.enc_keys.len(),
            self.rsa_sign_pem.len(), self.rsa_enc_pem.len());
    }

    /// 生成新的会话密钥句柄（线程安全的原子递增）
    pub fn next_handle() -> u32 {
        HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// 存储会话密钥，返回句柄
    pub fn store_session_key(&mut self, key_type: KeyType, data: KeyData) -> u32 {
        let handle = Self::next_handle();
        self.session_keys.insert(handle, KeyEntry { key_type, data, is_preset: false });
        handle
    }

    /// 获取会话密钥
    pub fn get_session_key(&self, handle: u32) -> Option<&KeyEntry> {
        self.session_keys.get(&handle)
    }

    /// 销毁会话密钥
    pub fn destroy_session_key(&mut self, handle: u32) -> bool {
        self.session_keys.remove(&handle).is_some()
    }

    /// 获取 KEK 密钥
    pub fn get_kek(&self, index: u32) -> Option<&[u8; 16]> {
        self.kek_keys.get(&index)
    }

    /// 获取预设签名密钥对（私钥，公钥）
    pub fn get_sign_key(&self, index: u32) -> Option<&([u8; 32], [u8; 65])> {
        self.sign_keys.get(&index)
    }

    /// 获取预设加密密钥对（私钥，公钥）
    pub fn get_enc_key(&self, index: u32) -> Option<&([u8; 32], [u8; 65])> {
        self.enc_keys.get(&index)
    }

    /// 获取根密钥
    pub fn root_key(&self) -> &[u8; 16] {
        &self.root_key
    }

    /// 预设签名公钥（只需公钥时）
    pub fn get_sign_public_key(&self, index: u32) -> Option<[u8; 65]> {
        self.sign_keys.get(&index).map(|(_, pub_key)| *pub_key)
    }

    /// 预设加密公钥（只需公钥时）
    pub fn get_enc_public_key(&self, index: u32) -> Option<[u8; 65]> {
        self.enc_keys.get(&index).map(|(_, pub_key)| *pub_key)
    }

    /// 获取 RSA 签名私钥（懒解析 PEM 为 RsaPrivateKey）
    pub fn get_rsa_sign_key(&self, index: u32) -> Option<rsa::RsaPrivateKey> {
        let pem = self.rsa_sign_pem.get(&index)?;
        crate::crypto::rsa_ops::rsa_load_private_key(pem).ok()
    }

    /// 获取 RSA 加密私钥
    pub fn get_rsa_enc_key(&self, index: u32) -> Option<rsa::RsaPrivateKey> {
        let pem = self.rsa_enc_pem.get(&index)?;
        crate::crypto::rsa_ops::rsa_load_private_key(pem).ok()
    }

    /// 检查 RSA 签名密钥索引是否存在
    pub fn has_rsa_sign_key(&self, index: u32) -> bool {
        self.rsa_sign_pem.contains_key(&index)
    }

    /// 检查 RSA 加密密钥索引是否存在
    pub fn has_rsa_enc_key(&self, index: u32) -> bool {
        self.rsa_enc_pem.contains_key(&index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_get_session_key() {
        let mut store = KeyStore::new();
        let data = KeyData::Symmetric(vec![0u8; 16]);
        let handle = store.store_session_key(KeyType::Symmetric, data);
        assert!(handle >= 0x10000001);
        assert!(store.get_session_key(handle).is_some());
    }

    #[test]
    fn test_destroy_session_key() {
        let mut store = KeyStore::new();
        let data = KeyData::Symmetric(vec![0u8; 16]);
        let handle = store.store_session_key(KeyType::Symmetric, data);
        assert!(store.destroy_session_key(handle));
        assert!(store.get_session_key(handle).is_none());
        // 重复销毁应返回 false
        assert!(!store.destroy_session_key(handle));
    }

    #[test]
    fn test_kek_not_found() {
        let store = KeyStore::new();
        assert!(store.get_kek(999).is_none());
    }
}
