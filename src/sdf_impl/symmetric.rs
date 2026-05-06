// 对称运算接口实现
// SDF_Encrypt / SDF_Decrypt / SDF_CalculateMAC / SDF_AuthEnc / SDF_AuthDec
// 多包流式接口：SDF_{En,De}crypt{Init,Update,Final} / SDF_CalculateMAC{Init,Update,Final}
//               SDF_AuthEnc{Init,Update,Final} / SDF_AuthDec{Init,Update,Final}

use crate::error_code::*;
use crate::sdf_impl::device::with_session;
use crate::key_mgr::KeyData;
use crate::crypto::sm4_ops::{sm4_encrypt, sm4_decrypt, sm4_cbc_mac, sm4_gcm_encrypt, sm4_gcm_decrypt, sm4_ccm_encrypt, sm4_ccm_decrypt};
use crate::types::alg_id;
use crate::key_mgr::session::{SymStreamCtx, MacStreamCtx, AeadStreamCtx, Direction};

/// 从会话密钥句柄提取 SM4 密钥（16字节）
fn extract_sym_key(key_data: &KeyData) -> Option<[u8; 16]> {
    if let KeyData::Symmetric(v) = key_data {
        if v.len() == 16 {
            return Some(v.as_slice().try_into().unwrap());
        }
    }
    None
}

/// SDF_Encrypt — 对称加密
/// key_handle: 会话密钥句柄
/// alg: 算法标识（SGD_SM4_ECB/CBC/CFB/OFB/CTR）
/// iv: 初始向量（16字节，ECB 忽略）
/// plaintext: 明文
pub fn sdf_encrypt(
    session_handle: u32,
    key_handle: u32,
    alg: u32,
    iv: &[u8; 16],
    plaintext: &[u8],
    ciphertext: &mut Vec<u8>,
) -> i32 {
    if plaintext.is_empty() {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) {
            Some(k) => k,
            None => return SDR_KEYTYPEERR,
        };
        match sm4_encrypt(&key, iv, alg, plaintext) {
            Ok(ct) => {
                *ciphertext = ct;
                log::debug!("SDF_Encrypt: alg=0x{:08X}, in={}, out={}", alg, plaintext.len(), ciphertext.len());
                SDR_OK
            }
            Err(e) => { log::error!("SDF_Encrypt 失败: {}", e); SDR_SYMOPERR }
        }
    })
}

/// SDF_Decrypt — 对称解密
pub fn sdf_decrypt(
    session_handle: u32,
    key_handle: u32,
    alg: u32,
    iv: &[u8; 16],
    ciphertext: &[u8],
    plaintext: &mut Vec<u8>,
) -> i32 {
    if ciphertext.is_empty() {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) {
            Some(k) => k,
            None => return SDR_KEYTYPEERR,
        };
        match sm4_decrypt(&key, iv, alg, ciphertext) {
            Ok(pt) => {
                *plaintext = pt;
                log::debug!("SDF_Decrypt: alg=0x{:08X}, in={}, out={}", alg, ciphertext.len(), plaintext.len());
                SDR_OK
            }
            Err(e) => { log::error!("SDF_Decrypt 失败: {}", e); SDR_SYMOPERR }
        }
    })
}

/// SDF_CalculateMAC — 计算 SM4-CBC-MAC
pub fn sdf_calculate_mac(
    session_handle: u32,
    key_handle: u32,
    iv: &[u8; 16],
    data: &[u8],
    mac: &mut [u8; 16],
) -> i32 {
    if data.is_empty() || data.len() % 16 != 0 {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) {
            Some(k) => k,
            None => return SDR_KEYTYPEERR,
        };
        match sm4_cbc_mac(&key, iv, data) {
            Ok(m) => {
                *mac = m;
                log::debug!("SDF_CalculateMAC: data_len={}", data.len());
                SDR_OK
            }
            Err(e) => { log::error!("MAC 计算失败: {}", e); SDR_SYMOPERR }
        }
    })
}

/// SDF_AuthEnc — 可鉴别加密（GCM/CCM）
/// nonce: 12字节随机数
/// aad: 附加认证数据
/// alg: SGD_SM4_GCM 或 SGD_SM4_CCM
/// 返回：密文 + 认证标签（GCM 固定16字节标签，CCM 标签附在密文后）
pub fn sdf_auth_enc(
    session_handle: u32,
    key_handle: u32,
    alg: u32,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut Vec<u8>,
    tag: &mut [u8; 16],
) -> i32 {
    if plaintext.is_empty() {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) {
            Some(k) => k,
            None => return SDR_KEYTYPEERR,
        };
        match alg {
            alg_id::SGD_SM4_GCM => {
                let (ct, t) = sm4_gcm_encrypt(&key, nonce, aad, plaintext);
                *ciphertext = ct;
                *tag = t;
                SDR_OK
            }
            alg_id::SGD_SM4_CCM => {
                // CCM 标签长度固定16字节
                let ct = sm4_ccm_encrypt(&key, nonce, aad, plaintext, 16);
                let ct_len = ct.len() - 16;
                *tag = ct[ct_len..].try_into().unwrap();
                *ciphertext = ct[..ct_len].to_vec();
                SDR_OK
            }
            _ => SDR_ALGNOTSUPPORT,
        }
    })
}

/// SDF_AuthDec — 可鉴别解密（GCM/CCM）
pub fn sdf_auth_dec(
    session_handle: u32,
    key_handle: u32,
    alg: u32,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext: &mut Vec<u8>,
) -> i32 {
    if ciphertext.is_empty() {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) {
            Some(k) => k,
            None => return SDR_KEYTYPEERR,
        };
        match alg {
            alg_id::SGD_SM4_GCM => {
                match sm4_gcm_decrypt(&key, nonce, aad, ciphertext, tag) {
                    Ok(pt) => { *plaintext = pt; SDR_OK }
                    Err(e) => { log::warn!("GCM 解密认证失败: {}", e); SDR_VERIFYERR }
                }
            }
            alg_id::SGD_SM4_CCM => {
                // 重组密文+标签
                let mut ct_with_tag = ciphertext.to_vec();
                ct_with_tag.extend_from_slice(tag);
                match sm4_ccm_decrypt(&key, nonce, aad, &ct_with_tag, 16) {
                    Ok(pt) => { *plaintext = pt; SDR_OK }
                    Err(e) => { log::warn!("CCM 解密认证失败: {}", e); SDR_VERIFYERR }
                }
            }
            _ => SDR_ALGNOTSUPPORT,
        }
    })
}

// ——————————————————————————————————
// 多包流式对称加解密 Init/Update/Final
// ——————————————————————————————————

/// SDF_EncryptInit — 初始化流式加密
pub fn sdf_encrypt_init(session_handle: u32, key_handle: u32, alg: u32, iv: &[u8; 16]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        if session.sym_stream.is_some() { return SDR_STEPERR; }
        if session.key_store.get_session_key(key_handle).is_none() { return SDR_KEYNOTEXIST; }
        session.sym_stream = Some(SymStreamCtx {
            key_handle, alg_id: alg, iv: *iv, buffer: Vec::new(), direction: Direction::Encrypt,
        });
        SDR_OK
    })
}

/// SDF_EncryptUpdate — 流式加密数据块，返回已加密数据
pub fn sdf_encrypt_update(session_handle: u32, data: &[u8], out: &mut Vec<u8>) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let ctx = match session.sym_stream.as_mut() {
            Some(c) if c.direction == Direction::Encrypt => c,
            _ => return SDR_STEPERR,
        };
        let entry = match session.key_store.get_session_key(ctx.key_handle) {
            Some(e) => e, None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) { Some(k) => k, None => return SDR_KEYTYPEERR };
        let alg = ctx.alg_id;
        if alg == alg_id::SGD_SM4_ECB || alg == alg_id::SGD_SM4_CBC {
            ctx.buffer.extend_from_slice(data);
            let complete = (ctx.buffer.len() / 16) * 16;
            if complete == 0 { return SDR_OK; }
            let block_data: Vec<u8> = ctx.buffer.drain(..complete).collect();
            let iv = ctx.iv;
            match sm4_encrypt(&key, &iv, alg, &block_data) {
                Ok(ct) => {
                    if alg == alg_id::SGD_SM4_CBC && ct.len() >= 16 {
                        ctx.iv.copy_from_slice(&ct[ct.len()-16..]);
                    }
                    *out = ct; SDR_OK
                }
                Err(_) => SDR_SYMOPERR,
            }
        } else {
            let iv = ctx.iv;
            match sm4_encrypt(&key, &iv, alg, data) {
                Ok(ct) => { *out = ct; SDR_OK }
                Err(_) => SDR_SYMOPERR,
            }
        }
    })
}

/// SDF_EncryptFinal — 完成流式加密（ECB/CBC 处理 PKCS#7 padding）
pub fn sdf_encrypt_final(session_handle: u32, out: &mut Vec<u8>) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let ctx = match session.sym_stream.take() {
            Some(c) if c.direction == Direction::Encrypt => c,
            Some(c) => { session.sym_stream = Some(c); return SDR_STEPERR; }
            None => return SDR_STEPERR,
        };
        let entry = match session.key_store.get_session_key(ctx.key_handle) {
            Some(e) => e, None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) { Some(k) => k, None => return SDR_KEYTYPEERR };
        let alg = ctx.alg_id;
        if alg == alg_id::SGD_SM4_ECB || alg == alg_id::SGD_SM4_CBC {
            let pad = 16 - (ctx.buffer.len() % 16);
            let mut padded = ctx.buffer.clone();
            padded.extend(std::iter::repeat(pad as u8).take(pad));
            match sm4_encrypt(&key, &ctx.iv, alg, &padded) {
                Ok(ct) => { *out = ct; SDR_OK }
                Err(_) => SDR_SYMOPERR,
            }
        } else {
            *out = Vec::new(); SDR_OK
        }
    })
}

/// SDF_DecryptInit — 初始化流式解密
pub fn sdf_decrypt_init(session_handle: u32, key_handle: u32, alg: u32, iv: &[u8; 16]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        if session.sym_stream.is_some() { return SDR_STEPERR; }
        if session.key_store.get_session_key(key_handle).is_none() { return SDR_KEYNOTEXIST; }
        session.sym_stream = Some(SymStreamCtx {
            key_handle, alg_id: alg, iv: *iv, buffer: Vec::new(), direction: Direction::Decrypt,
        });
        SDR_OK
    })
}

/// SDF_DecryptUpdate — 流式解密数据块
pub fn sdf_decrypt_update(session_handle: u32, data: &[u8], out: &mut Vec<u8>) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let ctx = match session.sym_stream.as_mut() {
            Some(c) if c.direction == Direction::Decrypt => c,
            _ => return SDR_STEPERR,
        };
        let entry = match session.key_store.get_session_key(ctx.key_handle) {
            Some(e) => e, None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) { Some(k) => k, None => return SDR_KEYTYPEERR };
        let alg = ctx.alg_id;
        if alg == alg_id::SGD_SM4_ECB || alg == alg_id::SGD_SM4_CBC {
            ctx.buffer.extend_from_slice(data);
            // Reason: 保留最后一块不输出，留给 Final 做 PKCS#7 去填充
            let complete = if ctx.buffer.len() > 16 { ((ctx.buffer.len() - 1) / 16) * 16 } else { 0 };
            if complete == 0 { return SDR_OK; }
            let block_data: Vec<u8> = ctx.buffer.drain(..complete).collect();
            let iv = ctx.iv;
            match sm4_decrypt(&key, &iv, alg, &block_data) {
                Ok(pt) => {
                    if alg == alg_id::SGD_SM4_CBC && block_data.len() >= 16 {
                        ctx.iv.copy_from_slice(&block_data[block_data.len()-16..]);
                    }
                    *out = pt; SDR_OK
                }
                Err(_) => SDR_SYMOPERR,
            }
        } else {
            let iv = ctx.iv;
            match sm4_decrypt(&key, &iv, alg, data) {
                Ok(pt) => { *out = pt; SDR_OK }
                Err(_) => SDR_SYMOPERR,
            }
        }
    })
}

/// SDF_DecryptFinal — 完成流式解密，去 PKCS#7 padding
pub fn sdf_decrypt_final(session_handle: u32, out: &mut Vec<u8>) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let ctx = match session.sym_stream.take() {
            Some(c) if c.direction == Direction::Decrypt => c,
            Some(c) => { session.sym_stream = Some(c); return SDR_STEPERR; }
            None => return SDR_STEPERR,
        };
        let entry = match session.key_store.get_session_key(ctx.key_handle) {
            Some(e) => e, None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) { Some(k) => k, None => return SDR_KEYTYPEERR };
        let alg = ctx.alg_id;
        if alg == alg_id::SGD_SM4_ECB || alg == alg_id::SGD_SM4_CBC {
            if ctx.buffer.is_empty() || ctx.buffer.len() % 16 != 0 { return SDR_SYMOPERR; }
            match sm4_decrypt(&key, &ctx.iv, alg, &ctx.buffer) {
                Ok(mut pt) => {
                    let pad = *pt.last().unwrap_or(&0) as usize;
                    if pad == 0 || pad > 16 { return SDR_SYMOPERR; }
                    pt.truncate(pt.len() - pad);
                    *out = pt; SDR_OK
                }
                Err(_) => SDR_SYMOPERR,
            }
        } else {
            *out = Vec::new(); SDR_OK
        }
    })
}

// ——————————————————————————————————
// 多包 MAC Init/Update/Final
// ——————————————————————————————————

pub fn sdf_calculate_mac_init(session_handle: u32, key_handle: u32, iv: &[u8; 16]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        if session.mac_stream.is_some() { return SDR_STEPERR; }
        if session.key_store.get_session_key(key_handle).is_none() { return SDR_KEYNOTEXIST; }
        session.mac_stream = Some(MacStreamCtx { key_handle, iv: *iv, buffer: Vec::new() });
        SDR_OK
    })
}

pub fn sdf_calculate_mac_update(session_handle: u32, data: &[u8]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match session.mac_stream.as_mut() {
            Some(ctx) => { ctx.buffer.extend_from_slice(data); SDR_OK }
            None => SDR_STEPERR,
        }
    })
}

pub fn sdf_calculate_mac_final(session_handle: u32, mac: &mut [u8; 16]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let ctx = match session.mac_stream.take() { Some(c) => c, None => return SDR_STEPERR };
        if ctx.buffer.is_empty() || ctx.buffer.len() % 16 != 0 { return SDR_INARGERR; }
        let entry = match session.key_store.get_session_key(ctx.key_handle) {
            Some(e) => e, None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) { Some(k) => k, None => return SDR_KEYTYPEERR };
        match sm4_cbc_mac(&key, &ctx.iv, &ctx.buffer) {
            Ok(m) => { *mac = m; SDR_OK }
            Err(_) => SDR_SYMOPERR,
        }
    })
}

// ——————————————————————————————————
// 多包 AEAD Init/Update/Final (GCM)
// Reason: 全累积模式简化实现，Final 一次性 GCM 出密文+tag，与真机行为等价
// ——————————————————————————————————

pub fn sdf_auth_enc_init(session_handle: u32, key_handle: u32, nonce: &[u8; 12], aad: &[u8]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        if session.aead_stream.is_some() { return SDR_STEPERR; }
        if session.key_store.get_session_key(key_handle).is_none() { return SDR_KEYNOTEXIST; }
        session.aead_stream = Some(AeadStreamCtx {
            key_handle, nonce: *nonce, aad: aad.to_vec(),
            buffer: Vec::new(), direction: Direction::Encrypt, auth_tag: None,
        });
        SDR_OK
    })
}

pub fn sdf_auth_enc_update(session_handle: u32, data: &[u8]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match session.aead_stream.as_mut() {
            Some(ctx) if ctx.direction == Direction::Encrypt => { ctx.buffer.extend_from_slice(data); SDR_OK }
            _ => SDR_STEPERR,
        }
    })
}

pub fn sdf_auth_enc_final(session_handle: u32, ciphertext: &mut Vec<u8>, tag: &mut [u8; 16]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let ctx = match session.aead_stream.take() {
            Some(c) if c.direction == Direction::Encrypt => c,
            Some(c) => { session.aead_stream = Some(c); return SDR_STEPERR; }
            None => return SDR_STEPERR,
        };
        let entry = match session.key_store.get_session_key(ctx.key_handle) {
            Some(e) => e, None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) { Some(k) => k, None => return SDR_KEYTYPEERR };
        let (ct, t) = sm4_gcm_encrypt(&key, &ctx.nonce, &ctx.aad, &ctx.buffer);
        *ciphertext = ct; *tag = t; SDR_OK
    })
}

pub fn sdf_auth_dec_init(session_handle: u32, key_handle: u32, nonce: &[u8; 12], aad: &[u8], auth_tag: &[u8; 16]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        if session.aead_stream.is_some() { return SDR_STEPERR; }
        if session.key_store.get_session_key(key_handle).is_none() { return SDR_KEYNOTEXIST; }
        session.aead_stream = Some(AeadStreamCtx {
            key_handle, nonce: *nonce, aad: aad.to_vec(),
            buffer: Vec::new(), direction: Direction::Decrypt, auth_tag: Some(*auth_tag),
        });
        SDR_OK
    })
}

pub fn sdf_auth_dec_update(session_handle: u32, data: &[u8]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match session.aead_stream.as_mut() {
            Some(ctx) if ctx.direction == Direction::Decrypt => { ctx.buffer.extend_from_slice(data); SDR_OK }
            _ => SDR_STEPERR,
        }
    })
}

pub fn sdf_auth_dec_final(session_handle: u32, plaintext: &mut Vec<u8>) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let ctx = match session.aead_stream.take() {
            Some(c) if c.direction == Direction::Decrypt => c,
            Some(c) => { session.aead_stream = Some(c); return SDR_STEPERR; }
            None => return SDR_STEPERR,
        };
        let tag = match ctx.auth_tag { Some(t) => t, None => return SDR_INARGERR };
        let entry = match session.key_store.get_session_key(ctx.key_handle) {
            Some(e) => e, None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) { Some(k) => k, None => return SDR_KEYTYPEERR };
        match sm4_gcm_decrypt(&key, &ctx.nonce, &ctx.aad, &ctx.buffer, &tag) {
            Ok(pt) => { *plaintext = pt; SDR_OK }
            Err(e) => { log::warn!("流式 GCM 解密认证失败: {}", e); SDR_VERIFYERR }
        }
    })
}
