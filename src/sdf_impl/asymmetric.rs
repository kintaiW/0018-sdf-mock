// 非对称运算接口实现
// SDF_ExternalSign_ECC / SDF_ExternalVerify_ECC / SDF_InternalSign_ECC /
// SDF_InternalVerify_ECC / SDF_ExternalEncrypt_ECC / SDF_ExternalDecrypt_ECC /
// SDF_InternalEncrypt_ECC / SDF_InternalDecrypt_ECC

use crate::error_code::*;
use crate::sdf_impl::device::with_session;
use crate::types::{ECCrefPublicKey, ECCrefPrivateKey, ECCCipher, ECCSignature};
use crate::crypto::sm2_ops::{
    ecc_ref_to_pub_key, ecc_ref_to_pri_key,
    sm2_sign_full, sm2_verify_full,
    sm2_ext_sign, sm2_ext_verify,
    sm2_enc, sm2_dec,
};

/// 默认用户 ID（GM/T 0003 标准附录）
const DEFAULT_ID: &[u8] = b"1234567812345678";

/// SDF_ExternalSign_ECC — 用外部私钥签名（直接对数据哈希签名，不计算 Z 值）
pub fn sdf_external_sign_ecc(
    session_handle: u32,
    _alg: u32,
    pri_key: &ECCrefPrivateKey,
    data: &[u8],
    sig: &mut ECCSignature,
) -> i32 {
    if data.len() != 32 {
        // SDF 标准：外部签名接收的是已哈希的32字节数据（即e值）
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        if let Err(e) = res { return e; }
        let pri = ecc_ref_to_pri_key(pri_key);
        // Reason: 外部签名接口接收预哈希数据，不再叠加 SM3
        let result = sm2_ext_sign(&pri, data);
        *sig = result;
        log::debug!("SDF_ExternalSign_ECC: 签名完成");
        SDR_OK
    })
}

/// SDF_ExternalVerify_ECC — 用外部公钥验签
pub fn sdf_external_verify_ecc(
    session_handle: u32,
    _alg: u32,
    pub_key: &ECCrefPublicKey,
    data: &[u8],
    sig: &ECCSignature,
) -> i32 {
    if data.len() != 32 {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        if let Err(e) = res { return e; }
        let pub_k = ecc_ref_to_pub_key(pub_key);
        if sm2_ext_verify(&pub_k, data, sig) {
            log::debug!("SDF_ExternalVerify_ECC: 验签成功");
            SDR_OK
        } else {
            log::warn!("SDF_ExternalVerify_ECC: 验签失败");
            SDR_VERIFYERR
        }
    })
}

/// SDF_InternalSign_ECC — 用内部（预设）签名私钥签名
/// isk_index: 签名密钥索引
/// data: 原始数据（函数内部计算 Z 值和 e 值）
pub fn sdf_internal_sign_ecc(
    session_handle: u32,
    isk_index: u32,
    data: &[u8],
    sig: &mut ECCSignature,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        // 检查私钥访问权限
        if !session.authorized_keys.contains(&isk_index) {
            log::warn!("SDF_InternalSign_ECC: 未授权的私钥访问 index={}", isk_index);
            return SDR_PARDENY;
        }
        let (pri, pub_k) = match session.key_store.get_sign_key(isk_index) {
            Some(kp) => *kp,
            None => return SDR_KEYNOTEXIST,
        };
        match sm2_sign_full(&pri, &pub_k, data, DEFAULT_ID) {
            Ok(s) => {
                *sig = s;
                log::debug!("SDF_InternalSign_ECC: index={}", isk_index);
                SDR_OK
            }
            Err(e) => { log::error!("签名失败: {}", e); SDR_SIGNERR }
        }
    })
}

/// SDF_InternalVerify_ECC — 用内部（预设）签名公钥验签
pub fn sdf_internal_verify_ecc(
    session_handle: u32,
    ipk_index: u32,
    data: &[u8],
    sig: &ECCSignature,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let (_, pub_k) = match session.key_store.get_sign_key(ipk_index) {
            Some(kp) => *kp,
            None => return SDR_KEYNOTEXIST,
        };
        if sm2_verify_full(&pub_k, data, DEFAULT_ID, sig) {
            log::debug!("SDF_InternalVerify_ECC: index={} 验签成功", ipk_index);
            SDR_OK
        } else {
            log::warn!("SDF_InternalVerify_ECC: index={} 验签失败", ipk_index);
            SDR_VERIFYERR
        }
    })
}

/// SDF_ExternalEncrypt_ECC — 用外部公钥加密
pub fn sdf_external_encrypt_ecc(
    session_handle: u32,
    _alg: u32,
    pub_key: &ECCrefPublicKey,
    plaintext: &[u8],
    cipher: &mut ECCCipher,
) -> i32 {
    if plaintext.is_empty() || plaintext.len() > 136 {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        if let Err(e) = res { return e; }
        let pub_k = ecc_ref_to_pub_key(pub_key);
        match sm2_enc(&pub_k, plaintext) {
            Ok(c) => {
                *cipher = c;
                log::debug!("SDF_ExternalEncrypt_ECC: plaintext_len={}", plaintext.len());
                SDR_OK
            }
            Err(e) => { log::error!("SM2 加密失败: {}", e); SDR_PKOPERR }
        }
    })
}

/// SDF_ExternalDecrypt_ECC — 用外部私钥解密
pub fn sdf_external_decrypt_ecc(
    session_handle: u32,
    _alg: u32,
    pri_key: &ECCrefPrivateKey,
    cipher: &ECCCipher,
    plaintext: &mut Vec<u8>,
) -> i32 {
    with_session(session_handle, |res| {
        if let Err(e) = res { return e; }
        let pri = ecc_ref_to_pri_key(pri_key);
        match sm2_dec(&pri, cipher) {
            Some(pt) => {
                *plaintext = pt;
                log::debug!("SDF_ExternalDecrypt_ECC: 解密成功");
                SDR_OK
            }
            None => { log::error!("SM2 解密失败"); SDR_SKOPERR }
        }
    })
}

/// SDF_InternalEncrypt_ECC — 用内部（预设）加密公钥加密
pub fn sdf_internal_encrypt_ecc(
    session_handle: u32,
    _alg: u32,
    ipk_index: u32,
    plaintext: &[u8],
    cipher: &mut ECCCipher,
) -> i32 {
    if plaintext.is_empty() || plaintext.len() > 128 {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let (_, pub_k) = match session.key_store.get_enc_key(ipk_index) {
            Some(kp) => *kp,
            None => return SDR_KEYNOTEXIST,
        };
        match sm2_enc(&pub_k, plaintext) {
            Ok(c) => { *cipher = c; SDR_OK }
            Err(e) => { log::error!("SDF_InternalEncrypt_ECC 失败: {}", e); SDR_PKOPERR }
        }
    })
}

/// SDF_InternalDecrypt_ECC — 用内部（预设）加密私钥解密
pub fn sdf_internal_decrypt_ecc(
    session_handle: u32,
    _alg: u32,
    isk_index: u32,
    cipher: &ECCCipher,
    plaintext: &mut Vec<u8>,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        if !session.authorized_keys.contains(&isk_index) {
            return SDR_PARDENY;
        }
        let (pri, _) = match session.key_store.get_enc_key(isk_index) {
            Some(kp) => *kp,
            None => return SDR_KEYNOTEXIST,
        };
        match sm2_dec(&pri, cipher) {
            Some(pt) => { *plaintext = pt; SDR_OK }
            None => { log::error!("SDF_InternalDecrypt_ECC 解密失败"); SDR_SKOPERR }
        }
    })
}
