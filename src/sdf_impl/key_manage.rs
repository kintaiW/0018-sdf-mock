// 密钥管理接口实现
use crate::error_code::*;
use crate::sdf_impl::device::with_session;
use crate::key_mgr::{KeyType, KeyData};
use crate::crypto::{sm2_keygen, generate_random, sm4_encrypt as sm4_enc, sm4_decrypt as sm4_dec};
use crate::types::{ECCrefPublicKey, ECCrefPrivateKey, ECCCipher, alg_id, RSArefPublicKey, RSArefPrivateKey};
use crate::crypto::sm2_ops::{
    pub_key_to_ecc_ref, ecc_ref_to_pub_key, ecc_ref_to_pri_key,
    sm2_enc, sm2_dec,
};
use crate::key_mgr::session::AgreementData;
use crate::crypto::rsa_ops::{rsa_load_private_key, rsa_pub_from_priv, rsa_pub_to_ref, rsa_priv_to_ref};

// ──────────────── RSA 接口（真实运算）────────────────

/// SDF_ExportSignPublicKey_RSA — 导出 RSA 签名公钥
pub fn sdf_export_sign_public_key_rsa(
    session_handle: u32,
    key_index: u32,
    pub_key: &mut RSArefPublicKey,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match session.key_store.get_rsa_sign_key(key_index) {
            Some(priv_k) => {
                *pub_key = rsa_pub_to_ref(&rsa_pub_from_priv(&priv_k));
                log::debug!("SDF_ExportSignPublicKey_RSA: index={}", key_index);
                SDR_OK
            }
            None => {
                log::warn!("SDF_ExportSignPublicKey_RSA: RSA签名密钥索引{}不存在", key_index);
                SDR_KEYNOTEXIST
            }
        }
    })
}

/// SDF_ExportEncPublicKey_RSA — 导出 RSA 加密公钥
pub fn sdf_export_enc_public_key_rsa(
    session_handle: u32,
    key_index: u32,
    pub_key: &mut RSArefPublicKey,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match session.key_store.get_rsa_enc_key(key_index) {
            Some(priv_k) => {
                *pub_key = rsa_pub_to_ref(&rsa_pub_from_priv(&priv_k));
                log::debug!("SDF_ExportEncPublicKey_RSA: index={}", key_index);
                SDR_OK
            }
            None => {
                log::warn!("SDF_ExportEncPublicKey_RSA: RSA加密密钥索引{}不存在", key_index);
                SDR_KEYNOTEXIST
            }
        }
    })
}

/// SDF_GenerateKeyPair_RSA — 生成 RSA 密钥对（临时，不存储到密钥库）
pub fn sdf_generate_key_pair_rsa(
    session_handle: u32,
    bits: u32,
    pub_key: &mut RSArefPublicKey,
    pri_key: &mut RSArefPrivateKey,
) -> i32 {
    if bits != 1024 && bits != 2048 && bits != 4096 {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        if let Err(e) = res { return e; }
        use rsa::rand_core::OsRng;
        match rsa::RsaPrivateKey::new(&mut OsRng, bits as usize) {
            Ok(priv_k) => {
                *pub_key = rsa_pub_to_ref(&rsa_pub_from_priv(&priv_k));
                *pri_key = rsa_priv_to_ref(&priv_k);
                log::debug!("SDF_GenerateKeyPair_RSA: bits={}", bits);
                SDR_OK
            }
            Err(e) => { log::error!("RSA密钥生成失败: {}", e); SDR_PKOPERR }
        }
    })
}

// ──────────────── 设备/会话密钥管理 ────────────────

/// SDF_GenerateRandom — 生成随机数
pub fn sdf_generate_random(session_handle: u32, length: u32, random: &mut Vec<u8>) -> i32 {
    if length == 0 || length > 4096 {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        if let Err(e) = res { return e; }
        *random = generate_random(length as usize);
        log::debug!("SDF_GenerateRandom: {} 字节", length);
        SDR_OK
    })
}

/// SDF_GetPrivateKeyAccessRight — 获取私钥访问权限
pub fn sdf_get_private_key_access_right(
    session_handle: u32,
    key_index: u32,
    _password: &[u8],
) -> i32 {
    // Reason: Mock 场景不验证密码，直接授权
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        session.authorized_keys.insert(key_index);
        log::debug!("SDF_GetPrivateKeyAccessRight: index={}", key_index);
        SDR_OK
    })
}

/// SDF_ReleasePrivateKeyAccessRight — 释放私钥访问权限
pub fn sdf_release_private_key_access_right(session_handle: u32, key_index: u32) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        session.authorized_keys.remove(&key_index);
        log::debug!("SDF_ReleasePrivateKeyAccessRight: index={}", key_index);
        SDR_OK
    })
}

/// SDF_ExportSignPublicKey_ECC — 导出签名公钥
pub fn sdf_export_sign_public_key_ecc(
    session_handle: u32,
    key_index: u32,
    pub_key: &mut ECCrefPublicKey,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match session.key_store.get_sign_public_key(key_index) {
            Some(pk) => {
                *pub_key = pub_key_to_ecc_ref(&pk);
                log::debug!("SDF_ExportSignPublicKey_ECC: index={}", key_index);
                SDR_OK
            }
            None => {
                log::warn!("SDF_ExportSignPublicKey_ECC: 签名密钥索引{}不存在", key_index);
                SDR_KEYNOTEXIST
            }
        }
    })
}

/// SDF_ExportEncPublicKey_ECC — 导出加密公钥
pub fn sdf_export_enc_public_key_ecc(
    session_handle: u32,
    key_index: u32,
    pub_key: &mut ECCrefPublicKey,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match session.key_store.get_enc_public_key(key_index) {
            Some(pk) => {
                *pub_key = pub_key_to_ecc_ref(&pk);
                log::debug!("SDF_ExportEncPublicKey_ECC: index={}", key_index);
                SDR_OK
            }
            None => {
                log::warn!("SDF_ExportEncPublicKey_ECC: 加密密钥索引{}不存在", key_index);
                SDR_KEYNOTEXIST
            }
        }
    })
}

/// SDF_GenerateKeyPair_ECC — 生成 ECC 密钥对
/// alg: 算法标识（SGD_SM2_1 签名 / SGD_SM2_3 加密）
/// bits: 密钥长度（SM2 固定256）
pub fn sdf_generate_key_pair_ecc(
    session_handle: u32,
    _alg: u32,
    _bits: u32,
    pub_key: &mut ECCrefPublicKey,
    pri_key: &mut ECCrefPrivateKey,
) -> i32 {
    with_session(session_handle, |res| {
        if let Err(e) = res { return e; }
        let (pri, pub_k) = sm2_keygen();
        *pub_key = pub_key_to_ecc_ref(&pub_k);
        pri_key.bits = 256;
        pri_key.K[32..64].copy_from_slice(&pri);
        log::debug!("SDF_GenerateKeyPair_ECC: 生成完毕");
        SDR_OK
    })
}

/// SDF_ImportKey — 明文导入会话密钥
/// key_data: 明文密钥数据（SM4 需16字节）
pub fn sdf_import_key(
    session_handle: u32,
    key_data: &[u8],
    key_handle: &mut u32,
) -> i32 {
    if key_data.len() != 16 {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let handle = session.key_store.store_session_key(
            KeyType::Symmetric,
            KeyData::Symmetric(key_data.to_vec()),
        );
        *key_handle = handle;
        log::debug!("SDF_ImportKey: handle=0x{:08X}", handle);
        SDR_OK
    })
}

/// SDF_GenerateKeyWithKEK — 用 KEK 生成会话密钥（SM4，16字节随机密钥 + SM4-ECB 封装）
/// 返回：加密后的密钥密文 + 会话密钥句柄
pub fn sdf_generate_key_with_kek(
    session_handle: u32,
    bits: u32,
    kek_index: u32,
    cipher_key: &mut Vec<u8>,
    key_handle: &mut u32,
) -> i32 {
    if bits != 128 {
        return SDR_INARGERR; // 仅支持 SM4 128位
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let kek = match session.key_store.get_kek(kek_index) {
            Some(k) => *k,
            None => {
                log::warn!("SDF_GenerateKeyWithKEK: KEK索引{}不存在", kek_index);
                return SDR_KEYNOTEXIST;
            }
        };
        // 生成随机 SM4 会话密钥
        let session_key = generate_random(16);
        // 用 KEK 加密（SM4-ECB）
        let iv = [0u8; 16];
        let encrypted = match sm4_enc(&kek, &iv, alg_id::SGD_SM4_ECB, &session_key) {
            Ok(c) => c,
            Err(e) => { log::error!("KEK 加密失败: {}", e); return SDR_SYMOPERR; }
        };
        *cipher_key = encrypted;
        // 存储会话密钥
        let handle = session.key_store.store_session_key(
            KeyType::Symmetric,
            KeyData::Symmetric(session_key),
        );
        *key_handle = handle;
        log::debug!("SDF_GenerateKeyWithKEK: kek_index={}, handle=0x{:08X}", kek_index, handle);
        SDR_OK
    })
}

/// SDF_ImportKeyWithKEK — 用 KEK 导入会话密钥
pub fn sdf_import_key_with_kek(
    session_handle: u32,
    _alg: u32,
    kek_index: u32,
    cipher_key: &[u8],
    key_handle: &mut u32,
) -> i32 {
    if cipher_key.len() != 16 {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let kek = match session.key_store.get_kek(kek_index) {
            Some(k) => *k,
            None => return SDR_KEYNOTEXIST,
        };
        let iv = [0u8; 16];
        let plain = match sm4_dec(&kek, &iv, alg_id::SGD_SM4_ECB, cipher_key) {
            Ok(p) => p,
            Err(_) => return SDR_SYMOPERR,
        };
        let handle = session.key_store.store_session_key(
            KeyType::Symmetric,
            KeyData::Symmetric(plain),
        );
        *key_handle = handle;
        log::debug!("SDF_ImportKeyWithKEK: handle=0x{:08X}", handle);
        SDR_OK
    })
}

/// SDF_GenerateKeyWithIPK_ECC — 用内部加密公钥封装会话密钥
pub fn sdf_generate_key_with_ipk_ecc(
    session_handle: u32,
    ipk_index: u32,
    bits: u32,
    cipher_key: &mut ECCCipher,
    key_handle: &mut u32,
) -> i32 {
    if bits != 128 {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let pub_k = match session.key_store.get_enc_public_key(ipk_index) {
            Some(pk) => pk,
            None => return SDR_KEYNOTEXIST,
        };
        // 生成随机 SM4 会话密钥并用 SM2 加密
        let session_key = generate_random(16);
        match sm2_enc(&pub_k, &session_key) {
            Ok(c) => {
                *cipher_key = c;
                let handle = session.key_store.store_session_key(
                    KeyType::Symmetric,
                    KeyData::Symmetric(session_key),
                );
                *key_handle = handle;
                log::debug!("SDF_GenerateKeyWithIPK_ECC: ipk_index={}, handle=0x{:08X}", ipk_index, handle);
                SDR_OK
            }
            Err(e) => { log::error!("SM2 加密失败: {}", e); SDR_PKOPERR }
        }
    })
}

/// SDF_GenerateKeyWithEPK_ECC — 用外部公钥封装会话密钥
pub fn sdf_generate_key_with_epk_ecc(
    session_handle: u32,
    bits: u32,
    _alg: u32,
    pub_key: &ECCrefPublicKey,
    cipher_key: &mut ECCCipher,
    key_handle: &mut u32,
) -> i32 {
    if bits != 128 {
        return SDR_INARGERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let pub_k = ecc_ref_to_pub_key(pub_key);
        let session_key = generate_random(16);
        match sm2_enc(&pub_k, &session_key) {
            Ok(c) => {
                *cipher_key = c;
                let handle = session.key_store.store_session_key(
                    KeyType::Symmetric,
                    KeyData::Symmetric(session_key),
                );
                *key_handle = handle;
                SDR_OK
            }
            Err(e) => { log::error!("SM2 加密失败: {}", e); SDR_PKOPERR }
        }
    })
}

/// SDF_ImportKeyWithISK_ECC — 用内部私钥解封装会话密钥
pub fn sdf_import_key_with_isk_ecc(
    session_handle: u32,
    isk_index: u32,
    cipher_key: &ECCCipher,
    key_handle: &mut u32,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        // 检查私钥访问权限
        if !session.authorized_keys.contains(&isk_index) {
            log::warn!("SDF_ImportKeyWithISK_ECC: 未授权的私钥访问 index={}", isk_index);
            return SDR_PARDENY;
        }
        let pri_k = match session.key_store.get_enc_key(isk_index) {
            Some((pri, _)) => *pri,
            None => return SDR_KEYNOTEXIST,
        };
        match sm2_dec(&pri_k, cipher_key) {
            Some(plain) => {
                let handle = session.key_store.store_session_key(
                    KeyType::Symmetric,
                    KeyData::Symmetric(plain),
                );
                *key_handle = handle;
                log::debug!("SDF_ImportKeyWithISK_ECC: handle=0x{:08X}", handle);
                SDR_OK
            }
            None => { log::error!("SM2 解密失败"); SDR_PKOPERR }
        }
    })
}

/// SDF_DestroyKey — 销毁会话密钥
pub fn sdf_destroy_key(session_handle: u32, key_handle: u32) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        if session.key_store.destroy_session_key(key_handle) {
            log::debug!("SDF_DestroyKey: handle=0x{:08X}", key_handle);
            SDR_OK
        } else {
            log::warn!("SDF_DestroyKey: 密钥句柄0x{:08X}不存在", key_handle);
            SDR_KEYNOTEXIST
        }
    })
}

// ──────────────── ECC 密钥协商 ────────────────

/// SDF_GenerateAgreementDataWithECC — 发起方生成临时密钥对和协商数据
/// isk_index: 本端长期加密密钥索引
/// sponsor_id: 本端用户 ID（用于 SM2 KDF）
/// sponsor_pub_key: 本端长期公钥（输出）
/// sponsor_tmp_pub_key: 本端临时公钥（输出）
pub fn sdf_generate_agreement_data_with_ecc(
    session_handle: u32,
    isk_index: u32,
    sponsor_id: &[u8],
    sponsor_pub_key: &mut ECCrefPublicKey,
    sponsor_tmp_pub_key: &mut ECCrefPublicKey,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        // 取本端长期加密密钥
        let (_, long_pub) = match session.key_store.get_enc_key(isk_index) {
            Some(kp) => *kp,
            None => return SDR_KEYNOTEXIST,
        };
        // 生成临时密钥对
        let (tmp_pri, tmp_pub) = sm2_keygen();
        session.agreement_data = Some(AgreementData {
            tmp_private: tmp_pri,
            tmp_public: tmp_pub,
            isk_index,
            id: sponsor_id.to_vec(),
        });
        *sponsor_pub_key = pub_key_to_ecc_ref(&long_pub);
        *sponsor_tmp_pub_key = pub_key_to_ecc_ref(&tmp_pub);
        log::debug!("SDF_GenerateAgreementDataWithECC: isk_index={}", isk_index);
        SDR_OK
    })
}

/// SDF_GenerateKeyWithECC — 响应方用对端协商数据生成会话密钥
/// 简化实现：用 SM3 对双方临时公钥做 KDF 派生 SM4 密钥
pub fn sdf_generate_key_with_ecc(
    session_handle: u32,
    response_id: &[u8],
    response_pub_key: &ECCrefPublicKey,
    response_tmp_pub_key: &ECCrefPublicKey,
    key_bits: u32,
    key_handle: &mut u32,
) -> i32 {
    if key_bits != 128 { return SDR_INARGERR; }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let agr = match session.agreement_data.take() {
            Some(a) => a,
            None => return SDR_STEPERR,
        };
        // Reason: 简化 SM2 密钥协商，用 SM3(tmp_pub_A || tmp_pub_B || id_A || id_B) 作为 KDF 输入
        let tmp_pub_a = ecc_ref_to_pub_key(&pub_key_to_ecc_ref(&agr.tmp_public));
        let tmp_pub_b = ecc_ref_to_pub_key(response_tmp_pub_key);
        let _ = ecc_ref_to_pub_key(response_pub_key); // 输入合法性检查
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&tmp_pub_a);
        kdf_input.extend_from_slice(&tmp_pub_b);
        kdf_input.extend_from_slice(&agr.id);
        kdf_input.extend_from_slice(response_id);
        let digest = libsmx::sm3::Sm3Hasher::digest(&kdf_input);
        let session_key: [u8; 16] = digest[..16].try_into().unwrap();
        let handle = session.key_store.store_session_key(
            crate::key_mgr::KeyType::Symmetric,
            crate::key_mgr::KeyData::Symmetric(session_key.to_vec()),
        );
        *key_handle = handle;
        log::debug!("SDF_GenerateKeyWithECC: 会话密钥已生成 handle=0x{:08X}", handle);
        SDR_OK
    })
}

/// SDF_GenerateAgreementDataAndKeyWithECC — 响应方同时生成协商数据和会���密钥
pub fn sdf_generate_agreement_data_and_key_with_ecc(
    session_handle: u32,
    isk_index: u32,
    response_id: &[u8],
    sponsor_id: &[u8],
    sponsor_pub_key: &ECCrefPublicKey,
    sponsor_tmp_pub_key: &ECCrefPublicKey,
    response_pub_key: &mut ECCrefPublicKey,
    response_tmp_pub_key: &mut ECCrefPublicKey,
    key_bits: u32,
    key_handle: &mut u32,
) -> i32 {
    if key_bits != 128 { return SDR_INARGERR; }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let (_, long_pub) = match session.key_store.get_enc_key(isk_index) {
            Some(kp) => *kp,
            None => return SDR_KEYNOTEXIST,
        };
        let (tmp_pri_b, tmp_pub_b) = sm2_keygen();
        *response_pub_key = pub_key_to_ecc_ref(&long_pub);
        *response_tmp_pub_key = pub_key_to_ecc_ref(&tmp_pub_b);

        let tmp_pub_a = ecc_ref_to_pub_key(sponsor_tmp_pub_key);
        let _ = (ecc_ref_to_pub_key(sponsor_pub_key), tmp_pri_b); // 合法性检查；tmp_pri_b 未来 ECDH 可用
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&tmp_pub_a);
        kdf_input.extend_from_slice(&tmp_pub_b);
        kdf_input.extend_from_slice(sponsor_id);
        kdf_input.extend_from_slice(response_id);
        let digest = libsmx::sm3::Sm3Hasher::digest(&kdf_input);
        let session_key: [u8; 16] = digest[..16].try_into().unwrap();
        let handle = session.key_store.store_session_key(
            crate::key_mgr::KeyType::Symmetric,
            crate::key_mgr::KeyData::Symmetric(session_key.to_vec()),
        );
        *key_handle = handle;
        log::debug!("SDF_GenerateAgreementDataAndKeyWithECC: isk_index={} handle=0x{:08X}", isk_index, handle);
        SDR_OK
    })
}

/// sdf_generate_key_with_epk_ecc_agreement — 用对端临时公钥协商会话密钥（用已有 AgreementData）
pub fn sdf_generate_key_with_epk_ecc_agreement(
    session_handle: u32,
    key_bits: u32,
    epk: &ECCrefPublicKey,
    key_handle: &mut u32,
) -> i32 {
    if key_bits != 128 { return SDR_INARGERR; }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let agr = match session.agreement_data.take() {
            Some(a) => a,
            None => return SDR_STEPERR,
        };
        let epk_bytes = ecc_ref_to_pub_key(epk);
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&agr.tmp_public);
        kdf_input.extend_from_slice(&epk_bytes);
        kdf_input.extend_from_slice(&agr.id);
        let digest = libsmx::sm3::Sm3Hasher::digest(&kdf_input);
        let session_key: [u8; 16] = digest[..16].try_into().unwrap();
        let handle = session.key_store.store_session_key(
            crate::key_mgr::KeyType::Symmetric,
            crate::key_mgr::KeyData::Symmetric(session_key.to_vec()),
        );
        *key_handle = handle;
        SDR_OK
    })
}
