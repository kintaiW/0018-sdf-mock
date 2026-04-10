// 哈希接口实现
// SDF_HashInit / SDF_HashUpdate / SDF_HashFinal / SDF_HMACInit / SDF_HMACUpdate / SDF_HMACFinal

use crate::error_code::*;
use crate::sdf_impl::device::with_session;
use crate::key_mgr::{KeyData, session::{HashCtx, HmacCtx}};
use crate::crypto::sm3_ops::{Sm3State, sm3_digest, hmac_sm3_digest};
use crate::types::alg_id;

/// SDF_HashInit — 初始化哈希运算
/// alg: SGD_SM3
/// pub_key: 可选，SM2 公钥（用于计算 Z 值；不需要时传 None）
/// id: 用户身份标识（计算 Z 值时使用）
pub fn sdf_hash_init(
    session_handle: u32,
    alg: u32,
    pub_key: Option<&crate::types::ECCrefPublicKey>,
    id: &[u8],
) -> i32 {
    if alg != alg_id::SGD_SM3 {
        return SDR_ALGNOTSUPPORT;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let mut state = Sm3State::new();

        // 若提供了公钥，计算 Z 值并预先写入 SM3 状态
        // Reason: SM3WithSM2 签名时，哈希输入为 Z || M
        let pk_bytes = pub_key.map(|pk| {
            use crate::crypto::sm2_ops::ecc_ref_to_pub_key;
            ecc_ref_to_pub_key(pk)
        });

        if let Some(pk) = pk_bytes {
            use libsmx::sm2::get_z;
            let z = get_z(id, &pk);
            state.update(&z);
        }

        session.hash_ctx = Some(HashCtx {
            state,
            alg_id: alg,
            pub_key: pub_key.map(|pk| {
                use crate::crypto::sm2_ops::ecc_ref_to_pub_key;
                ecc_ref_to_pub_key(pk)
            }),
        });
        log::debug!("SDF_HashInit: alg=0x{:08X}", alg);
        SDR_OK
    })
}

/// SDF_HashUpdate — 追加哈希数据
pub fn sdf_hash_update(session_handle: u32, data: &[u8]) -> i32 {
    if data.is_empty() {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match &mut session.hash_ctx {
            Some(ctx) => {
                ctx.state.update(data);
                log::debug!("SDF_HashUpdate: {} 字节", data.len());
                SDR_OK
            }
            None => {
                log::warn!("SDF_HashUpdate: 哈希未初始化");
                SDR_STEPERR
            }
        }
    })
}

/// SDF_HashFinal — 完成哈希运算，返回摘要
pub fn sdf_hash_final(session_handle: u32, hash: &mut [u8; 32]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match session.hash_ctx.take() {
            Some(ctx) => {
                *hash = ctx.state.finalize();
                log::debug!("SDF_HashFinal: 完成");
                SDR_OK
            }
            None => {
                log::warn!("SDF_HashFinal: 哈希未初始化");
                SDR_STEPERR
            }
        }
    })
}

/// SDF_HMACInit — 初始化 HMAC-SM3 运算
pub fn sdf_hmac_init(session_handle: u32, key_handle: u32, _alg: u32) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        // 检查密钥句柄有效性
        if session.key_store.get_session_key(key_handle).is_none() {
            return SDR_KEYNOTEXIST;
        }
        session.hmac_ctx = Some(HmacCtx {
            key_handle,
            buffer: Vec::new(),
        });
        log::debug!("SDF_HMACInit: key_handle=0x{:08X}", key_handle);
        SDR_OK
    })
}

/// SDF_HMACUpdate — 追加 HMAC 数据
pub fn sdf_hmac_update(session_handle: u32, data: &[u8]) -> i32 {
    if data.is_empty() {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match &mut session.hmac_ctx {
            Some(ctx) => {
                ctx.buffer.extend_from_slice(data);
                SDR_OK
            }
            None => SDR_STEPERR,
        }
    })
}

/// SDF_HMACFinal — 完成 HMAC 运算
pub fn sdf_hmac_final(session_handle: u32, mac: &mut [u8; 32]) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let hmac_ctx = match session.hmac_ctx.take() {
            Some(c) => c,
            None => return SDR_STEPERR,
        };
        let key_handle = hmac_ctx.key_handle;
        let data = hmac_ctx.buffer;

        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match &entry.data {
            KeyData::Symmetric(v) => v.clone(),
            _ => return SDR_KEYTYPEERR,
        };
        *mac = hmac_sm3_digest(&key, &data);
        log::debug!("SDF_HMACFinal: 完成");
        SDR_OK
    })
}
