// SM4 算法封装
// 封装 libsmx 的 SM4 多种模式，适配 GM/T 0018 SDF 接口

use libsmx::sm4::{
    sm4_encrypt_ecb, sm4_decrypt_ecb,
    sm4_encrypt_cbc, sm4_decrypt_cbc,
    sm4_encrypt_cfb, sm4_decrypt_cfb,
    sm4_crypt_ofb,
    sm4_crypt_ctr,
    sm4_encrypt_gcm, sm4_decrypt_gcm,
    sm4_encrypt_ccm, sm4_decrypt_ccm,
};
use crate::types::alg_id;

/// SM4 加密（根据算法标识分发）
/// key: 16字节密钥
/// iv: 16字节 IV（ECB 模式忽略）
/// alg: 算法标识（SGD_SM4_xxx）
/// data: 明文（ECB/CBC 需16字节对齐，无填充模式）
pub fn sm4_encrypt(key: &[u8; 16], iv: &[u8; 16], alg: u32, data: &[u8]) -> Result<Vec<u8>, String> {
    match alg {
        alg_id::SGD_SM4_ECB => Ok(sm4_encrypt_ecb(key, data)),
        alg_id::SGD_SM4_CBC => {
            if data.len() % 16 != 0 {
                return Err(format!("CBC 模式数据长度必须为16的倍数，实际{}字节", data.len()));
            }
            Ok(sm4_encrypt_cbc(key, iv, data))
        }
        alg_id::SGD_SM4_CFB => Ok(sm4_encrypt_cfb(key, iv, data)),
        // Reason: OFB/CTR 为自反模式，libsmx 使用同一函数加解密，返回 Vec<u8>
        alg_id::SGD_SM4_OFB => Ok(sm4_crypt_ofb(key, iv, data)),
        alg_id::SGD_SM4_CTR => Ok(sm4_crypt_ctr(key, iv, data)),
        _ => Err(format!("不支持的 SM4 算法标识: 0x{:08X}", alg)),
    }
}

/// SM4 解密（根据算法标识分发）
pub fn sm4_decrypt(key: &[u8; 16], iv: &[u8; 16], alg: u32, data: &[u8]) -> Result<Vec<u8>, String> {
    match alg {
        alg_id::SGD_SM4_ECB => Ok(sm4_decrypt_ecb(key, data)),
        alg_id::SGD_SM4_CBC => {
            if data.len() % 16 != 0 {
                return Err(format!("CBC 模式数据长度必须为16的倍数，实际{}字节", data.len()));
            }
            Ok(sm4_decrypt_cbc(key, iv, data))
        }
        alg_id::SGD_SM4_CFB => Ok(sm4_decrypt_cfb(key, iv, data)),
        alg_id::SGD_SM4_OFB => Ok(sm4_crypt_ofb(key, iv, data)),
        alg_id::SGD_SM4_CTR => Ok(sm4_crypt_ctr(key, iv, data)),
        _ => Err(format!("不支持的 SM4 算法标识: 0x{:08X}", alg)),
    }
}

/// SM4-GCM AEAD 加密
/// nonce: 12字节
/// aad: 附加认证数据
/// 返回: (密文, 16字节认证标签)
pub fn sm4_gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // Reason: libsmx 参数顺序 (key, nonce, aad, plaintext)，tag 返回 [u8;16]
    sm4_encrypt_gcm(key, nonce, aad, plaintext)
}

/// SM4-GCM AEAD 解密
pub fn sm4_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, String> {
    sm4_decrypt_gcm(key, nonce, aad, ciphertext, tag)
        .map_err(|e| format!("SM4-GCM 解密失败: {:?}", e))
}

/// SM4-CCM AEAD 加密
/// nonce: 12字节
/// tag_len: 认证标签长度（4/6/8/10/12/14/16）
/// 返回: 密文 || 认证标签
pub fn sm4_ccm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Vec<u8> {
    // Reason: libsmx 的 sm4_encrypt_ccm 返回 Result，此处 panic 仅在 tag_len 非法时触发
    sm4_encrypt_ccm(key, nonce, aad, plaintext, tag_len)
        .expect("SM4-CCM 加密参数非法")
}

/// SM4-CCM AEAD 解密
pub fn sm4_ccm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, String> {
    sm4_decrypt_ccm(key, nonce, aad, ciphertext_with_tag, tag_len)
        .map_err(|e| format!("SM4-CCM 解密失败: {:?}", e))
}

/// SM4-CBC-MAC（消息认证码）
/// 使用 CBC 模式，取最后一块密文作为 MAC
pub fn sm4_cbc_mac(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<[u8; 16], String> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(format!("MAC 计算数据长度必须为16的整倍数，实际{}字节", data.len()));
    }
    let out = sm4_encrypt_cbc(key, iv, data);
    // 取最后16字节作为 MAC
    let mac: [u8; 16] = out[out.len()-16..].try_into().unwrap();
    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 16] {
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
         0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10]
    }

    fn iv() -> [u8; 16] { [0u8; 16] }

    #[test]
    fn test_sm4_ecb_roundtrip() {
        let plaintext = [0x01u8; 16];
        let ct = sm4_encrypt(&key(), &iv(), alg_id::SGD_SM4_ECB, &plaintext).unwrap();
        let pt = sm4_decrypt(&key(), &iv(), alg_id::SGD_SM4_ECB, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_sm4_cbc_roundtrip() {
        let plaintext = [0x02u8; 32];
        let ct = sm4_encrypt(&key(), &iv(), alg_id::SGD_SM4_CBC, &plaintext).unwrap();
        let pt = sm4_decrypt(&key(), &iv(), alg_id::SGD_SM4_CBC, &ct).unwrap();
        assert_eq!(pt, plaintext.to_vec());
    }

    #[test]
    fn test_sm4_gcm_roundtrip() {
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello gcm world";
        let (ct, tag) = sm4_gcm_encrypt(&key(), &nonce, aad, plaintext);
        let pt = sm4_gcm_decrypt(&key(), &nonce, aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_sm4_cbc_unaligned_fails() {
        let result = sm4_encrypt(&key(), &iv(), alg_id::SGD_SM4_CBC, b"short");
        assert!(result.is_err());
    }
}
