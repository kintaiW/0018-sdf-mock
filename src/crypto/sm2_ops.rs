// SM2 算法封装
// 对 libsmx 的 SM2 接口进行薄封装，适配 GM/T 0018 的数据结构格式

use libsmx::sm2;
use libsmx::sm3;
use rand::rngs::OsRng;
use crate::types::{ECCrefPublicKey, ECCrefPrivateKey, ECCCipher, ECCSignature};

/// 生成 SM2 密钥对
pub fn sm2_keygen() -> ([u8; 32], [u8; 65]) {
    let (pri_key, pub_key) = sm2::generate_keypair(&mut OsRng);
    let mut pri_bytes = [0u8; 32];
    pri_bytes.copy_from_slice(pri_key.as_bytes());
    (pri_bytes, pub_key)
}

/// libsmx 公钥（65字节 04||x||y）→ GM/T 0018 ECCrefPublicKey（x/y 各64字节右对齐）
pub fn pub_key_to_ecc_ref(pub_key: &[u8; 65]) -> ECCrefPublicKey {
    let mut ecc_pub = ECCrefPublicKey::default();
    ecc_pub.x[32..64].copy_from_slice(&pub_key[1..33]);
    ecc_pub.y[32..64].copy_from_slice(&pub_key[33..65]);
    ecc_pub
}

/// GM/T 0018 ECCrefPublicKey → libsmx 公钥（65字节 04||x||y）
pub fn ecc_ref_to_pub_key(ecc_pub: &ECCrefPublicKey) -> [u8; 65] {
    let mut pub_key = [0u8; 65];
    pub_key[0] = 0x04;
    pub_key[1..33].copy_from_slice(&ecc_pub.x[32..64]);
    pub_key[33..65].copy_from_slice(&ecc_pub.y[32..64]);
    pub_key
}

/// libsmx 私钥（32字节）→ GM/T 0018 ECCrefPrivateKey（K 字段64字节右对齐）
pub fn pri_key_to_ecc_ref(pri_key: &[u8; 32]) -> ECCrefPrivateKey {
    let mut ecc_pri = ECCrefPrivateKey::default();
    ecc_pri.K[32..64].copy_from_slice(pri_key);
    ecc_pri
}

/// GM/T 0018 ECCrefPrivateKey → libsmx 私钥（32字节，取 K 字段后32字节）
pub fn ecc_ref_to_pri_key(ecc_pri: &ECCrefPrivateKey) -> [u8; 32] {
    ecc_pri.K[32..64].try_into().unwrap()
}

/// SM2 签名（完整 Z 值流程）
/// 内部手动计算 Z 和 e 值，再对 e 签名
pub fn sm2_sign_full(
    pri_key: &[u8; 32],
    pub_key: &[u8; 65],
    data: &[u8],
    id: &[u8],
) -> Result<ECCSignature, String> {
    let pk = sm2::PrivateKey::from_bytes(pri_key)
        .map_err(|_| "私钥无效".to_string())?;
    // 计算 Z = SM3(ENTL||ID||a||b||Gx||Gy||Px||Py)
    let z = sm2::get_z(id, pub_key);
    // 计算 e = SM3(Z||M)
    // Reason: libsmx get_e 参数顺序为 (&z, msg)，与 gm-sdk-rs 的 (msg, &z) 相反
    let e = sm2::get_e(&z, data);

    let sig_bytes = sm2::sign(&e, &pk, &mut OsRng);

    let mut sig = ECCSignature::default();
    sig.r[32..64].copy_from_slice(&sig_bytes[..32]);
    sig.s[32..64].copy_from_slice(&sig_bytes[32..]);
    Ok(sig)
}

/// SM2 验签（完整 Z 值流程）
pub fn sm2_verify_full(
    pub_key: &[u8; 65],
    data: &[u8],
    id: &[u8],
    sig: &ECCSignature,
) -> bool {
    let z = sm2::get_z(id, pub_key);
    let e = sm2::get_e(&z, data);

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r[32..64]);
    sig_bytes[32..].copy_from_slice(&sig.s[32..64]);

    sm2::verify(&e, pub_key, &sig_bytes).is_ok()
}

/// SM2 外部密钥签名（对数据做 SM3 哈希后签名���不含 Z 值）
pub fn sm2_ext_sign(pri_key: &[u8; 32], data: &[u8]) -> ECCSignature {
    // Reason: libsmx sign() 接受预哈希的 e 值（32字节），需先做 SM3
    let e = sm3::Sm3Hasher::digest(data);
    let pk = sm2::PrivateKey::from_bytes(pri_key).expect("私钥无效");
    let sig_bytes = sm2::sign(&e, &pk, &mut OsRng);
    let mut sig = ECCSignature::default();
    sig.r[32..64].copy_from_slice(&sig_bytes[..32]);
    sig.s[32..64].copy_from_slice(&sig_bytes[32..]);
    sig
}

/// SM2 外部密钥验签
pub fn sm2_ext_verify(pub_key: &[u8; 65], data: &[u8], sig: &ECCSignature) -> bool {
    let e = sm3::Sm3Hasher::digest(data);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r[32..64]);
    sig_bytes[32..].copy_from_slice(&sig.s[32..64]);
    sm2::verify(&e, pub_key, &sig_bytes).is_ok()
}

/// SM2 公钥加密 → GM/T 0018 ECCCipher
/// libsmx 输出格式：C1(65) || C3(32) || C2(变长)
pub fn sm2_enc(pub_key: &[u8; 65], plaintext: &[u8]) -> Result<ECCCipher, String> {
    if plaintext.len() > 136 {
        return Err(format!("明文最大136字节，实际{}字节", plaintext.len()));
    }
    let raw = sm2::encrypt(pub_key, plaintext, &mut OsRng)
        .map_err(|e| format!("SM2 加密失败: {:?}", e))?;
    if raw.len() < 97 {
        return Err("加密输出长度不足".to_string());
    }
    let mut cipher = ECCCipher::default();
    cipher.x[32..64].copy_from_slice(&raw[1..33]);
    cipher.y[32..64].copy_from_slice(&raw[33..65]);
    cipher.M.copy_from_slice(&raw[65..97]);
    let c2 = &raw[97..];
    cipher.L = c2.len() as u32;
    cipher.C[..c2.len()].copy_from_slice(c2);
    Ok(cipher)
}

/// SM2 私钥解密（输入 GM/T 0018 ECCCipher）
pub fn sm2_dec(pri_key: &[u8; 32], cipher: &ECCCipher) -> Option<Vec<u8>> {
    let c2_len = cipher.L as usize;
    if c2_len > 136 {
        return None;
    }
    let pk = sm2::PrivateKey::from_bytes(pri_key).ok()?;
    // 重组为 libsmx 格式：C1(65) || C3(32) || C2
    let mut raw = Vec::with_capacity(65 + 32 + c2_len);
    raw.push(0x04);
    raw.extend_from_slice(&cipher.x[32..64]);
    raw.extend_from_slice(&cipher.y[32..64]);
    raw.extend_from_slice(&cipher.M);
    raw.extend_from_slice(&cipher.C[..c2_len]);
    sm2::decrypt(&pk, &raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_conversion_roundtrip() {
        let (pri, pub_key) = sm2_keygen();
        let ecc_pub = pub_key_to_ecc_ref(&pub_key);
        let pub_back = ecc_ref_to_pub_key(&ecc_pub);
        assert_eq!(pub_key, pub_back);

        let ecc_pri = pri_key_to_ecc_ref(&pri);
        let pri_back = ecc_ref_to_pri_key(&ecc_pri);
        assert_eq!(pri, pri_back);
    }

    #[test]
    fn test_sm2_ext_sign_verify() {
        let (pri, pub_key) = sm2_keygen();
        let data = b"external sign test";
        let sig = sm2_ext_sign(&pri, data);
        assert!(sm2_ext_verify(&pub_key, data, &sig));
    }

    #[test]
    fn test_sm2_encrypt_decrypt_roundtrip() {
        let (pri, pub_key) = sm2_keygen();
        let plaintext = b"test encrypt";
        let cipher = sm2_enc(&pub_key, plaintext).unwrap();
        let decrypted = sm2_dec(&pri, &cipher).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
