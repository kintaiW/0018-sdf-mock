// SM2 算法封装
// 对 libsmx 的 SM2 接口进行薄封装，适配 GM/T 0018 的数据结构格式

use libsmx::sm2::{
    generate_keypair,
    get_z, get_e,
    sign, verify,
    encrypt, decrypt,
    PrivateKey,
};
use rand::rngs::OsRng;
use crate::types::{ECCrefPublicKey, ECCrefPrivateKey, ECCCipher, ECCSignature};

/// 生成 SM2 密钥对
/// 返回 (私钥32字节, 公钥65字节 04||x||y)，保持与上层接口兼容
pub fn sm2_keygen() -> ([u8; 32], [u8; 65]) {
    let mut rng = OsRng;
    let (pri, pub_key) = generate_keypair(&mut rng);
    (*pri.as_bytes(), pub_key)
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
/// 内部使用 get_z + get_e + sign，再提取 r/s 填入 ECCSignature
pub fn sm2_sign_full(
    pri_key: &[u8; 32],
    pub_key: &[u8; 65],
    data: &[u8],
    id: &[u8],
) -> Result<ECCSignature, String> {
    let pri = PrivateKey::from_bytes(pri_key)
        .map_err(|e| format!("私钥无效: {:?}", e))?;

    // 计算 Z = SM3(ENTL||ID||a||b||Gx||Gy||Px||Py)
    let z = get_z(id, pub_key);
    // 计算 e = SM3(Z||M)
    // Reason: libsmx 的 get_e 参数顺序是 (z, msg)，与旧版 gm-sdk-rs 相同
    let e = get_e(&z, data);

    let mut rng = OsRng;
    // sign 返回 [u8; 64]（r||s 各32字节）
    let sig_bytes = sign(&e, &pri, &mut rng);

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
    let z = get_z(id, pub_key);
    let e = get_e(&z, data);

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r[32..64]);
    sig_bytes[32..].copy_from_slice(&sig.s[32..64]);

    // verify 返回 Result<(), Error>，转换为 bool
    verify(&e, pub_key, &sig_bytes).is_ok()
}

/// SM2 外部密钥签名（对数据做 SM3 哈希后签名，不含 Z 值）
pub fn sm2_ext_sign(pri_key: &[u8; 32], data: &[u8]) -> ECCSignature {
    let pri = PrivateKey::from_bytes(pri_key).expect("私钥无效");
    // Reason: ext_sign 不走 Z 值流程，直接以 SM3(data) 作为消息摘要 e 签名
    let e = libsmx::sm3::Sm3Hasher::digest(data);
    let mut rng = OsRng;
    let sig_bytes = sign(&e, &pri, &mut rng);
    let mut sig = ECCSignature::default();
    sig.r[32..64].copy_from_slice(&sig_bytes[..32]);
    sig.s[32..64].copy_from_slice(&sig_bytes[32..]);
    sig
}

/// SM2 外部密钥验签
pub fn sm2_ext_verify(pub_key: &[u8; 65], data: &[u8], sig: &ECCSignature) -> bool {
    let e = libsmx::sm3::Sm3Hasher::digest(data);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r[32..64]);
    sig_bytes[32..].copy_from_slice(&sig.s[32..64]);
    verify(&e, pub_key, &sig_bytes).is_ok()
}

/// SM2 公钥加密 → GM/T 0018 ECCCipher
/// libsmx 输出格式：C1(65) || C3(32) || C2(变长)，与旧版一致
/// BREAKING(0.2.0): ECCCipher.C 最大128字节，与真实 SDK ABI 对齐
pub fn sm2_enc(pub_key: &[u8; 65], plaintext: &[u8]) -> Result<ECCCipher, String> {
    if plaintext.len() > 128 {
        return Err(format!("明文最大128字节，实际{}字节", plaintext.len()));
    }
    let mut rng = OsRng;
    let raw = encrypt(pub_key, plaintext, &mut rng)
        .map_err(|e| format!("SM2加密失败: {:?}", e))?;
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
    let pri = PrivateKey::from_bytes(pri_key).ok()?;
    let c2_len = cipher.L as usize;
    if c2_len > 128 {
        return None;
    }
    // 重组为 libsmx 格式：C1(65) || C3(32) || C2
    let mut raw = Vec::with_capacity(65 + 32 + c2_len);
    raw.push(0x04);
    raw.extend_from_slice(&cipher.x[32..64]);
    raw.extend_from_slice(&cipher.y[32..64]);
    raw.extend_from_slice(&cipher.M);
    raw.extend_from_slice(&cipher.C[..c2_len]);
    decrypt(&pri, &raw).ok()
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
