// RSA 运算封装（PKCS#1 v1.5 签名/验签、OAEP 加解密、原始 RSA 模幂）
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey, BigUint};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::oaep::Oaep;
use rsa::sha2::Sha256;
use rsa::signature::{Signer, Verifier, SignatureEncoding};
use rsa::traits::{PublicKeyParts, PrivateKeyParts};
use crate::types::{RSArefPublicKey, RSArefPrivateKey};

/// 从 PKCS#8 PEM 字符串加载 RSA 私钥
pub fn rsa_load_private_key(pem: &str) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs8_pem(pem.trim())
        .map_err(|e| format!("RSA 私钥解析失败: {}", e))
}

/// 从 RsaPrivateKey 提取公钥
pub fn rsa_pub_from_priv(priv_key: &RsaPrivateKey) -> RsaPublicKey {
    RsaPublicKey::from(priv_key)
}

/// 将 BigUint 大端右对齐写入固定长度字节数组（高位补零）
fn biguint_to_bytes_right_aligned(n: &BigUint, buf: &mut [u8]) {
    let bytes = n.to_bytes_be();
    let src_len = bytes.len();
    let dst_len = buf.len();
    let copy_len = src_len.min(dst_len);
    // Reason: 大端右对齐，高位补零（已在 buf 初始化为0时自然满足）
    let dst_start = dst_len - copy_len;
    let src_start = src_len - copy_len;
    buf[dst_start..].copy_from_slice(&bytes[src_start..]);
}

/// 将 RsaPublicKey 导出为 RSArefPublicKey（GM/T 0018 格式）
pub fn rsa_pub_to_ref(pub_key: &RsaPublicKey) -> RSArefPublicKey {
    let mut out = RSArefPublicKey { bits: 2048, m: [0u8; 256], e: [0u8; 256] };
    biguint_to_bytes_right_aligned(pub_key.n(), &mut out.m);
    biguint_to_bytes_right_aligned(pub_key.e(), &mut out.e);
    out
}

/// 将 RsaPrivateKey 导出为 RSArefPrivateKey（GM/T 0018 格式）
pub fn rsa_priv_to_ref(priv_key: &RsaPrivateKey) -> RSArefPrivateKey {
    let pub_ref = rsa_pub_to_ref(&rsa_pub_from_priv(priv_key));
    let mut out = RSArefPrivateKey {
        bits: 2048,
        m: pub_ref.m,
        e: pub_ref.e,
        d: [0u8; 256],
        prime: [[0u8; 128]; 2],
        pexp: [[0u8; 128]; 2],
        coef: [0u8; 128],
    };
    biguint_to_bytes_right_aligned(priv_key.d(), &mut out.d);
    let primes = priv_key.primes();
    if primes.len() >= 2 {
        biguint_to_bytes_right_aligned(&primes[0], &mut out.prime[0]);
        biguint_to_bytes_right_aligned(&primes[1], &mut out.prime[1]);
        if let Some(dp) = priv_key.dp() {
            biguint_to_bytes_right_aligned(dp, &mut out.pexp[0]);
        }
        if let Some(dq) = priv_key.dq() {
            biguint_to_bytes_right_aligned(dq, &mut out.pexp[1]);
        }
        // Reason: qinv 为 rsa crate 内部 BigInt 类型，未对外暴露 to_biguint；
        // coef 字段留零，GM/T 0018 不强制依赖该字段做运算
    }
    out
}

/// RSA PKCS#1 v1.5 签名（SHA-256）
pub fn rsa_sign_pkcs1(priv_key: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    let signing_key = SigningKey::<Sha256>::new(priv_key.clone());
    signing_key.sign(data).to_bytes().to_vec()
}

/// RSA PKCS#1 v1.5 验签（SHA-256）
pub fn rsa_verify_pkcs1(pub_key: &RsaPublicKey, data: &[u8], sig_bytes: &[u8]) -> bool {
    use rsa::pkcs1v15::Signature;
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key.clone());
    let Ok(sig) = Signature::try_from(sig_bytes) else { return false; };
    verifying_key.verify(data, &sig).is_ok()
}

/// RSA-OAEP 加密（SHA-256）
pub fn rsa_encrypt_oaep(pub_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, String> {
    use rsa::rand_core::OsRng;
    pub_key.encrypt(&mut OsRng, Oaep::new::<Sha256>(), data)
        .map_err(|e| format!("RSA-OAEP 加密失败: {}", e))
}

/// RSA-OAEP 解密（SHA-256）
pub fn rsa_decrypt_oaep(priv_key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    priv_key.decrypt(Oaep::new::<Sha256>(), ciphertext)
        .map_err(|e| format!("RSA-OAEP 解密失败: {}", e))
}

/// RSA 原始公钥模幂：m^e mod n（用于 PKCS#1 v1.5 等上层协议的手动封装）
pub fn rsa_public_key_op(pub_key: &RsaPublicKey, input: &[u8]) -> Result<Vec<u8>, String> {
    let m = BigUint::from_bytes_be(input);
    if &m >= pub_key.n() {
        return Err("输入超过模数".to_string());
    }
    let result = m.modpow(pub_key.e(), pub_key.n());
    let key_len = (pub_key.n().bits() as usize + 7) / 8;
    let mut out = result.to_bytes_be();
    while out.len() < key_len { out.insert(0, 0u8); }
    Ok(out)
}

/// RSA 原始私钥模幂：c^d mod n（用于 PKCS#1 v1.5 等上层协议的手动封装）
pub fn rsa_private_key_op(priv_key: &RsaPrivateKey, input: &[u8]) -> Result<Vec<u8>, String> {
    let c = BigUint::from_bytes_be(input);
    if &c >= priv_key.n() {
        return Err("输入超过模数".to_string());
    }
    let result = c.modpow(priv_key.d(), priv_key.n());
    let key_len = (priv_key.n().bits() as usize + 7) / 8;
    let mut out = result.to_bytes_be();
    while out.len() < key_len { out.insert(0, 0u8); }
    Ok(out)
}
