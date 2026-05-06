// GM/T 0018 Mock SDK 集成测试
// 通过库公开接口（sdf_impl 层）进行端到端测试
// 不依赖 mock_keys.toml，所有密钥均在测试中临时生成

use std::sync::Mutex;
use sdf_mock::error_code::*;
use sdf_mock::sdf_impl::{
    device::{sdf_open_device, sdf_close_device, sdf_open_session, sdf_close_session, sdf_get_device_info},
    key_manage::{sdf_generate_random, sdf_generate_key_pair_ecc, sdf_destroy_key},
    asymmetric::{sdf_external_sign_ecc, sdf_external_verify_ecc,
                 sdf_external_encrypt_ecc, sdf_external_decrypt_ecc},
    symmetric::{
        sdf_encrypt, sdf_decrypt, sdf_calculate_mac,
        sdf_encrypt_init, sdf_encrypt_update, sdf_encrypt_final,
        sdf_decrypt_init, sdf_decrypt_update, sdf_decrypt_final,
        sdf_auth_enc_init, sdf_auth_enc_update, sdf_auth_enc_final,
        sdf_auth_dec_init, sdf_auth_dec_update, sdf_auth_dec_final,
    },
    hash::{sdf_hash_init, sdf_hash_update, sdf_hash_final,
           sdf_hmac_init, sdf_hmac_update, sdf_hmac_final},
};
use sdf_mock::types::{DEVICEINFO, ECCrefPublicKey, ECCrefPrivateKey, ECCSignature, alg_id};
use sdf_mock::key_mgr::{KeyType, KeyData};
use sdf_mock::sdf_impl::device::with_session;

// 全局序列化锁（设备是单例）
static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn setup() -> u32 {
    // 重置设备状态
    let _ = sdf_close_device();
    assert_eq!(sdf_open_device(), SDR_OK);
    let mut handle = 0u32;
    assert_eq!(sdf_open_session(&mut handle), SDR_OK);
    assert_ne!(handle, 0);
    handle
}

fn teardown(session: u32) {
    let _ = sdf_close_session(session);
    let _ = sdf_close_device();
}

// ── 设备基础 ───────────────────────────────────────────────────

#[test]
fn test_get_device_info() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut info = DEVICEINFO::default();
    assert_eq!(sdf_get_device_info(session, &mut info), SDR_OK);
    // Mock 设备名称应非空
    assert!(info.DeviceName.iter().any(|&b| b != 0));

    teardown(session);
}

#[test]
fn test_generate_random() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut buf = Vec::new();
    assert_eq!(sdf_generate_random(session, 32, &mut buf), SDR_OK);
    assert_eq!(buf.len(), 32);
    // 随机数不应全为零（概率极低）
    assert!(buf.iter().any(|&b| b != 0));

    teardown(session);
}

#[test]
fn test_generate_random_invalid() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut buf = Vec::new();
    // 长度为0 → 参数错误
    assert_eq!(sdf_generate_random(session, 0, &mut buf), SDR_INARGERR);
    // 长度过大
    assert_eq!(sdf_generate_random(session, 5000, &mut buf), SDR_INARGERR);

    teardown(session);
}

// ── SM2 外部签名/验签 ──────────────────────────────────────────

#[test]
fn test_sm2_external_sign_verify() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut pub_key = ECCrefPublicKey::default();
    let mut pri_key = ECCrefPrivateKey::default();
    assert_eq!(
        sdf_generate_key_pair_ecc(session, alg_id::SGD_SM2_1, 256, &mut pub_key, &mut pri_key),
        SDR_OK
    );

    // 待签名数据（32字节哈希值）
    let data = [0xABu8; 32];
    let mut sig = ECCSignature::default();
    assert_eq!(
        sdf_external_sign_ecc(session, alg_id::SGD_SM2_1, &pri_key, &data, &mut sig),
        SDR_OK
    );

    // 验签成功
    assert_eq!(
        sdf_external_verify_ecc(session, alg_id::SGD_SM2_1, &pub_key, &data, &sig),
        SDR_OK
    );

    teardown(session);
}

#[test]
fn test_sm2_verify_wrong_data_fails() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut pub_key = ECCrefPublicKey::default();
    let mut pri_key = ECCrefPrivateKey::default();
    assert_eq!(
        sdf_generate_key_pair_ecc(session, alg_id::SGD_SM2_1, 256, &mut pub_key, &mut pri_key),
        SDR_OK
    );

    let data = [0x11u8; 32];
    let mut sig = ECCSignature::default();
    assert_eq!(
        sdf_external_sign_ecc(session, alg_id::SGD_SM2_1, &pri_key, &data, &mut sig),
        SDR_OK
    );

    // 用不同数据验签 → 失败
    let wrong_data = [0x22u8; 32];
    assert_eq!(
        sdf_external_verify_ecc(session, alg_id::SGD_SM2_1, &pub_key, &wrong_data, &sig),
        SDR_VERIFYERR
    );

    teardown(session);
}

// ── SM2 外部加密/解密 ──────────────────────────────────────────

#[test]
fn test_sm2_external_encrypt_decrypt() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut pub_key = ECCrefPublicKey::default();
    let mut pri_key = ECCrefPrivateKey::default();
    assert_eq!(
        sdf_generate_key_pair_ecc(session, alg_id::SGD_SM2_3, 256, &mut pub_key, &mut pri_key),
        SDR_OK
    );

    let plaintext = b"integration test plaintext";
    let mut cipher = sdf_mock::types::ECCCipher::default();
    assert_eq!(
        sdf_external_encrypt_ecc(session, alg_id::SGD_SM2_3, &pub_key, plaintext, &mut cipher),
        SDR_OK
    );
    assert_eq!(cipher.L as usize, plaintext.len());

    let mut recovered = Vec::new();
    assert_eq!(
        sdf_external_decrypt_ecc(session, alg_id::SGD_SM2_3, &pri_key, &cipher, &mut recovered),
        SDR_OK
    );
    assert_eq!(recovered, plaintext);

    teardown(session);
}

// ── SM3 哈希 ────────────────────────────────────────────────────

#[test]
fn test_sm3_hash() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let data = b"abc";
    assert_eq!(sdf_hash_init(session, alg_id::SGD_SM3, None, b""), SDR_OK);
    assert_eq!(sdf_hash_update(session, data), SDR_OK);

    let mut hash = [0u8; 32];
    assert_eq!(sdf_hash_final(session, &mut hash), SDR_OK);

    // SM3("abc") 已知值
    let expected = hex::decode("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
        .unwrap();
    assert_eq!(&hash, expected.as_slice());

    teardown(session);
}

#[test]
fn test_sm3_hash_incremental() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    // 分块 update 与一次性 update 结果应相同
    assert_eq!(sdf_hash_init(session, alg_id::SGD_SM3, None, b""), SDR_OK);
    assert_eq!(sdf_hash_update(session, b"hel"), SDR_OK);
    assert_eq!(sdf_hash_update(session, b"lo"), SDR_OK);
    let mut hash1 = [0u8; 32];
    assert_eq!(sdf_hash_final(session, &mut hash1), SDR_OK);

    // 重新 Init，一次性 update
    assert_eq!(sdf_hash_init(session, alg_id::SGD_SM3, None, b""), SDR_OK);
    assert_eq!(sdf_hash_update(session, b"hello"), SDR_OK);
    let mut hash2 = [0u8; 32];
    assert_eq!(sdf_hash_final(session, &mut hash2), SDR_OK);

    assert_eq!(hash1, hash2);

    teardown(session);
}

// ── SM4-CBC 加密/解密 ─────────────────────────────────────────

fn make_sym_key(session: u32) -> u32 {
    // 直接向会话注入一个已知 SM4 密钥（绕过 KEK，仅用于测试）
    let key_data = KeyData::Symmetric(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    ]);
    let mut handle = 0u32;
    with_session(session, |res| {
        let s = res.unwrap();
        handle = s.key_store.store_session_key(KeyType::Symmetric, key_data.clone());
        0i32
    });
    handle
}

#[test]
fn test_sm4_cbc_encrypt_decrypt() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    let iv = [0u8; 16];
    let plaintext = b"1234567890ABCDEF"; // 16 字节
    let mut ciphertext = Vec::new();
    assert_eq!(
        sdf_encrypt(session, key_handle, alg_id::SGD_SM4_CBC, &iv, plaintext, &mut ciphertext),
        SDR_OK
    );
    assert_eq!(ciphertext.len(), 16);

    let mut recovered = Vec::new();
    assert_eq!(
        sdf_decrypt(session, key_handle, alg_id::SGD_SM4_CBC, &iv, &ciphertext, &mut recovered),
        SDR_OK
    );
    assert_eq!(&recovered, plaintext);

    let _ = sdf_destroy_key(session, key_handle);
    teardown(session);
}

#[test]
fn test_sm4_ecb_encrypt_decrypt() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    let iv = [0u8; 16];
    let plaintext = b"ABCDEFGHIJKLMNOP"; // 16 字节
    let mut ct = Vec::new();
    assert_eq!(
        sdf_encrypt(session, key_handle, alg_id::SGD_SM4_ECB, &iv, plaintext, &mut ct),
        SDR_OK
    );

    let mut pt = Vec::new();
    assert_eq!(
        sdf_decrypt(session, key_handle, alg_id::SGD_SM4_ECB, &iv, &ct, &mut pt),
        SDR_OK
    );
    assert_eq!(&pt, plaintext);

    let _ = sdf_destroy_key(session, key_handle);
    teardown(session);
}

#[test]
fn test_sm4_ctr_encrypt_decrypt() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    let iv = [0x01u8; 16];
    let plaintext = b"CTR mode test!!"; // 任意长度
    let mut ct = Vec::new();
    assert_eq!(
        sdf_encrypt(session, key_handle, alg_id::SGD_SM4_CTR, &iv, plaintext, &mut ct),
        SDR_OK
    );
    assert_eq!(ct.len(), plaintext.len());

    let mut pt = Vec::new();
    assert_eq!(
        sdf_decrypt(session, key_handle, alg_id::SGD_SM4_CTR, &iv, &ct, &mut pt),
        SDR_OK
    );
    assert_eq!(&pt, plaintext);

    let _ = sdf_destroy_key(session, key_handle);
    teardown(session);
}

// ── CBC-MAC ───────────────────────────────────────────────────

#[test]
fn test_calculate_mac() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    let iv = [0u8; 16];
    let data = [0xFFu8; 32]; // 32 字节
    let mut mac = [0u8; 16];
    assert_eq!(sdf_calculate_mac(session, key_handle, &iv, &data, &mut mac), SDR_OK);
    // MAC 不应全零
    assert!(mac.iter().any(|&b| b != 0));

    // 相同输入，相同 MAC
    let mut mac2 = [0u8; 16];
    assert_eq!(sdf_calculate_mac(session, key_handle, &iv, &data, &mut mac2), SDR_OK);
    assert_eq!(mac, mac2);

    let _ = sdf_destroy_key(session, key_handle);
    teardown(session);
}

// ── HMAC-SM3 ─────────────────────────────────────────────────

#[test]
fn test_hmac_sm3() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    assert_eq!(sdf_hmac_init(session, key_handle, alg_id::SGD_SM3), SDR_OK);
    assert_eq!(sdf_hmac_update(session, b"hello"), SDR_OK);
    assert_eq!(sdf_hmac_update(session, b" world"), SDR_OK);

    let mut mac = [0u8; 32];
    assert_eq!(sdf_hmac_final(session, &mut mac), SDR_OK);
    assert!(mac.iter().any(|&b| b != 0));

    // 相同数据，相同 HMAC
    assert_eq!(sdf_hmac_init(session, key_handle, alg_id::SGD_SM3), SDR_OK);
    assert_eq!(sdf_hmac_update(session, b"hello world"), SDR_OK);
    let mut mac2 = [0u8; 32];
    assert_eq!(sdf_hmac_final(session, &mut mac2), SDR_OK);
    assert_eq!(mac, mac2);

    let _ = sdf_destroy_key(session, key_handle);
    teardown(session);
}

// ── 密钥句柄生命周期 ─────────────────────────────────────────

#[test]
fn test_destroy_key() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    // 正常销毁
    assert_eq!(sdf_destroy_key(session, key_handle), SDR_OK);
    // 重复销毁 → 密钥不存在
    assert_eq!(sdf_destroy_key(session, key_handle), SDR_KEYNOTEXIST);

    teardown(session);
}

// ── 错误路径 ─────────────────────────────────────────────────

#[test]
fn test_ops_without_open_device() {
    let _lock = TEST_MUTEX.lock().unwrap();
    // 确保设备未打开
    let _ = sdf_close_device();

    let mut handle = 0u32;
    // 设备未开，OpenSession 应失败
    assert_eq!(sdf_open_session(&mut handle), SDR_OPENDEVICE);
    assert_eq!(handle, 0);
}

#[test]
fn test_invalid_session_handle() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let bad_handle = 0xDEAD_BEEFu32;
    // 无效会话句柄
    let mut buf = Vec::new();
    assert_eq!(sdf_generate_random(bad_handle, 16, &mut buf), SDR_INARGERR);

    teardown(session);
}

// ── RSA 集成测试 ──────────────────────────────────────────────

const RSA_TEST_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtrXsBmSziEsDs
p6gP5KzhzWlxAAPLsjF3i9yProYU3WqpYoHeh6bDueSasGp4Q32LqMh6IVuihge7
ABqyZ6o3hPC17bEum54dycMXPy6QB8IdGhuKQ9OvUh9Zju8HAYBVcDc4ExQdoC3Z
mmdSFgqr8E45PgqaxpsOGKJZhNacz49Q9AqunB7XBByoxBWm1f6oERapZBT5omKj
sA7YhvcrAPVOGoj0djbDgggv5/I3ExP3e+0VzTlDL+DwTbQhk5fn6FmQvrqEGgmT
lKWE9MSbyLWpyPCzXldFrSdNDFlR0LX6PAw3uIc3q329W7KhdJIYYm5tPenQqA4A
cGk5rZirAgMBAAECggEAMqKE1CBX6YnpRAGr0kb7ddeXIRXJuTmrRDattIaP1h4d
vRxZYpkvs/8EbtgqtphaRMiefTZiGUvIldQ928guAUn3JisPVkic9OepAmjZeKHO
fviy6U/t5yntt9y1m558Qrd3bCDUZkNbwUIdxOUhPOQjJhrLk5HAMs6Yt82PEzTT
ykaABYPL3kT8NnmnLn1CovcAtIg+jz84WTm+SJW9tL7J/NjS6UcbxI4N+vbLPnI1
R1Cj6rq6v+VwOM380zZRr+22XZMbSEbqOEMYhHuR8+T/mSSNgfAb92stPiJ2ZQ3u
ytf2+YHDSS9dykfwPsvgDLsM0lYWxKQpFG43FPlF4QKBgQD7gDPQt8h2rTqmxTsd
SeimRE0jjEJfWHqA4fqkW+Mz7bahLmAI98UhUlmHKBJfMtsnmV4+kChElQgwtwlY
dFslBzapG41ax96jXEwH97lRTk6fTyBQpc+xcJn3xReZYYDStqFgS8UiXewrTrVs
MwWnf85JUexT/M63o2BeX4Px4wKBgQDx7fjqDtAcchYhcgp2La/T0e5+eNQOmkQE
EpECvRtXYZXk3vPk+h/Y+k+V4LExYCmgbkoRUz8hTCFOMqAwYgYoBxl/2FxfkC/D
9kdRUgsu9TFEoVuH6hp51fiDhSypzF5Ww2zfdD5C8wBuh1WEGTUuR41n2+9ACm9d
Bty2RGRYmQKBgQC3FNCjc+Y+XkR/+rvZyl/OCZKN+iCm/+XNxLOMykdPGhEErJnE
bXnXk/cQaJ9XJdJbtU3iBVcK9eKMc/IdrjZbcjDcUe5I047DJQFEG5WQFo0tc5B2
pP3YkbvDnnpbcZsxyTkYvI+5QN4XeKihJ1NKZ8NnpHeBfFuPWyNgD/AhOQKBgA2Z
dviRRJmUwDG5G2VxRAUANAvf9uurOE+SS5x/zN2omqh27/bbKJcl2vtt2ggQg8aE
7Jz0tQPGJ8khh2ew2u+9Fm3dV7P3gvfdDD1CA2bsWYymFWMagcp/gKzD+7K/zj3K
VoBpJGbXChsseF4onJixZP2Fm3laHNB55kZIqethAoGAb2xdslxq6qGyQzjO2qWE
RNxc4NA737FLg7ZfkUXwRobOXj6tNiTqMTkCtyfzDQ0TAsb70xLtPPjplt2aiB43
0wwiKDZ+7oZbAI91HQXJFUGnw8hUmj/DOPbMjXbqNWq10gfLCYuWASok/+ZTaur3
PCFDjos4+kHk9Gll7oBjAQE=
-----END PRIVATE KEY-----"#;

#[test]
fn test_rsa_sign_verify_roundtrip() {
    use sdf_mock::crypto::rsa_ops::{rsa_load_private_key, rsa_pub_from_priv, rsa_sign_pkcs1, rsa_verify_pkcs1};

    let priv_key = rsa_load_private_key(RSA_TEST_PEM).expect("RSA PEM 解析失败");
    let pub_key = rsa_pub_from_priv(&priv_key);
    let data = b"hello RSA signing test";
    let sig = rsa_sign_pkcs1(&priv_key, data);
    assert!(!sig.is_empty());
    assert!(rsa_verify_pkcs1(&pub_key, data, &sig));
    // 篡改数据后验签应失败
    assert!(!rsa_verify_pkcs1(&pub_key, b"tampered", &sig));
}

#[test]
fn test_rsa_encrypt_decrypt_roundtrip() {
    use sdf_mock::crypto::rsa_ops::{rsa_load_private_key, rsa_pub_from_priv, rsa_encrypt_oaep, rsa_decrypt_oaep};

    let priv_key = rsa_load_private_key(RSA_TEST_PEM).expect("RSA PEM 解析失败");
    let pub_key = rsa_pub_from_priv(&priv_key);
    let plaintext = b"RSA OAEP encryption test";
    let ct = rsa_encrypt_oaep(&pub_key, plaintext).expect("RSA OAEP 加密失败");
    let pt = rsa_decrypt_oaep(&priv_key, &ct).expect("RSA OAEP 解密失败");
    assert_eq!(pt, plaintext);
}

#[test]
fn test_rsa_generate_keypair() {
    use sdf_mock::sdf_impl::key_manage::sdf_generate_key_pair_rsa;
    use sdf_mock::types::{RSArefPublicKey, RSArefPrivateKey};

    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut pub_key = RSArefPublicKey { bits: 0, m: [0u8; 256], e: [0u8; 256] };
    let mut pri_key = RSArefPrivateKey { bits: 0, m: [0u8; 256], e: [0u8; 256],
        d: [0u8; 256], prime: [[0u8; 128]; 2], pexp: [[0u8; 128]; 2], coef: [0u8; 128] };
    assert_eq!(sdf_generate_key_pair_rsa(session, 2048, &mut pub_key, &mut pri_key), SDR_OK);
    assert_eq!(pub_key.bits, 2048);
    assert!(pub_key.m.iter().any(|&b| b != 0));

    teardown(session);
}

/// 辅助：注入一个已知 SM4 密钥到会话，返回 key_handle
fn inject_sym_key(session: u32, key_bytes: &[u8; 16]) -> u32 {
    with_session(session, |res| {
        let s = res.unwrap();
        s.key_store.store_session_key(
            KeyType::Symmetric,
            KeyData::Symmetric(key_bytes.to_vec()),
        )
    })
}

#[test]
fn test_stream_encrypt_decrypt_cbc() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let key_bytes = [0x01u8; 16];
    let kh = inject_sym_key(session, &key_bytes);
    let iv = [0x00u8; 16];
    // 31 字节明文，非对齐；Final 应补 PKCS#7 变为 32 字节密文
    let plaintext = b"hello streaming CBC mode test!!";
    assert_eq!(plaintext.len(), 31);

    assert_eq!(sdf_encrypt_init(session, kh, alg_id::SGD_SM4_CBC, &iv), SDR_OK);
    let mut ct1 = Vec::new();
    // 先喂 15 字节，不足一块，Update 输出空
    assert_eq!(sdf_encrypt_update(session, &plaintext[..15], &mut ct1), SDR_OK);
    assert!(ct1.is_empty());
    let mut ct2 = Vec::new();
    // 再喂 16 字节，合计 31 字节，仍不足两块（只有一整块可出），输出16字节
    assert_eq!(sdf_encrypt_update(session, &plaintext[15..], &mut ct2), SDR_OK);
    assert_eq!(ct2.len(), 16);
    let mut ct3 = Vec::new();
    assert_eq!(sdf_encrypt_final(session, &mut ct3), SDR_OK);
    assert_eq!(ct3.len(), 16); // PKCS#7 填充后第二块

    let mut full_ct: Vec<u8> = ct2;
    full_ct.extend_from_slice(&ct3);
    assert_eq!(full_ct.len(), 32);

    // 解密还原
    assert_eq!(sdf_decrypt_init(session, kh, alg_id::SGD_SM4_CBC, &iv), SDR_OK);
    let mut pt1 = Vec::new();
    assert_eq!(sdf_decrypt_update(session, &full_ct[..16], &mut pt1), SDR_OK);
    // 解密 Update 保留最后一块（用于 Final 去padding），所以这里 pt1 为空
    assert!(pt1.is_empty());
    let mut pt2 = Vec::new();
    assert_eq!(sdf_decrypt_update(session, &full_ct[16..], &mut pt2), SDR_OK);
    assert_eq!(pt2.len(), 16);
    let mut pt3 = Vec::new();
    assert_eq!(sdf_decrypt_final(session, &mut pt3), SDR_OK);
    // pt3 是最后一块去 padding 后的内容（31 - 16 = 15 字节）
    assert_eq!(pt3.len(), 15);

    let mut recovered: Vec<u8> = pt2;
    recovered.extend_from_slice(&pt3);
    assert_eq!(recovered, plaintext);

    assert_eq!(sdf_destroy_key(session, kh), SDR_OK);
    teardown(session);
}

#[test]
fn test_stream_step_error() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let kh = inject_sym_key(session, &[0u8; 16]);
    let iv = [0u8; 16];

    // 未 Init 直接 Update → STEPERR
    let mut out = Vec::new();
    assert_eq!(sdf_encrypt_update(session, b"data", &mut out), SDR_STEPERR);
    // 未 Init 直接 Final → STEPERR
    assert_eq!(sdf_encrypt_final(session, &mut out), SDR_STEPERR);

    // 正常 Init 后，不能再次 Init（already active）
    assert_eq!(sdf_encrypt_init(session, kh, alg_id::SGD_SM4_CBC, &iv), SDR_OK);
    assert_eq!(sdf_encrypt_init(session, kh, alg_id::SGD_SM4_CBC, &iv), SDR_STEPERR);
    // 清理：Final 结束流式状态
    let mut _dummy = Vec::new();
    assert_eq!(sdf_encrypt_final(session, &mut _dummy), SDR_OK);

    assert_eq!(sdf_destroy_key(session, kh), SDR_OK);
    teardown(session);
}

#[test]
fn test_stream_gcm_roundtrip() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let kh = inject_sym_key(session, &[0xAAu8; 16]);
    let nonce = [0x01u8; 12];
    let aad = b"header";
    let plaintext = b"GCM streaming test data";

    assert_eq!(sdf_auth_enc_init(session, kh, &nonce, aad), SDR_OK);
    assert_eq!(sdf_auth_enc_update(session, plaintext), SDR_OK);
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    assert_eq!(sdf_auth_enc_final(session, &mut ct, &mut tag), SDR_OK);
    assert_eq!(ct.len(), plaintext.len());

    assert_eq!(sdf_auth_dec_init(session, kh, &nonce, aad, &tag), SDR_OK);
    assert_eq!(sdf_auth_dec_update(session, &ct), SDR_OK);
    let mut pt = Vec::new();
    assert_eq!(sdf_auth_dec_final(session, &mut pt), SDR_OK);
    assert_eq!(pt, plaintext);

    assert_eq!(sdf_destroy_key(session, kh), SDR_OK);
    teardown(session);
}
