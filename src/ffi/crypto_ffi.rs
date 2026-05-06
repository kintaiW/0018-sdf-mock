// 运算 FFI 导出（非对称、对称、哈希）
use std::os::raw::{c_int, c_void, c_uint, c_uchar};
use crate::error_code::SDR_INARGERR;
use crate::types::{ECCrefPublicKey, ECCrefPrivateKey, ECCCipher, ECCSignature};
use crate::sdf_impl::{
    asymmetric::*,
    symmetric::{
        sdf_encrypt, sdf_decrypt, sdf_calculate_mac, sdf_auth_enc, sdf_auth_dec,
        sdf_encrypt_init, sdf_encrypt_update, sdf_encrypt_final,
        sdf_decrypt_init, sdf_decrypt_update, sdf_decrypt_final,
        sdf_calculate_mac_init, sdf_calculate_mac_update, sdf_calculate_mac_final,
        sdf_auth_enc_init, sdf_auth_enc_update, sdf_auth_enc_final,
        sdf_auth_dec_init, sdf_auth_dec_update, sdf_auth_dec_final,
    },
    hash::*,
};

// ──────────────── ECCCipher 柔性数组适配辅助函数 ────────────────
// Reason: C 侧标准 ECCCipher.C 是柔性数组（大小=1），Rust 侧 ECCCipher.C 是 C[136]。
// 两者 sizeof 不同（C=168, Rust=300），不能整体 memcpy/deref 赋值，
// 必须逐字段操作，否则写出时会栈溢出，读入时读到垃圾数据。

/// 将 Rust ECCCipher 逐字段写入 C 侧指针（安全写出 L 字节的 C 数据）
pub(crate) unsafe fn ecc_cipher_write_to_c(src: &ECCCipher, dst: *mut ECCCipher) {
    std::ptr::copy_nonoverlapping(src.x.as_ptr(), (*dst).x.as_mut_ptr(), 64);
    std::ptr::copy_nonoverlapping(src.y.as_ptr(), (*dst).y.as_mut_ptr(), 64);
    std::ptr::copy_nonoverlapping(src.M.as_ptr(), (*dst).M.as_mut_ptr(), 32);
    (*dst).L = src.L;
    // 写 C 字段：C 紧跟在 L 之后，通过指针算术寻址（绕过柔性数组大小限制）
    let c_ptr = (dst as *mut u8).add(std::mem::offset_of!(ECCCipher, C));
    std::ptr::copy_nonoverlapping(src.C.as_ptr(), c_ptr, src.L as usize);
}

/// 从 C 侧指针读入 ECCCipher 到 Rust 结构（安全读入 L 字节的 C 数据）
pub(crate) unsafe fn ecc_cipher_read_from_c(src: *const ECCCipher) -> ECCCipher {
    let mut dst = ECCCipher::default();
    std::ptr::copy_nonoverlapping((*src).x.as_ptr(), dst.x.as_mut_ptr(), 64);
    std::ptr::copy_nonoverlapping((*src).y.as_ptr(), dst.y.as_mut_ptr(), 64);
    std::ptr::copy_nonoverlapping((*src).M.as_ptr(), dst.M.as_mut_ptr(), 32);
    dst.L = (*src).L;
    let c_len = (dst.L as usize).min(128);
    let c_ptr = (src as *const u8).add(std::mem::offset_of!(ECCCipher, C));
    std::ptr::copy_nonoverlapping(c_ptr, dst.C.as_mut_ptr(), c_len);
    dst
}

// ──────────────── 非对称运算 ────────────────

/// SDF_ExternalSign_ECC
#[no_mangle]
pub extern "C" fn SDF_ExternalSign_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    pucPrivateKey: *const ECCrefPrivateKey,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucSignature: *mut ECCSignature,
) -> c_int {
    if pucPrivateKey.is_null() || pucData.is_null() || pucSignature.is_null() {
        return SDR_INARGERR;
    }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    unsafe {
        sdf_external_sign_ecc(handle, uiAlgID, &*pucPrivateKey, data, &mut *pucSignature)
    }
}

/// SDF_ExternalVerify_ECC
#[no_mangle]
pub extern "C" fn SDF_ExternalVerify_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    pucPublicKey: *const ECCrefPublicKey,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucSignature: *const ECCSignature,
) -> c_int {
    if pucPublicKey.is_null() || pucData.is_null() || pucSignature.is_null() {
        return SDR_INARGERR;
    }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    unsafe {
        sdf_external_verify_ecc(handle, uiAlgID, &*pucPublicKey, data, &*pucSignature)
    }
}

/// SDF_InternalSign_ECC
#[no_mangle]
pub extern "C" fn SDF_InternalSign_ECC(
    hSessionHandle: *mut c_void,
    uiISKIndex: c_uint,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucSignature: *mut ECCSignature,
) -> c_int {
    if pucData.is_null() || pucSignature.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    unsafe { sdf_internal_sign_ecc(handle, uiISKIndex, data, &mut *pucSignature) }
}

/// SDF_InternalVerify_ECC
#[no_mangle]
pub extern "C" fn SDF_InternalVerify_ECC(
    hSessionHandle: *mut c_void,
    uiIPKIndex: c_uint,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucSignature: *const ECCSignature,
) -> c_int {
    if pucData.is_null() || pucSignature.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    unsafe { sdf_internal_verify_ecc(handle, uiIPKIndex, data, &*pucSignature) }
}

/// SDF_ExternalEncrypt_ECC
#[no_mangle]
pub extern "C" fn SDF_ExternalEncrypt_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    pucPublicKey: *const ECCrefPublicKey,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucEncData: *mut ECCCipher,
) -> c_int {
    if pucPublicKey.is_null() || pucData.is_null() || pucEncData.is_null() {
        return SDR_INARGERR;
    }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    // Reason: C 侧 ECCCipher.C 是柔性数组（C[1]），大小与 Rust ECCCipher.C[136] 不同，
    // 不能整体赋值，必须逐字段写入，避免栈溢出
    let mut cipher = ECCCipher::default();
    let ret = unsafe {
        sdf_external_encrypt_ecc(handle, uiAlgID, &*pucPublicKey, data, &mut cipher)
    };
    if ret == 0 {
        unsafe { ecc_cipher_write_to_c(&cipher, pucEncData); }
    }
    ret
}

/// SDF_ExternalDecrypt_ECC
#[no_mangle]
pub extern "C" fn SDF_ExternalDecrypt_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    pucPrivateKey: *const ECCrefPrivateKey,
    pucEncData: *const ECCCipher,
    pucData: *mut c_uchar,
    puiDataLength: *mut c_uint,
) -> c_int {
    if pucPrivateKey.is_null() || pucEncData.is_null() || pucData.is_null() || puiDataLength.is_null() {
        return SDR_INARGERR;
    }
    let handle = hSessionHandle as usize as u32;
    // Reason: 从 C 侧柔性数组安全读入 ECCCipher，不做整体 deref
    let cipher = unsafe { ecc_cipher_read_from_c(pucEncData) };
    let mut plaintext = Vec::new();
    let ret = unsafe {
        sdf_external_decrypt_ecc(handle, uiAlgID, &*pucPrivateKey, &cipher, &mut plaintext)
    };
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(plaintext.as_ptr(), pucData, plaintext.len());
            *puiDataLength = plaintext.len() as c_uint;
        }
    }
    ret
}

// ──────────────── 对称运算 ────────────────

/// SDF_Encrypt
#[no_mangle]
pub extern "C" fn SDF_Encrypt(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucIV: *const c_uchar,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucEncData: *mut c_uchar,
    puiEncDataLength: *mut c_uint,
) -> c_int {
    if pucData.is_null() || pucEncData.is_null() || puiEncDataLength.is_null() {
        return SDR_INARGERR;
    }
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let iv: [u8; 16] = if pucIV.is_null() {
        [0u8; 16]
    } else {
        unsafe { std::slice::from_raw_parts(pucIV, 16).try_into().unwrap() }
    };
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    let mut ct = Vec::new();
    let ret = sdf_encrypt(session, key, uiAlgID, &iv, data, &mut ct);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(ct.as_ptr(), pucEncData, ct.len());
            *puiEncDataLength = ct.len() as c_uint;
        }
    }
    ret
}

/// SDF_Decrypt
#[no_mangle]
pub extern "C" fn SDF_Decrypt(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucIV: *const c_uchar,
    pucEncData: *const c_uchar,
    uiEncDataLength: c_uint,
    pucData: *mut c_uchar,
    puiDataLength: *mut c_uint,
) -> c_int {
    if pucEncData.is_null() || pucData.is_null() || puiDataLength.is_null() {
        return SDR_INARGERR;
    }
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let iv: [u8; 16] = if pucIV.is_null() {
        [0u8; 16]
    } else {
        unsafe { std::slice::from_raw_parts(pucIV, 16).try_into().unwrap() }
    };
    let ct = unsafe { std::slice::from_raw_parts(pucEncData, uiEncDataLength as usize) };
    let mut pt = Vec::new();
    let ret = sdf_decrypt(session, key, uiAlgID, &iv, ct, &mut pt);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(pt.as_ptr(), pucData, pt.len());
            *puiDataLength = pt.len() as c_uint;
        }
    }
    ret
}

/// SDF_CalculateMAC
#[no_mangle]
pub extern "C" fn SDF_CalculateMAC(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucIV: *const c_uchar,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucMAC: *mut c_uchar,
    puiMACLength: *mut c_uint,
) -> c_int {
    if pucData.is_null() || pucMAC.is_null() || puiMACLength.is_null() { return SDR_INARGERR; }
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let iv: [u8; 16] = if pucIV.is_null() {
        [0u8; 16]
    } else {
        unsafe { std::slice::from_raw_parts(pucIV, 16).try_into().unwrap() }
    };
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    let mut mac = [0u8; 16];
    let ret = sdf_calculate_mac(session, key, &iv, data, &mut mac);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(mac.as_ptr(), pucMAC, 16);
            *puiMACLength = 16;
        }
    }
    ret
}

/// SDF_AuthEnc — 可鉴别加密（SM4-GCM）
/// 签名与 sdfc 标准一致：
///   pucStartVar/uiStartVarLength: nonce（可变长，GCM 使用12字节，超出截取）
///   pucAuthData/*puiAuthDataLength: tag 输出（固定16字节，通过长度指针返回）
#[no_mangle]
pub extern "C" fn SDF_AuthEnc(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucStartVar: *const c_uchar,
    uiStartVarLength: c_uint,
    pucAAD: *const c_uchar,
    uiAADLength: c_uint,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucEncData: *mut c_uchar,
    puiEncDataLength: *mut c_uint,
    pucAuthData: *mut c_uchar,
    puiAuthDataLength: *mut c_uint,
) -> c_int {
    if pucStartVar.is_null() || pucData.is_null() || pucEncData.is_null()
        || puiEncDataLength.is_null() || pucAuthData.is_null() || puiAuthDataLength.is_null()
    {
        return SDR_INARGERR;
    }
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    // Reason: GCM 标准 nonce 为 12 字节；若调用方传入不足12字节则补零，超出则截取
    let nonce_len = (uiStartVarLength as usize).min(12);
    let mut nonce = [0u8; 12];
    unsafe { std::ptr::copy_nonoverlapping(pucStartVar, nonce.as_mut_ptr(), nonce_len); }
    let aad: &[u8] = if pucAAD.is_null() || uiAADLength == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(pucAAD, uiAADLength as usize) }
    };
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    let ret = sdf_auth_enc(session, key, uiAlgID, &nonce, aad, data, &mut ct, &mut tag);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(ct.as_ptr(), pucEncData, ct.len());
            *puiEncDataLength = ct.len() as c_uint;
            std::ptr::copy_nonoverlapping(tag.as_ptr(), pucAuthData, 16);
            *puiAuthDataLength = 16;
        }
    }
    ret
}

/// SDF_AuthDec — 可鉴别解密（SM4-GCM）
/// 签名与 sdfc 标准一致：
///   pucAuthData/puiAuthDataLength: tag（值传递，非指针）
///   pucEncData/puiEncDataLength:   密文（值传递，非指针）
#[no_mangle]
pub extern "C" fn SDF_AuthDec(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucStartVar: *const c_uchar,
    uiStartVarLength: c_uint,
    pucAAD: *const c_uchar,
    uiAADLength: c_uint,
    pucAuthData: *const c_uchar,
    uiAuthDataLength: c_uint,
    pucEncData: *const c_uchar,
    uiEncDataLength: c_uint,
    pucData: *mut c_uchar,
    puiDataLength: *mut c_uint,
) -> c_int {
    if pucStartVar.is_null() || pucEncData.is_null() || pucAuthData.is_null()
        || pucData.is_null() || puiDataLength.is_null()
    {
        return SDR_INARGERR;
    }
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let nonce_len = (uiStartVarLength as usize).min(12);
    let mut nonce = [0u8; 12];
    unsafe { std::ptr::copy_nonoverlapping(pucStartVar, nonce.as_mut_ptr(), nonce_len); }
    let aad: &[u8] = if pucAAD.is_null() || uiAADLength == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(pucAAD, uiAADLength as usize) }
    };
    let ct = unsafe { std::slice::from_raw_parts(pucEncData, uiEncDataLength as usize) };
    // Reason: tag 长度由调用方传入，GCM 期望16字节；不足则补零，超出截取
    let tag_len = (uiAuthDataLength as usize).min(16);
    let mut tag = [0u8; 16];
    unsafe { std::ptr::copy_nonoverlapping(pucAuthData, tag.as_mut_ptr(), tag_len); }
    let mut pt = Vec::new();
    let ret = sdf_auth_dec(session, key, uiAlgID, &nonce, aad, ct, &tag, &mut pt);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(pt.as_ptr(), pucData, pt.len());
            *puiDataLength = pt.len() as c_uint;
        }
    }
    ret
}

// ──────────────── 流式对称加解密 Init/Update/Final ────────────────

/// SDF_EncryptInit
#[no_mangle]
pub extern "C" fn SDF_EncryptInit(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucIV: *const c_uchar,
) -> c_int {
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let iv: [u8; 16] = if pucIV.is_null() {
        [0u8; 16]
    } else {
        unsafe { std::slice::from_raw_parts(pucIV, 16).try_into().unwrap() }
    };
    sdf_encrypt_init(session, key, uiAlgID, &iv)
}

/// SDF_EncryptUpdate
#[no_mangle]
pub extern "C" fn SDF_EncryptUpdate(
    hSessionHandle: *mut c_void,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucEncData: *mut c_uchar,
    puiEncDataLength: *mut c_uint,
) -> c_int {
    if pucData.is_null() || pucEncData.is_null() || puiEncDataLength.is_null() {
        return SDR_INARGERR;
    }
    let session = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    let mut ct = Vec::new();
    let ret = sdf_encrypt_update(session, data, &mut ct);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(ct.as_ptr(), pucEncData, ct.len());
            *puiEncDataLength = ct.len() as c_uint;
        }
    }
    ret
}

/// SDF_EncryptFinal
#[no_mangle]
pub extern "C" fn SDF_EncryptFinal(
    hSessionHandle: *mut c_void,
    pucEncData: *mut c_uchar,
    puiEncDataLength: *mut c_uint,
) -> c_int {
    if pucEncData.is_null() || puiEncDataLength.is_null() { return SDR_INARGERR; }
    let session = hSessionHandle as usize as u32;
    let mut ct = Vec::new();
    let ret = sdf_encrypt_final(session, &mut ct);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(ct.as_ptr(), pucEncData, ct.len());
            *puiEncDataLength = ct.len() as c_uint;
        }
    }
    ret
}

/// SDF_DecryptInit
#[no_mangle]
pub extern "C" fn SDF_DecryptInit(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucIV: *const c_uchar,
) -> c_int {
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let iv: [u8; 16] = if pucIV.is_null() {
        [0u8; 16]
    } else {
        unsafe { std::slice::from_raw_parts(pucIV, 16).try_into().unwrap() }
    };
    sdf_decrypt_init(session, key, uiAlgID, &iv)
}

/// SDF_DecryptUpdate
#[no_mangle]
pub extern "C" fn SDF_DecryptUpdate(
    hSessionHandle: *mut c_void,
    pucEncData: *const c_uchar,
    uiEncDataLength: c_uint,
    pucData: *mut c_uchar,
    puiDataLength: *mut c_uint,
) -> c_int {
    if pucEncData.is_null() || pucData.is_null() || puiDataLength.is_null() {
        return SDR_INARGERR;
    }
    let session = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucEncData, uiEncDataLength as usize) };
    let mut pt = Vec::new();
    let ret = sdf_decrypt_update(session, data, &mut pt);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(pt.as_ptr(), pucData, pt.len());
            *puiDataLength = pt.len() as c_uint;
        }
    }
    ret
}

/// SDF_DecryptFinal
#[no_mangle]
pub extern "C" fn SDF_DecryptFinal(
    hSessionHandle: *mut c_void,
    pucData: *mut c_uchar,
    puiDataLength: *mut c_uint,
) -> c_int {
    if pucData.is_null() || puiDataLength.is_null() { return SDR_INARGERR; }
    let session = hSessionHandle as usize as u32;
    let mut pt = Vec::new();
    let ret = sdf_decrypt_final(session, &mut pt);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(pt.as_ptr(), pucData, pt.len());
            *puiDataLength = pt.len() as c_uint;
        }
    }
    ret
}

// ──────────────── 流式 MAC Init/Update/Final ────────────────

/// SDF_CalculateMACInit
#[no_mangle]
pub extern "C" fn SDF_CalculateMACInit(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucIV: *const c_uchar,
) -> c_int {
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let iv: [u8; 16] = if pucIV.is_null() {
        [0u8; 16]
    } else {
        unsafe { std::slice::from_raw_parts(pucIV, 16).try_into().unwrap() }
    };
    let _ = uiAlgID; // MAC 仅支持 SM4-CBC-MAC
    sdf_calculate_mac_init(session, key, &iv)
}

/// SDF_CalculateMACUpdate
#[no_mangle]
pub extern "C" fn SDF_CalculateMACUpdate(
    hSessionHandle: *mut c_void,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
) -> c_int {
    if pucData.is_null() { return SDR_INARGERR; }
    let session = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    sdf_calculate_mac_update(session, data)
}

/// SDF_CalculateMACFinal
#[no_mangle]
pub extern "C" fn SDF_CalculateMACFinal(
    hSessionHandle: *mut c_void,
    pucMAC: *mut c_uchar,
    puiMACLength: *mut c_uint,
) -> c_int {
    if pucMAC.is_null() || puiMACLength.is_null() { return SDR_INARGERR; }
    let session = hSessionHandle as usize as u32;
    let mut mac = [0u8; 16];
    let ret = sdf_calculate_mac_final(session, &mut mac);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(mac.as_ptr(), pucMAC, 16);
            *puiMACLength = 16;
        }
    }
    ret
}

// ──────────────── 流式 AEAD Init/Update/Final ────────────────

/// SDF_AuthEncInit
#[no_mangle]
pub extern "C" fn SDF_AuthEncInit(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucStartVar: *const c_uchar,
    uiStartVarLength: c_uint,
    pucAAD: *const c_uchar,
    uiAADLength: c_uint,
) -> c_int {
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let _ = uiAlgID;
    let nonce_len = (uiStartVarLength as usize).min(12);
    let mut nonce = [0u8; 12];
    if !pucStartVar.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(pucStartVar, nonce.as_mut_ptr(), nonce_len); }
    }
    let aad: &[u8] = if pucAAD.is_null() || uiAADLength == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(pucAAD, uiAADLength as usize) }
    };
    sdf_auth_enc_init(session, key, &nonce, aad)
}

/// SDF_AuthEncUpdate
#[no_mangle]
pub extern "C" fn SDF_AuthEncUpdate(
    hSessionHandle: *mut c_void,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
) -> c_int {
    if pucData.is_null() { return SDR_INARGERR; }
    let session = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    sdf_auth_enc_update(session, data)
}

/// SDF_AuthEncFinal
#[no_mangle]
pub extern "C" fn SDF_AuthEncFinal(
    hSessionHandle: *mut c_void,
    pucEncData: *mut c_uchar,
    puiEncDataLength: *mut c_uint,
    pucAuthData: *mut c_uchar,
    puiAuthDataLength: *mut c_uint,
) -> c_int {
    if pucEncData.is_null() || puiEncDataLength.is_null()
        || pucAuthData.is_null() || puiAuthDataLength.is_null()
    {
        return SDR_INARGERR;
    }
    let session = hSessionHandle as usize as u32;
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    let ret = sdf_auth_enc_final(session, &mut ct, &mut tag);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(ct.as_ptr(), pucEncData, ct.len());
            *puiEncDataLength = ct.len() as c_uint;
            std::ptr::copy_nonoverlapping(tag.as_ptr(), pucAuthData, 16);
            *puiAuthDataLength = 16;
        }
    }
    ret
}

/// SDF_AuthDecInit
#[no_mangle]
pub extern "C" fn SDF_AuthDecInit(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucStartVar: *const c_uchar,
    uiStartVarLength: c_uint,
    pucAAD: *const c_uchar,
    uiAADLength: c_uint,
    pucAuthData: *const c_uchar,
    uiAuthDataLength: c_uint,
) -> c_int {
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let _ = uiAlgID;
    let nonce_len = (uiStartVarLength as usize).min(12);
    let mut nonce = [0u8; 12];
    if !pucStartVar.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(pucStartVar, nonce.as_mut_ptr(), nonce_len); }
    }
    let aad: &[u8] = if pucAAD.is_null() || uiAADLength == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(pucAAD, uiAADLength as usize) }
    };
    let tag_len = (uiAuthDataLength as usize).min(16);
    let mut tag = [0u8; 16];
    if !pucAuthData.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(pucAuthData, tag.as_mut_ptr(), tag_len); }
    }
    sdf_auth_dec_init(session, key, &nonce, aad, &tag)
}

/// SDF_AuthDecUpdate
#[no_mangle]
pub extern "C" fn SDF_AuthDecUpdate(
    hSessionHandle: *mut c_void,
    pucEncData: *const c_uchar,
    uiEncDataLength: c_uint,
) -> c_int {
    if pucEncData.is_null() { return SDR_INARGERR; }
    let session = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucEncData, uiEncDataLength as usize) };
    sdf_auth_dec_update(session, data)
}

/// SDF_AuthDecFinal
#[no_mangle]
pub extern "C" fn SDF_AuthDecFinal(
    hSessionHandle: *mut c_void,
    pucData: *mut c_uchar,
    puiDataLength: *mut c_uint,
) -> c_int {
    if pucData.is_null() || puiDataLength.is_null() { return SDR_INARGERR; }
    let session = hSessionHandle as usize as u32;
    let mut pt = Vec::new();
    let ret = sdf_auth_dec_final(session, &mut pt);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(pt.as_ptr(), pucData, pt.len());
            *puiDataLength = pt.len() as c_uint;
        }
    }
    ret
}

// ──────────────── 内部 ECC 加解密 ────────────────

/// SDF_InternalEncrypt_ECC
#[no_mangle]
pub extern "C" fn SDF_InternalEncrypt_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    uiIPKIndex: c_uint,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucEncData: *mut ECCCipher,
) -> c_int {
    if pucData.is_null() || pucEncData.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    let mut cipher = ECCCipher::default();
    let ret = sdf_internal_encrypt_ecc(handle, uiAlgID, uiIPKIndex, data, &mut cipher);
    if ret == 0 {
        unsafe { ecc_cipher_write_to_c(&cipher, pucEncData); }
    }
    ret
}

/// SDF_InternalDecrypt_ECC
#[no_mangle]
pub extern "C" fn SDF_InternalDecrypt_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    uiISKIndex: c_uint,
    pucEncData: *const ECCCipher,
    pucData: *mut c_uchar,
    puiDataLength: *mut c_uint,
) -> c_int {
    if pucEncData.is_null() || pucData.is_null() || puiDataLength.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let cipher = unsafe { ecc_cipher_read_from_c(pucEncData) };
    let mut plaintext = Vec::new();
    let ret = sdf_internal_decrypt_ecc(handle, uiAlgID, uiISKIndex, &cipher, &mut plaintext);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(plaintext.as_ptr(), pucData, plaintext.len());
            *puiDataLength = plaintext.len() as c_uint;
        }
    }
    ret
}

/// SDF_HashInit
#[no_mangle]
pub extern "C" fn SDF_HashInit(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    pucPublicKey: *const ECCrefPublicKey,
    pucID: *const c_uchar,
    uiIDLength: c_uint,
) -> c_int {
    let handle = hSessionHandle as usize as u32;
    let pub_key = if pucPublicKey.is_null() {
        None
    } else {
        Some(unsafe { &*pucPublicKey })
    };
    let id = if pucID.is_null() || uiIDLength == 0 {
        &b"1234567812345678"[..]
    } else {
        unsafe { std::slice::from_raw_parts(pucID, uiIDLength as usize) }
    };
    sdf_hash_init(handle, uiAlgID, pub_key, id)
}

/// SDF_HashUpdate
#[no_mangle]
pub extern "C" fn SDF_HashUpdate(
    hSessionHandle: *mut c_void,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
) -> c_int {
    if pucData.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    sdf_hash_update(handle, data)
}

/// SDF_HashFinal
#[no_mangle]
pub extern "C" fn SDF_HashFinal(
    hSessionHandle: *mut c_void,
    pucHash: *mut c_uchar,
    puiHashLength: *mut c_uint,
) -> c_int {
    if pucHash.is_null() || puiHashLength.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let mut hash = [0u8; 32];
    let ret = sdf_hash_final(handle, &mut hash);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), pucHash, 32);
            *puiHashLength = 32;
        }
    }
    ret
}

/// SDF_HMACInit
#[no_mangle]
pub extern "C" fn SDF_HMACInit(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
) -> c_int {
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    sdf_hmac_init(session, key, uiAlgID)
}

/// SDF_HMACUpdate
#[no_mangle]
pub extern "C" fn SDF_HMACUpdate(
    hSessionHandle: *mut c_void,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
) -> c_int {
    if pucData.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    sdf_hmac_update(handle, data)
}

/// SDF_HMACFinal
#[no_mangle]
pub extern "C" fn SDF_HMACFinal(
    hSessionHandle: *mut c_void,
    pucMAC: *mut c_uchar,
    puiMACLength: *mut c_uint,
) -> c_int {
    if pucMAC.is_null() || puiMACLength.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let mut mac = [0u8; 32];
    let ret = sdf_hmac_final(handle, &mut mac);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(mac.as_ptr(), pucMAC, 32);
            *puiMACLength = 32;
        }
    }
    ret
}
