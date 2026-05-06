// 密钥管理 FFI 导出
use std::os::raw::{c_int, c_void, c_uint};
use crate::error_code::SDR_INARGERR;
use crate::types::{ECCrefPublicKey, ECCrefPrivateKey, ECCCipher, RSArefPublicKey, RSArefPrivateKey};
use crate::sdf_impl::key_manage::*;
use crate::ffi::crypto_ffi::{ecc_cipher_write_to_c, ecc_cipher_read_from_c};

// ──────────────── RSA 接口（真实运算）────────────────

/// SDF_ExportSignPublicKey_RSA
#[no_mangle]
pub extern "C" fn SDF_ExportSignPublicKey_RSA(
    hSessionHandle: *mut c_void,
    uiKeyIndex: c_uint,
    pucPublicKey: *mut RSArefPublicKey,
) -> c_int {
    if pucPublicKey.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    unsafe { sdf_export_sign_public_key_rsa(handle, uiKeyIndex, &mut *pucPublicKey) }
}

/// SDF_ExportEncPublicKey_RSA
#[no_mangle]
pub extern "C" fn SDF_ExportEncPublicKey_RSA(
    hSessionHandle: *mut c_void,
    uiKeyIndex: c_uint,
    pucPublicKey: *mut RSArefPublicKey,
) -> c_int {
    if pucPublicKey.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    unsafe { sdf_export_enc_public_key_rsa(handle, uiKeyIndex, &mut *pucPublicKey) }
}

/// SDF_GenerateKeyPair_RSA
#[no_mangle]
pub extern "C" fn SDF_GenerateKeyPair_RSA(
    hSessionHandle: *mut c_void,
    uiBits: c_uint,
    pucPublicKey: *mut RSArefPublicKey,
    pucPrivateKey: *mut RSArefPrivateKey,
) -> c_int {
    if pucPublicKey.is_null() || pucPrivateKey.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    unsafe { sdf_generate_key_pair_rsa(handle, uiBits, &mut *pucPublicKey, &mut *pucPrivateKey) }
}

// ──────────────── 其他密钥管理接口 ────────────────

/// SDF_GenerateRandom
#[no_mangle]
pub extern "C" fn SDF_GenerateRandom(
    hSessionHandle: *mut c_void,
    uiLength: c_uint,
    pucRandom: *mut u8,
) -> c_int {
    if pucRandom.is_null() || uiLength == 0 {
        return SDR_INARGERR;
    }
    let handle = hSessionHandle as usize as u32;
    let mut random = Vec::new();
    let ret = sdf_generate_random(handle, uiLength, &mut random);
    if ret == 0 {
        unsafe { std::ptr::copy_nonoverlapping(random.as_ptr(), pucRandom, random.len()); }
    }
    ret
}

/// SDF_GetPrivateKeyAccessRight
#[no_mangle]
pub extern "C" fn SDF_GetPrivateKeyAccessRight(
    hSessionHandle: *mut c_void,
    uiKeyIndex: c_uint,
    pucPassword: *const u8,
    uiPwdLength: c_uint,
) -> c_int {
    let handle = hSessionHandle as usize as u32;
    let pwd = if pucPassword.is_null() {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(pucPassword, uiPwdLength as usize) }
    };
    sdf_get_private_key_access_right(handle, uiKeyIndex, pwd)
}

/// SDF_ReleasePrivateKeyAccessRight
#[no_mangle]
pub extern "C" fn SDF_ReleasePrivateKeyAccessRight(
    hSessionHandle: *mut c_void,
    uiKeyIndex: c_uint,
) -> c_int {
    let handle = hSessionHandle as usize as u32;
    sdf_release_private_key_access_right(handle, uiKeyIndex)
}

/// SDF_ExportSignPublicKey_ECC
#[no_mangle]
pub extern "C" fn SDF_ExportSignPublicKey_ECC(
    hSessionHandle: *mut c_void,
    uiKeyIndex: c_uint,
    pucPublicKey: *mut ECCrefPublicKey,
) -> c_int {
    if pucPublicKey.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    unsafe { sdf_export_sign_public_key_ecc(handle, uiKeyIndex, &mut *pucPublicKey) }
}

/// SDF_ExportEncPublicKey_ECC
#[no_mangle]
pub extern "C" fn SDF_ExportEncPublicKey_ECC(
    hSessionHandle: *mut c_void,
    uiKeyIndex: c_uint,
    pucPublicKey: *mut ECCrefPublicKey,
) -> c_int {
    if pucPublicKey.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    unsafe { sdf_export_enc_public_key_ecc(handle, uiKeyIndex, &mut *pucPublicKey) }
}

/// SDF_GenerateKeyPair_ECC
#[no_mangle]
pub extern "C" fn SDF_GenerateKeyPair_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    uiKeyBits: c_uint,
    pucPublicKey: *mut ECCrefPublicKey,
    pucPrivateKey: *mut ECCrefPrivateKey,
) -> c_int {
    if pucPublicKey.is_null() || pucPrivateKey.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    unsafe {
        sdf_generate_key_pair_ecc(handle, uiAlgID, uiKeyBits, &mut *pucPublicKey, &mut *pucPrivateKey)
    }
}

/// SDF_ImportKey — 明文导入会话密钥
#[no_mangle]
pub extern "C" fn SDF_ImportKey(
    hSessionHandle: *mut c_void,
    pucKey: *const u8,
    uiKeyLength: c_uint,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucKey.is_null() || phKeyHandle.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let key_bytes = unsafe { std::slice::from_raw_parts(pucKey, uiKeyLength as usize) };
    let mut key_handle: u32 = 0;
    let ret = sdf_import_key(handle, key_bytes, &mut key_handle);
    if ret == 0 {
        unsafe { *phKeyHandle = key_handle as usize as *mut c_void; }
    }
    ret
}

/// SDF_GenerateKeyWithKEK
#[no_mangle]
pub extern "C" fn SDF_GenerateKeyWithKEK(
    hSessionHandle: *mut c_void,
    uiLength: c_uint,
    uiAlgID: c_uint,
    uiKEKIndex: c_uint,
    pucKey: *mut u8,
    puiKeyLength: *mut c_uint,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucKey.is_null() || puiKeyLength.is_null() || phKeyHandle.is_null() {
        return SDR_INARGERR;
    }
    let handle = hSessionHandle as usize as u32;
    let mut cipher_key = Vec::new();
    let mut key_handle: u32 = 0;
    let ret = sdf_generate_key_with_kek(handle, uiLength, uiKEKIndex, &mut cipher_key, &mut key_handle);
    if ret == 0 {
        unsafe {
            // Reason: 调用方初始时 keycipherLen 可能为0，不做容量校验，直接写入
            // 调用方负责保证 pucKey 缓冲区足够大（通常 256 字节）
            std::ptr::copy_nonoverlapping(cipher_key.as_ptr(), pucKey, cipher_key.len());
            *puiKeyLength = cipher_key.len() as c_uint;
            *phKeyHandle = key_handle as usize as *mut c_void;
        }
    }
    ret
}

/// SDF_ImportKeyWithKEK
#[no_mangle]
pub extern "C" fn SDF_ImportKeyWithKEK(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    uiKEKIndex: c_uint,
    pucKey: *const u8,
    uiKeyLength: c_uint,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucKey.is_null() || phKeyHandle.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let key_bytes = unsafe { std::slice::from_raw_parts(pucKey, uiKeyLength as usize) };
    let mut key_handle: u32 = 0;
    let ret = sdf_import_key_with_kek(handle, uiAlgID, uiKEKIndex, key_bytes, &mut key_handle);
    if ret == 0 {
        unsafe { *phKeyHandle = key_handle as usize as *mut c_void; }
    }
    ret
}

/// SDF_DestroyKey
#[no_mangle]
pub extern "C" fn SDF_DestroyKey(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
) -> c_int {
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    sdf_destroy_key(session, key)
}

// ──────────────── ECC 密钥协商 ────────────────

/// SDF_GenerateAgreementDataWithECC — 发起方生成临时密钥对和协商数据
#[no_mangle]
pub extern "C" fn SDF_GenerateAgreementDataWithECC(
    hSessionHandle: *mut c_void,
    uiISKIndex: c_uint,
    pucSponsorID: *const u8,
    uiSponsorIDLength: c_uint,
    pucSponsorPublicKey: *mut ECCrefPublicKey,
    pucSponsorTmpPublicKey: *mut ECCrefPublicKey,
) -> c_int {
    if pucSponsorPublicKey.is_null() || pucSponsorTmpPublicKey.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let id = if pucSponsorID.is_null() || uiSponsorIDLength == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(pucSponsorID, uiSponsorIDLength as usize) }
    };
    unsafe {
        sdf_generate_agreement_data_with_ecc(
            handle, uiISKIndex, id,
            &mut *pucSponsorPublicKey, &mut *pucSponsorTmpPublicKey,
        )
    }
}

/// SDF_GenerateKeyWithECC — 响应方用协商数据生成会话密钥
#[no_mangle]
pub extern "C" fn SDF_GenerateKeyWithECC(
    hSessionHandle: *mut c_void,
    pucResponseID: *const u8,
    uiResponseIDLength: c_uint,
    pucResponsePublicKey: *const ECCrefPublicKey,
    pucResponseTmpPublicKey: *const ECCrefPublicKey,
    uiKeyBits: c_uint,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucResponsePublicKey.is_null() || pucResponseTmpPublicKey.is_null()
        || phKeyHandle.is_null()
    {
        return SDR_INARGERR;
    }
    let handle = hSessionHandle as usize as u32;
    let id = if pucResponseID.is_null() || uiResponseIDLength == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(pucResponseID, uiResponseIDLength as usize) }
    };
    let mut key_handle: u32 = 0;
    let ret = unsafe {
        sdf_generate_key_with_ecc(
            handle, id,
            &*pucResponsePublicKey, &*pucResponseTmpPublicKey,
            uiKeyBits, &mut key_handle,
        )
    };
    if ret == 0 {
        unsafe { *phKeyHandle = key_handle as usize as *mut c_void; }
    }
    ret
}

/// SDF_GenerateAgreementDataAndKeyWithECC — 响应方同时生成协商数据和会话密钥
#[no_mangle]
pub extern "C" fn SDF_GenerateAgreementDataAndKeyWithECC(
    hSessionHandle: *mut c_void,
    uiISKIndex: c_uint,
    pucResponseID: *const u8,
    uiResponseIDLength: c_uint,
    pucSponsorID: *const u8,
    uiSponsorIDLength: c_uint,
    pucSponsorPublicKey: *const ECCrefPublicKey,
    pucSponsorTmpPublicKey: *const ECCrefPublicKey,
    pucResponsePublicKey: *mut ECCrefPublicKey,
    pucResponseTmpPublicKey: *mut ECCrefPublicKey,
    uiKeyBits: c_uint,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucSponsorPublicKey.is_null() || pucSponsorTmpPublicKey.is_null()
        || pucResponsePublicKey.is_null() || pucResponseTmpPublicKey.is_null()
        || phKeyHandle.is_null()
    {
        return SDR_INARGERR;
    }
    let handle = hSessionHandle as usize as u32;
    let resp_id = if pucResponseID.is_null() || uiResponseIDLength == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(pucResponseID, uiResponseIDLength as usize) }
    };
    let spon_id = if pucSponsorID.is_null() || uiSponsorIDLength == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(pucSponsorID, uiSponsorIDLength as usize) }
    };
    let mut key_handle: u32 = 0;
    let ret = unsafe {
        sdf_generate_agreement_data_and_key_with_ecc(
            handle, uiISKIndex, resp_id, spon_id,
            &*pucSponsorPublicKey, &*pucSponsorTmpPublicKey,
            &mut *pucResponsePublicKey, &mut *pucResponseTmpPublicKey,
            uiKeyBits, &mut key_handle,
        )
    };
    if ret == 0 {
        unsafe { *phKeyHandle = key_handle as usize as *mut c_void; }
    }
    ret
}

/// SDF_GenerateKeyWithEPK_ECC（基于已存储的协商数据，用对端临时公钥派生密钥）
#[no_mangle]
pub extern "C" fn SDF_GenerateKeyWithEPK_ECC(
    hSessionHandle: *mut c_void,
    uiKeyBits: c_uint,
    _uiAlgID: c_uint,
    pucPublicKey: *const ECCrefPublicKey,
    pucEncData: *mut ECCCipher,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucPublicKey.is_null() || phKeyHandle.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let mut key_handle: u32 = 0;
    let ret = unsafe {
        sdf_generate_key_with_epk_ecc_agreement(handle, uiKeyBits, &*pucPublicKey, &mut key_handle)
    };
    if ret == 0 {
        unsafe { *phKeyHandle = key_handle as usize as *mut c_void; }
    }
    // Reason: pucEncData 在 ECC 协商场景中不使用（密钥通过协商派生，不通过非对称加密传输）
    let _ = pucEncData;
    ret
}
#[no_mangle]
pub extern "C" fn SDF_GenerateKeyWithIPK_ECC(
    hSessionHandle: *mut c_void,
    uiIPKIndex: c_uint,
    uiKeyBits: c_uint,
    pucKey: *mut ECCCipher,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucKey.is_null() || phKeyHandle.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let mut cipher = ECCCipher::default();
    let mut key_handle: u32 = 0;
    let ret = sdf_generate_key_with_ipk_ecc(handle, uiIPKIndex, uiKeyBits, &mut cipher, &mut key_handle);
    if ret == 0 {
        unsafe {
            // Reason: C 侧 ECCCipher.C 是柔性数组，不能整体赋值，逐字段写入
            ecc_cipher_write_to_c(&cipher, pucKey);
            *phKeyHandle = key_handle as usize as *mut c_void;
        }
    }
    ret
}

/// SDF_ImportKeyWithISK_ECC
#[no_mangle]
pub extern "C" fn SDF_ImportKeyWithISK_ECC(
    hSessionHandle: *mut c_void,
    uiISKIndex: c_uint,
    pucKey: *const ECCCipher,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucKey.is_null() || phKeyHandle.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    // Reason: 从 C 侧柔性数组安全读入 ECCCipher
    let cipher = unsafe { ecc_cipher_read_from_c(pucKey) };
    let mut key_handle: u32 = 0;
    let ret = sdf_import_key_with_isk_ecc(handle, uiISKIndex, &cipher, &mut key_handle);
    if ret == 0 {
        unsafe { *phKeyHandle = key_handle as usize as *mut c_void; }
    }
    ret
}
