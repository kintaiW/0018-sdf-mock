// 设备管理 FFI 导出
use std::os::raw::{c_int, c_void, c_uint, c_uchar};
use crate::error_code::SDR_INARGERR;
use crate::sdf_impl::device::*;
use crate::types::DEVICEINFO;

/// SDF_OpenDevice
/// 参数：phDeviceHandle（输出，设备句柄；Mock 中忽略，传出固定值1）
#[no_mangle]
pub extern "C" fn SDF_OpenDevice(phDeviceHandle: *mut *mut c_void) -> c_int {
    let ret = sdf_open_device();
    if ret == 0 && !phDeviceHandle.is_null() {
        unsafe { *phDeviceHandle = 1usize as *mut c_void; }
    }
    ret
}

/// SDF_CloseDevice
#[no_mangle]
pub extern "C" fn SDF_CloseDevice(_hDeviceHandle: *mut c_void) -> c_int {
    sdf_close_device()
}

/// SDF_OpenSession
/// hDeviceHandle: 设备句柄（Mock 中忽略）
/// phSessionHandle: 输出会话句柄
#[no_mangle]
pub extern "C" fn SDF_OpenSession(
    _hDeviceHandle: *mut c_void,
    phSessionHandle: *mut *mut c_void,
) -> c_int {
    if phSessionHandle.is_null() {
        return SDR_INARGERR;
    }
    let mut handle: u32 = 0;
    let ret = sdf_open_session(&mut handle);
    if ret == 0 {
        unsafe { *phSessionHandle = handle as usize as *mut c_void; }
    }
    ret
}

/// SDF_CloseSession
#[no_mangle]
pub extern "C" fn SDF_CloseSession(hSessionHandle: *mut c_void) -> c_int {
    let handle = hSessionHandle as usize as u32;
    sdf_close_session(handle)
}

/// SDF_GetDeviceInfo
#[no_mangle]
pub extern "C" fn SDF_GetDeviceInfo(
    hSessionHandle: *mut c_void,
    pstDeviceInfo: *mut DEVICEINFO,
) -> c_int {
    if pstDeviceInfo.is_null() {
        return SDR_INARGERR;
    }
    let handle = hSessionHandle as usize as u32;
    unsafe { sdf_get_device_info(handle, &mut *pstDeviceInfo) }
}

/// SDF_Test — 设备内部一致性自检（计算 SM3 哈希后写入输出缓冲）
#[no_mangle]
pub extern "C" fn SDF_Test(
    hSessionHandle: *mut c_void,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucTestResult: *mut c_uchar,
    puiTestResultLength: *mut c_uint,
) -> c_int {
    if pucData.is_null() || pucTestResult.is_null() || puiTestResultLength.is_null() {
        return SDR_INARGERR;
    }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    let mut out = Vec::new();
    let ret = sdf_test(handle, data, &mut out);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(out.as_ptr(), pucTestResult, out.len());
            *puiTestResultLength = out.len() as c_uint;
        }
    }
    ret
}
