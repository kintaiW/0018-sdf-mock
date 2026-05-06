// 文件操作 FFI 导出（Stub）
// GM/T 0018 §6.6 文件管理接口，Mock 环境全部返回 SDR_NOTSUPPORT
use std::os::raw::{c_int, c_void, c_uint, c_uchar};
use crate::error_code::SDR_INARGERR;
use crate::sdf_impl::file_ops::*;

/// SDF_CreateFile — 在设备内创建文件（Mock 不支持）
/// pucFileName:    [in] 文件名（最大 128 字节）
/// uiNameLen:      [in] 文件名长度
/// uiFileSize:     [in] 文件大小（字节）
#[no_mangle]
pub extern "C" fn SDF_CreateFile(
    hSessionHandle: *mut c_void,
    pucFileName: *const c_uchar,
    uiNameLen: c_uint,
    uiFileSize: c_uint,
) -> c_int {
    if pucFileName.is_null() || uiNameLen == 0 { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let name = unsafe { std::slice::from_raw_parts(pucFileName, uiNameLen as usize) };
    sdf_create_file(handle, name, uiFileSize)
}

/// SDF_WriteFile — 向设备文件写入数据（Mock 不支持）
/// pucFileName:    [in] 文件名
/// uiOffset:       [in] 写入偏移
/// pucBuffer:      [in] 数据
/// uiWriteLength:  [in] 写入长度
#[no_mangle]
pub extern "C" fn SDF_WriteFile(
    hSessionHandle: *mut c_void,
    pucFileName: *const c_uchar,
    uiNameLen: c_uint,
    uiOffset: c_uint,
    pucBuffer: *const c_uchar,
    uiWriteLength: c_uint,
) -> c_int {
    if pucFileName.is_null() || pucBuffer.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let name = unsafe { std::slice::from_raw_parts(pucFileName, uiNameLen as usize) };
    let data = unsafe { std::slice::from_raw_parts(pucBuffer, uiWriteLength as usize) };
    sdf_write_file(handle, name, uiOffset, data)
}

/// SDF_ReadFile — 从设备文件读取数据（Mock 不支持）
/// pucFileName:    [in]  文件名
/// uiOffset:       [in]  读取偏移
/// puiReadLength:  [in/out] 请求长度 / 实际读取长度
/// pucBuffer:      [out] 数据缓冲区
#[no_mangle]
pub extern "C" fn SDF_ReadFile(
    hSessionHandle: *mut c_void,
    pucFileName: *const c_uchar,
    uiNameLen: c_uint,
    uiOffset: c_uint,
    puiReadLength: *mut c_uint,
    _pucBuffer: *mut c_uchar,
) -> c_int {
    if pucFileName.is_null() || puiReadLength.is_null() { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let name = unsafe { std::slice::from_raw_parts(pucFileName, uiNameLen as usize) };
    let mut out_len = unsafe { *puiReadLength };
    sdf_read_file(handle, name, uiOffset, &mut out_len)
}

/// SDF_DeleteFile — 删除设备文件（Mock 不支持）
#[no_mangle]
pub extern "C" fn SDF_DeleteFile(
    hSessionHandle: *mut c_void,
    pucFileName: *const c_uchar,
    uiNameLen: c_uint,
) -> c_int {
    if pucFileName.is_null() || uiNameLen == 0 { return SDR_INARGERR; }
    let handle = hSessionHandle as usize as u32;
    let name = unsafe { std::slice::from_raw_parts(pucFileName, uiNameLen as usize) };
    sdf_delete_file(handle, name)
}
