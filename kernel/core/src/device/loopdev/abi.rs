// SPDX-License-Identifier: MPL-2.0

//! Linux loop ioctl commands and the loop status ABI.
//!
//! Userspace sees `struct loop_info` (legacy) and `struct loop_info64`.
//! The runtime keeps only [`LoopConfig`]; the wire types and all conversion
//! and validation live here.

use ostd::const_assert;

use super::disk::{LoopConfig, LoopFlags};
use crate::{
    ioc,
    prelude::*,
    util::ioctl::{InData, NoData, OutData, PassByVal},
};

impl LoopConfig {
    /// Converts a legacy `struct loop_info` into the runtime configuration.
    pub(super) fn from_legacy(info: &LegacyInfo) -> Result<Self> {
        if info.encrypt_type != 0 || info.encrypt_key_size != 0 {
            return_errno_with_message!(Errno::EINVAL, "loop encryption is not supported");
        }
        if info.offset < 0 {
            return_errno_with_message!(Errno::EINVAL, "negative loop offset");
        }
        let flags = LoopFlags::from_bits(info.flags as u32)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "unsupported loop flags"))?;
        Ok(Self {
            offset: info.offset as u64,
            size_limit: 0,
            flags,
            file_name: sanitize_file_name(info.file_name),
        })
    }
}

/// Status payload shared by `LOOP_SET_STATUS64` and `LOOP_GET_STATUS64`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct Info64 {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    size_limit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
}

impl Info64 {
    /// Converts a `struct loop_info64` into the runtime configuration.
    pub(super) fn to_config(self) -> Result<LoopConfig> {
        if self.encrypt_type != 0 || self.encrypt_key_size != 0 {
            return_errno_with_message!(Errno::EINVAL, "loop encryption is not supported");
        }
        if self.offset > isize::MAX as u64 || self.size_limit > isize::MAX as u64 {
            return_errno_with_message!(Errno::EOVERFLOW, "loop offset or size limit is too large");
        }
        let flags = LoopFlags::from_bits(self.flags)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "unsupported loop flags"))?;
        Ok(LoopConfig {
            offset: self.offset,
            size_limit: self.size_limit,
            flags,
            file_name: sanitize_file_name(self.file_name),
        })
    }

    /// Builds a `struct loop_info64` from the runtime state.
    pub(super) fn from_config(config: &LoopConfig, number: u32, device: u64, inode: u64) -> Self {
        Self {
            device,
            inode,
            rdevice: 0,
            offset: config.offset,
            size_limit: config.size_limit,
            number,
            encrypt_type: 0,
            encrypt_key_size: 0,
            flags: config.flags.bits(),
            file_name: config.file_name,
            crypt_name: [0; 64],
            encrypt_key: [0; 32],
            init: [0; 2],
        }
    }

    /// Converts this 64-bit status into the legacy `struct loop_info`.
    pub(super) fn to_legacy(self) -> Result<LegacyInfo> {
        if self.offset > i32::MAX as u64 {
            return_errno_with_message!(Errno::EOVERFLOW, "loop offset does not fit the legacy ABI");
        }
        let mut info = LegacyInfo {
            number: self.number as i32,
            _pad: 0,
            device: 0,
            inode: self.inode,
            rdevice: 0,
            offset: self.offset as i32,
            encrypt_type: 0,
            encrypt_key_size: 0,
            flags: self.flags as i32,
            file_name: self.file_name,
            encrypt_key: [0; 32],
            init: [0; 2],
            reserved: [0; 4],
            _tail_pad: 0,
        };
        #[cfg(target_arch = "x86_64")]
        {
            info.device = self.device;
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            info.device = u32::try_from(self.device).map_err(|_| Error::new(Errno::EOVERFLOW))?;
        }
        Ok(info)
    }
}

// `struct loop_info` is the legacy ABI. `__kernel_old_dev_t` is an
// `unsigned long` on x86-64 but `unsigned int` elsewhere; the explicit padding
// makes the layout deterministic, because `Pod` forbids implicit padding.
// References: Linux `arch/x86/include/uapi/asm/posix_types_64.h`,
// `include/uapi/asm-generic/posix_types.h`, and `include/uapi/linux/loop.h`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct LegacyInfo {
    number: i32,
    _pad: u32,
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: i32,
    encrypt_type: i32,
    encrypt_key_size: i32,
    flags: i32,
    file_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
    reserved: [u8; 4],
    _tail_pad: u32,
}

#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct LegacyInfo {
    number: i32,
    device: u32,
    inode: u64,
    rdevice: u32,
    offset: i32,
    encrypt_type: i32,
    encrypt_key_size: i32,
    flags: i32,
    file_name: [u8; 64],
    encrypt_key: [u8; 32],
    _pad: u32,
    init: [u64; 2],
    reserved: [u8; 4],
    _tail_pad: u32,
}

#[cfg(target_arch = "x86_64")]
pub(super) const LEGACY_SIZE: usize = 168;
#[cfg(not(target_arch = "x86_64"))]
pub(super) const LEGACY_SIZE: usize = 160;

const_assert!(size_of::<LegacyInfo>() == LEGACY_SIZE);

impl LegacyInfo {
    /// Converts a `struct loop_info` into the runtime configuration.
    pub(super) fn to_config(self) -> Result<LoopConfig> {
        LoopConfig::from_legacy(&self)
    }
}

fn sanitize_file_name(mut file_name: [u8; 64]) -> [u8; 64] {
    file_name[63] = 0;
    file_name
}

pub(super) type SetFd = ioc!(LOOP_SET_FD, 0x4c00, InData<i32, PassByVal>);
pub(super) type ClearFd = ioc!(LOOP_CLR_FD, 0x4c01, NoData);
pub(super) type SetStatus = ioc!(LOOP_SET_STATUS, 0x4c02, InData<LegacyInfo>);
pub(super) type GetStatus = ioc!(LOOP_GET_STATUS, 0x4c03, OutData<LegacyInfo>);
pub(super) type SetStatus64 = ioc!(LOOP_SET_STATUS64, 0x4c04, InData<Info64>);
pub(super) type GetStatus64 = ioc!(LOOP_GET_STATUS64, 0x4c05, OutData<Info64>);
pub(super) type SetCapacity = ioc!(LOOP_SET_CAPACITY, 0x4c07, NoData);
pub(super) type ControlAdd = ioc!(LOOP_CTL_ADD, 0x4c80, InData<i32, PassByVal>);
pub(super) type ControlRemove = ioc!(LOOP_CTL_REMOVE, 0x4c81, InData<i32, PassByVal>);
pub(super) type ControlGetFree = ioc!(LOOP_CTL_GET_FREE, 0x4c82, NoData);
