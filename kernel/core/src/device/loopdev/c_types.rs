// SPDX-License-Identifier: MPL-2.0

//! Linux loop UAPI structs and runtime configuration conversions.
//!
//! Userspace sees `struct loop_info` (legacy), `struct loop_info64`, and
//! `struct loop_config`. The runtime keeps only [`LoopConfig`]; the wire
//! structs and all conversion and validation live here.

use ostd::const_assert;

use super::disk::{LoopConfig, LoopFlags};
use crate::prelude::*;

// Reference: <https://elixir.bootlin.com/linux/v6.18/source/include/uapi/linux/loop.h>.
pub(super) const LO_NAME_SIZE: usize = 64;
const LO_KEY_SIZE: usize = 32;
const OLD_DEV_COMPONENT_MAX: u32 = 0xff;
const CONFIGURE_RESERVED_WORDS: usize = 8;

impl LoopConfig {
    /// Converts a legacy `struct loop_info` into the runtime configuration.
    pub(super) fn from_legacy(info: &LegacyInfo) -> Result<Self> {
        if info.encrypt_type != 0 || info.encrypt_key_size != 0 {
            return_errno_with_message!(Errno::EINVAL, "loop encryption is not supported");
        }
        if info.offset < 0 {
            // Linux's `loop_set_info_configure` stores the negative offset in
            // an unsigned 64-bit field, so it exceeds `LLONG_MAX` and the later
            // range check reports `EOVERFLOW`.
            return_errno_with_message!(Errno::EOVERFLOW, "negative loop offset");
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
    file_name: [u8; LO_NAME_SIZE],
    crypt_name: [u8; LO_NAME_SIZE],
    encrypt_key: [u8; LO_KEY_SIZE],
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
            crypt_name: [0; LO_NAME_SIZE],
            encrypt_key: [0; LO_KEY_SIZE],
            init: [0; 2],
        }
    }

    /// Converts this 64-bit status into the legacy `struct loop_info`.
    pub(super) fn to_legacy(self) -> Result<LegacyInfo> {
        if self.offset > i32::MAX as u64 {
            return_errno_with_message!(Errno::EOVERFLOW, "loop offset does not fit the legacy ABI");
        }
        // Linux `loop_get_status_old` encodes `lo_device` with `old_encode_dev`,
        // which only has room for 8-bit major and minor numbers.
        let (major, minor) = device_id::decode_device_numbers(self.device);
        if major > OLD_DEV_COMPONENT_MAX || minor > OLD_DEV_COMPONENT_MAX {
            return_errno_with_message!(
                Errno::EOVERFLOW,
                "loop device number does not fit the legacy ABI"
            );
        }
        let old_device = (major << 8) | minor;
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
            encrypt_key: [0; LO_KEY_SIZE],
            init: [0; 2],
            reserved: [0; 4],
            _tail_pad: 0,
        };
        #[cfg(target_arch = "x86_64")]
        {
            info.device = old_device as u64;
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            info.device = old_device;
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
    file_name: [u8; LO_NAME_SIZE],
    encrypt_key: [u8; LO_KEY_SIZE],
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
    file_name: [u8; LO_NAME_SIZE],
    encrypt_key: [u8; LO_KEY_SIZE],
    _pad: u32,
    init: [u64; 2],
    reserved: [u8; 4],
    _tail_pad: u32,
}

#[cfg(target_arch = "x86_64")]
const LEGACY_SIZE: usize = 168;
#[cfg(not(target_arch = "x86_64"))]
const LEGACY_SIZE: usize = 160;

const_assert!(size_of::<LegacyInfo>() == LEGACY_SIZE);

impl LegacyInfo {
    /// Converts a `struct loop_info` into the runtime configuration.
    pub(super) fn to_config(self) -> Result<LoopConfig> {
        LoopConfig::from_legacy(&self)
    }
}

/// `struct loop_config`, the argument of `LOOP_CONFIGURE`.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.18/source/include/uapi/linux/loop.h>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct LoopConfigAbi {
    fd: u32,
    block_size: u32,
    info: Info64,
    reserved: [u64; CONFIGURE_RESERVED_WORDS],
}

const_assert!(size_of::<LoopConfigAbi>() == 304);

impl LoopConfigAbi {
    /// Returns the backing file descriptor.
    pub(super) fn fd(self) -> Result<i32> {
        i32::try_from(self.fd)
            .map_err(|_| Error::with_message(Errno::EBADF, "the loop backing fd is too large"))
    }

    /// Validates the atomic configure request and converts it to the runtime
    /// configuration.
    ///
    /// `LOOP_CONFIGURE` is all-or-nothing: any unsupported field must fail
    /// with `EINVAL` rather than be ignored.
    pub(super) fn to_config(self) -> Result<LoopConfig> {
        if self.reserved.iter().any(|&word| word != 0) {
            return_errno_with_message!(Errno::EINVAL, "loop configure reserved words are not zero");
        }
        if self.block_size != 0 && self.block_size != aster_block::SECTOR_SIZE as u32 {
            return_errno_with_message!(Errno::EINVAL, "only 512-byte loop blocks are supported");
        }
        self.info.to_config()
    }
}

fn sanitize_file_name(mut file_name: [u8; LO_NAME_SIZE]) -> [u8; LO_NAME_SIZE] {
    file_name[LO_NAME_SIZE - 1] = 0;
    file_name
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn info64_to_config_validates_fields() {
        let mut info = Info64::from_config(&LoopConfig::default(), 0, 0, 0);
        info.offset = 1024;
        info.size_limit = 4096;
        info.flags = LoopFlags::READ_ONLY.bits();
        info.file_name = [b'a'; LO_NAME_SIZE];

        let config = info.to_config().unwrap();
        assert_eq!(config.offset, 1024);
        assert_eq!(config.size_limit, 4096);
        assert_eq!(config.flags, LoopFlags::READ_ONLY);
        assert_eq!(config.file_name[LO_NAME_SIZE - 1], 0);

        let mut encrypted = info;
        encrypted.encrypt_type = 1;
        assert_eq!(encrypted.to_config().unwrap_err().error(), Errno::EINVAL);

        let mut huge_offset = info;
        huge_offset.offset = isize::MAX as u64 + 1;
        assert_eq!(
            huge_offset.to_config().unwrap_err().error(),
            Errno::EOVERFLOW
        );

        let mut huge_limit = info;
        huge_limit.size_limit = isize::MAX as u64 + 1;
        assert_eq!(
            huge_limit.to_config().unwrap_err().error(),
            Errno::EOVERFLOW
        );

        let mut bad_flags = info;
        bad_flags.flags = 1 << 3; // LO_FLAGS_PARTSCAN
        assert_eq!(bad_flags.to_config().unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn legacy_info_round_trip_and_limits() {
        let mut config = LoopConfig {
            offset: 512,
            size_limit: 2048,
            flags: LoopFlags::READ_ONLY,
            file_name: [0; LO_NAME_SIZE],
        };
        config.file_name[..4].copy_from_slice(b"disk");

        let dev = device_id::encode_device_numbers(7, 3);
        let info64 = Info64::from_config(&config, 2, dev, 99);
        let legacy = info64.to_legacy().unwrap();
        assert_eq!(legacy.number, 2);
        assert_eq!(u64::from(legacy.device), (7 << 8) | 3);
        assert_eq!(legacy.inode, 99);
        assert_eq!(legacy.offset, 512);

        let parsed = legacy.to_config().unwrap();
        assert_eq!(parsed.offset, 512);
        assert_eq!(parsed.size_limit, 0);
        assert_eq!(parsed.flags, LoopFlags::READ_ONLY);

        let mut negative = legacy;
        negative.offset = -1;
        assert_eq!(negative.to_config().unwrap_err().error(), Errno::EOVERFLOW);

        let mut large_offset = info64;
        large_offset.offset = i32::MAX as u64 + 1;
        assert_eq!(
            large_offset.to_legacy().unwrap_err().error(),
            Errno::EOVERFLOW
        );

        let mut wide_dev = info64;
        wide_dev.device = device_id::encode_device_numbers(256, 0);
        assert_eq!(wide_dev.to_legacy().unwrap_err().error(), Errno::EOVERFLOW);
    }

    #[ktest]
    fn configure_abi_validates_request() {
        let info = Info64::from_config(&LoopConfig::default(), 0, 0, 0);
        let base = LoopConfigAbi {
            fd: 3,
            block_size: 0,
            info,
            reserved: [0; CONFIGURE_RESERVED_WORDS],
        };

        assert_eq!(base.fd().unwrap(), 3);
        assert!(base.to_config().is_ok());

        let with_512 = LoopConfigAbi {
            block_size: aster_block::SECTOR_SIZE as u32,
            ..base
        };
        assert!(with_512.to_config().is_ok());

        let bad_fd = LoopConfigAbi {
            fd: u32::MAX,
            ..base
        };
        assert_eq!(bad_fd.fd().unwrap_err().error(), Errno::EBADF);

        let bad_block_size = LoopConfigAbi {
            block_size: 1024,
            ..base
        };
        assert_eq!(
            bad_block_size.to_config().unwrap_err().error(),
            Errno::EINVAL
        );

        let mut bad_reserved = base;
        bad_reserved.reserved[0] = 1;
        assert_eq!(bad_reserved.to_config().unwrap_err().error(), Errno::EINVAL);
    }
}
