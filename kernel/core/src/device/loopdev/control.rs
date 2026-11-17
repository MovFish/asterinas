// SPDX-License-Identifier: MPL-2.0

//! The `/dev/loop-control` miscellaneous character device.

use device_id::{DeviceId, MinorId};

use super::{
    abi::{ControlAdd, ControlGetFree, ControlRemove},
    check_admin, pool,
};
use crate::{
    device::{Device, DeviceType, misc, registry::char},
    dispatch_ioctl,
    events::IoEvents,
    fs::{
        devtmpfs::DevtmpfsNodeMeta,
        file::{PerOpenFileOps, StatusFlags},
        vfs::{inode::FileOps, path::Path},
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::ioctl::RawIoctl,
};

const LOOP_CTL_MINOR: u32 = 237;

/// Registers `/dev/loop-control` in the character device registry.
pub(super) fn register() -> Result<()> {
    char::register(Arc::new(LoopControl))
}

struct LoopControl;

impl Device for LoopControl {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(misc::major(), MinorId::new(LOOP_CTL_MINOR))
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsNodeMeta> {
        Some(DevtmpfsNodeMeta::new("loop-control").unwrap())
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(Self))
    }
}

impl FileOps for LoopControl {
    fn read_at(
        &self,
        _offset: usize,
        _writer: &mut VmWriter,
        _flags: StatusFlags,
    ) -> Result<usize> {
        return_errno!(Errno::EINVAL);
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _flags: StatusFlags,
    ) -> Result<usize> {
        return_errno!(Errno::EINVAL);
    }
}

impl Pollable for LoopControl {
    fn poll(&self, _mask: IoEvents, _handle: Option<&mut PollHandle>) -> IoEvents {
        IoEvents::empty()
    }
}

impl PerOpenFileOps for LoopControl {
    fn check_seekable(&self) -> Result<()> {
        return_errno!(Errno::ESPIPE);
    }

    fn is_offset_aware(&self) -> bool {
        false
    }

    fn ioctl(&self, _path: &Path, raw_ioctl: RawIoctl) -> Result<i32> {
        check_admin()?;
        let pool = pool()?;
        dispatch_ioctl!(match raw_ioctl {
            _cmd @ ControlGetFree => {
                pool.get_free()
            }
            cmd @ ControlAdd => {
                let number = u32::try_from(cmd.get()).map_err(|_| Error::new(Errno::EINVAL))?;
                pool.add(number)
            }
            cmd @ ControlRemove => {
                let number = u32::try_from(cmd.get()).map_err(|_| Error::new(Errno::EINVAL))?;
                pool.remove(number)
            }
            _ => return_errno!(Errno::ENOTTY),
        })
    }
}
