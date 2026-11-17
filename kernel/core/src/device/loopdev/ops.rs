// SPDX-License-Identifier: MPL-2.0

//! The loop driver hooks used by the generic block device file.

use aster_block::BlockDevice;
use aster_device::{
    common::AnyDevice,
    uevent::{self, UeventAction},
};

use super::{abi, check_admin, disk::LoopDisk};
use crate::{
    device::registry::block::RegisteredBlockDevice, dispatch_ioctl, prelude::*,
    util::ioctl::RawIoctl,
};

/// Emits a change event after a disk transition.
///
/// The device-model node may have been removed while the file is open, in
/// which case there is nothing left to notify. A failed broadcast cannot undo
/// a completed disk transition.
fn emit_change(device: Option<&dyn AnyDevice>) {
    let Some(device) = device else {
        return;
    };
    if let Err(error) = uevent::emit(device, UeventAction::Change) {
        warn!("failed to broadcast loop change: {:?}", error);
    }
}

impl RegisteredBlockDevice for LoopDisk {
    fn backend(&self) -> &dyn BlockDevice {
        self
    }

    fn into_backend(self: Arc<Self>) -> Arc<dyn BlockDevice> {
        self
    }

    fn open(&self) -> Result<()> {
        self.try_open()
    }

    fn release(&self) {
        self.close();
    }

    fn ioctl(&self, device: Option<&dyn AnyDevice>, raw_ioctl: RawIoctl) -> Result<i32> {
        use abi::*;
        dispatch_ioctl!(match raw_ioctl {
            cmd @ SetFd => {
                check_admin()?;
                self.attach(cmd.get())?;
                emit_change(device);
                Ok(0)
            }
            _cmd @ ClearFd => {
                check_admin()?;
                self.detach()?;
                emit_change(device);
                Ok(0)
            }
            cmd @ SetStatus => {
                check_admin()?;
                let config = cmd.read()?.to_config()?;
                if self.set_status(config)? {
                    emit_change(device);
                }
                Ok(0)
            }
            cmd @ GetStatus => {
                cmd.write(&self.status()?.to_legacy()?)?;
                Ok(0)
            }
            cmd @ SetStatus64 => {
                check_admin()?;
                let config = cmd.read()?.to_config()?;
                if self.set_status(config)? {
                    emit_change(device);
                }
                Ok(0)
            }
            cmd @ GetStatus64 => {
                cmd.write(&self.status()?)?;
                Ok(0)
            }
            _cmd @ SetCapacity => {
                check_admin()?;
                if self.set_capacity()? {
                    emit_change(device);
                }
                Ok(0)
            }
            _ => return_errno!(Errno::ENOTTY),
        })
    }

    fn is_read_only(&self) -> bool {
        LoopDisk::is_read_only(self)
    }
}
