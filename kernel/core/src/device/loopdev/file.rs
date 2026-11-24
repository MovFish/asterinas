// SPDX-License-Identifier: MPL-2.0

//! Opened `/dev/loopN` file operations.
//!
//! Composes [`OpenBlockFile`] with loop open tracking, read-only enforcement,
//! and `LOOP_*` ioctl handling.

use aster_block::BlockDevice;
use ostd::task::Task;

use super::{
    disk::{self, LoopDisk},
    ioctl_defs,
};
use crate::{
    device::registry::OpenBlockFile,
    dispatch_ioctl,
    events::IoEvents,
    fs::{
        file::{PerOpenFileOps, SettableStatusFlags, StatusFlags, SyncMode},
        vfs::{inode::FileOps, path::Path},
    },
    prelude::*,
    process::{
        UserNamespace,
        credentials::capabilities::CapSet,
        posix_thread::AsPosixThread,
        signal::{PollHandle, Pollable},
    },
    security::lsm::hooks::{self as lsm_hook, CapableContext},
    util::ioctl::RawIoctl,
};

/// Opens a loop block device, returning a [`LoopFile`] layered over [`OpenBlockFile`].
pub(super) fn open(device: Arc<BlockDevice>) -> Result<Box<dyn PerOpenFileOps>> {
    super::loop_disk(&device).try_open()?;
    Ok(Box::new(LoopFile(OpenBlockFile::new(device))))
}

struct LoopFile(OpenBlockFile);

impl LoopFile {
    fn disk(&self) -> &LoopDisk {
        super::loop_disk(self.0.device())
    }
}

impl Drop for LoopFile {
    fn drop(&mut self) {
        self.disk().close();
    }
}

impl FileOps for LoopFile {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        status_flags: StatusFlags,
    ) -> Result<usize> {
        self.0.read_at(offset, writer, status_flags)
    }

    fn write_at(
        &self,
        offset: usize,
        reader: &mut VmReader,
        status_flags: StatusFlags,
    ) -> Result<usize> {
        if !reader.has_remain() {
            return Ok(0);
        }
        if self.disk().is_read_only() {
            return_errno_with_message!(Errno::EPERM, "the loop device is read-only");
        }
        self.0.write_at(offset, reader, status_flags)
    }
}

impl Pollable for LoopFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.0.poll(mask, poller)
    }
}

impl PerOpenFileOps for LoopFile {
    fn check_seekable(&self) -> Result<()> {
        self.0.check_seekable()
    }

    fn is_offset_aware(&self) -> bool {
        self.0.is_offset_aware()
    }

    fn seek_end(&self) -> Result<Option<usize>> {
        self.0.seek_end()
    }

    fn settable_status_flags(&self) -> SettableStatusFlags {
        self.0.settable_status_flags()
    }

    fn sync(&self, mode: SyncMode) -> Result<()> {
        self.0.sync(mode)
    }

    fn ioctl(&self, path: &Path, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;
        let device = self.0.device();
        let disk = self.disk();
        // TODO: Once `Device::open` receives `AccessMode`, allow modifying
        // ioctls on writable `/dev/loopN` descriptors without `CAP_SYS_ADMIN`,
        // matching Linux's `(mode & BLK_OPEN_WRITE) || capable(CAP_SYS_ADMIN)`.
        dispatch_ioctl!(match raw_ioctl {
            cmd @ SetFd => {
                check_admin()?;
                disk.attach(cmd.get(), Default::default())?;
                disk::emit_change(device);
                Ok(0)
            }
            cmd @ Configure => {
                check_admin()?;
                let config = cmd.read()?;
                let fd = config.fd()?;
                disk.attach(fd, config.to_config()?)?;
                disk::emit_change(device);
                Ok(0)
            }
            _cmd @ ClearFd => {
                check_admin()?;
                disk.detach()?;
                disk::emit_change(device);
                Ok(0)
            }
            cmd @ SetStatus => {
                check_admin()?;
                let config = cmd.read()?.to_config()?;
                if disk.set_status(config)? {
                    disk::emit_change(device);
                }
                Ok(0)
            }
            cmd @ GetStatus => {
                cmd.write(&disk.status()?.to_legacy()?)?;
                Ok(0)
            }
            cmd @ SetStatus64 => {
                check_admin()?;
                let config = cmd.read()?.to_config()?;
                if disk.set_status(config)? {
                    disk::emit_change(device);
                }
                Ok(0)
            }
            cmd @ GetStatus64 => {
                cmd.write(&disk.status()?)?;
                Ok(0)
            }
            _cmd @ SetCapacity => {
                check_admin()?;
                if disk.set_capacity()? {
                    disk::emit_change(device);
                }
                Ok(0)
            }
            _ => self.0.ioctl(path, raw_ioctl),
        })
    }
}

fn check_admin() -> Result<()> {
    let task = Task::current().ok_or_else(|| Error::new(Errno::EPERM))?;
    let posix_thread = task
        .as_posix_thread()
        .ok_or_else(|| Error::new(Errno::EPERM))?;
    lsm_hook::on_capable(CapableContext::new(
        UserNamespace::get_init_singleton().as_ref(),
        posix_thread,
        CapSet::SYS_ADMIN,
    ))
}
