// SPDX-License-Identifier: MPL-2.0

//! The backing file of an attached loop device and its VFS validation.

use ostd::task::Task;

use super::disk::LOOP_MAJOR;
use crate::{
    fs::file::{FileLike, InodeType, StatusFlags, SyncMode, file_table::get_file_fast},
    prelude::*,
};

/// A regular file opened to back a loop device.
pub(super) struct BackingFile {
    file: Arc<dyn FileLike>,
    writable: bool,
}

impl BackingFile {
    pub(super) fn from_fd(fd: i32) -> Result<Self> {
        let task = Task::current().unwrap();
        let thread_local = task.as_thread_local().ok_or_else(|| {
            Error::with_message(Errno::EBADF, "the current task has no file table")
        })?;
        let mut table = thread_local.borrow_file_table_mut();
        let file = get_file_fast!(&mut table, fd.try_into()?).into_owned();
        let inode_handle = file.as_inode_handle_or_err()?;
        if inode_handle.status_flags().contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "loop backing is an O_PATH descriptor");
        }
        if inode_handle.path().type_() != InodeType::File {
            return_errno_with_message!(Errno::EINVAL, "loop backing must be a regular file");
        }
        if !inode_handle.access_mode().is_readable() {
            return_errno_with_message!(Errno::EBADF, "loop backing is not readable");
        }
        // A regular inode may itself live on a loop-mounted filesystem. Reject
        // those and opaque stacking filesystems until their dependencies can be
        // traversed; otherwise a BIO worker can recursively wait on itself.
        let (major, _) = device_id::decode_device_numbers(
            inode_handle
                .path()
                .fs()
                .sb()
                .container_dev_id
                .as_encoded_u64(),
        );
        if major == u32::from(LOOP_MAJOR)
            || !matches!(
                inode_handle.path().fs().name(),
                "ramfs" | "rootfs" | "tmpfs" | "ext2" | "exfat" | "virtiofs"
            )
        {
            return_errno_with_message!(
                Errno::EINVAL,
                "unsupported or recursive loop backing filesystem"
            );
        }
        let writable = inode_handle.access_mode().is_writable();
        Ok(Self { file, writable })
    }

    pub(super) fn is_writable(&self) -> bool {
        self.writable
    }

    pub(super) fn size(&self) -> usize {
        self.file.path().size()
    }

    pub(super) fn inode_number(&self) -> u64 {
        self.file.path().inode().ino()
    }

    pub(super) fn device_number(&self) -> u64 {
        self.file.path().fs().sb().container_dev_id.as_encoded_u64()
    }

    pub(super) fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        self.file
            .path()
            .inode()
            .read_at(offset, writer, StatusFlags::empty())
    }

    /// Writes without append or direct-I/O semantics, clearing privilege bits.
    ///
    /// Kernel workers have no user credentials, so writes conservatively clear
    /// set-ID bits and file capabilities without relying on `PosixThread` state.
    pub(super) fn write_at(&self, offset: usize, reader: &mut VmReader) -> Result<usize> {
        if !self.is_writable() {
            return_errno_with_message!(Errno::EBADF, "loop backing is not opened writable");
        }
        let path = self.file.path();
        if reader.remain() != 0 {
            path.clear_file_priv()?;
        }
        path.inode().write_at(offset, reader, StatusFlags::empty())
    }

    pub(super) fn sync(&self) -> Result<()> {
        self.file.sync(SyncMode::Full)
    }
}
