// SPDX-License-Identifier: MPL-2.0

//! The backing file of an attached loop device and its VFS validation.

use ostd::task::Task;

use super::disk;
use crate::{
    fs::file::{
        FileLike, InodeHandle, InodeType, StatusFlags, SyncMode, file_table::get_file_fast,
    },
    prelude::*,
};

/// A regular file opened to back a loop device.
pub(super) struct BackingFile {
    file: Arc<dyn FileLike>,
    is_writable: bool,
}

impl BackingFile {
    pub(super) fn from_fd(fd: i32) -> Result<Self> {
        let file = {
            let task = Task::current().unwrap();
            let thread_local = task.as_thread_local().ok_or_else(|| {
                Error::with_message(Errno::EBADF, "the current task has no file table")
            })?;
            let mut table = thread_local.borrow_file_table_mut();
            get_file_fast!(&mut table, fd.try_into()?).into_owned()
        };
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
        // Reject files on loop-mounted filesystems and opaque stacking
        // filesystems such as `overlay`, whose underlying layers could reside
        // on a loop device and deadlock the BIO worker.
        let fs = inode_handle.path().fs();
        if fs.sb().container_dev_id.major().get() == disk::LOOP_MAJOR || fs.name() == "overlay" {
            return_errno_with_message!(
                Errno::EINVAL,
                "recursive or stacked loop backing filesystem is not supported"
            );
        }
        let is_writable = inode_handle.access_mode().is_writable();
        Ok(Self { file, is_writable })
    }

    fn inode_handle(&self) -> &InodeHandle {
        self.file
            .as_inode_handle_or_err()
            .expect("loop backing file is always an inode handle")
    }

    pub(super) fn is_writable(&self) -> bool {
        self.is_writable
    }

    pub(super) fn size(&self) -> usize {
        self.inode_handle().path().size()
    }

    pub(super) fn inode_number(&self) -> u64 {
        self.inode_handle().path().inode().ino()
    }

    pub(super) fn device_number(&self) -> Result<u64> {
        Ok(self
            .inode_handle()
            .path()
            .inode()
            .metadata()?
            .container_dev_id
            .as_encoded_u64())
    }

    pub(super) fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        self.inode_handle()
            .read_at_with_flags(offset, writer, StatusFlags::empty())
    }

    /// Writes at `offset` without `O_APPEND` or `O_DIRECT` semantics.
    pub(super) fn write_at(&self, offset: usize, reader: &mut VmReader) -> Result<usize> {
        if !self.is_writable {
            return_errno_with_message!(Errno::EBADF, "loop backing is not opened writable");
        }
        self.inode_handle()
            .write_at_with_flags(offset, reader, StatusFlags::empty())
    }

    pub(super) fn sync(&self) -> Result<()> {
        self.file.sync(SyncMode::Full)
    }
}
