// SPDX-License-Identifier: MPL-2.0

//! Loop block devices and the `/dev/loop-control` character device.
//!
//! Each loop device is a member of the shared [`BlockClass`] in the device
//! model (`/sys/class/block` and `/dev/loopN`). It is registered through the
//! canonical block registration entry, which keeps `aster_block` and the block
//! class in sync. A BIO worker exists only while a backing file is attached;
//! the generic block file keeps the weak device-model handle used for `change`
//! uevents.
//!
//! [`BlockClass`]: crate::device::registry::block::BlockClass

mod abi;
mod backing;
mod control;
mod disk;
mod ops;

use alloc::format;

use aster_block::{BlockDevice as RawBlockDevice, MajorIdOwner};
use device_id::MajorId;
use ostd::task::Task;
use spin::Once;

use self::disk::LoopDisk;
use super::registry::block;
use crate::{
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread},
    security::lsm::hooks::{self as lsm_hook, CapableContext},
};

const INITIAL_DISKS: u32 = 8;
const MAX_DISKS: u32 = 256;

static POOL: Once<Pool> = Once::new();
static LOOP_MAJOR_OWNER: Once<MajorIdOwner> = Once::new();

/// Initializes loop block devices and `/dev/loop-control`.
///
/// Failures are logged rather than propagated so that loop support remains
/// optional and cannot prevent the kernel from booting.
pub(super) fn init_in_first_kthread() {
    if let Err(error) = init_devices() {
        warn!("cannot initialize loop devices: {:?}", error);
    }
}

fn init_devices() -> Result<()> {
    let major = aster_block::acquire_major(MajorId::new(disk::LOOP_MAJOR))
        .map_err(|_| Error::with_message(Errno::EBUSY, "loop major is already allocated"))?;
    LOOP_MAJOR_OWNER.call_once(|| major);

    let pool = POOL.call_once(|| Pool {
        devices: Mutex::new(BTreeMap::new()),
    });
    for number in 0..INITIAL_DISKS {
        pool.add(number)?;
    }
    control::register()?;
    Ok(())
}

pub(super) struct Pool {
    devices: Mutex<BTreeMap<u32, Arc<LoopDisk>>>,
}

impl Pool {
    pub(super) fn add(&self, number: u32) -> Result<i32> {
        let mut devices = self.devices.lock();
        self.add_locked(number, &mut devices)
    }

    fn add_locked(&self, number: u32, devices: &mut BTreeMap<u32, Arc<LoopDisk>>) -> Result<i32> {
        if number >= MAX_DISKS {
            return_errno!(Errno::ENOSPC);
        }
        if devices.contains_key(&number) {
            return_errno!(Errno::EEXIST);
        }
        let name = format!("loop{number}");
        let disk = LoopDisk::new(number, name);
        block::register(disk.clone())?;
        devices.insert(number, disk);
        Ok(number as i32)
    }

    pub(super) fn remove(&self, number: u32) -> Result<i32> {
        let mut devices = self.devices.lock();
        let disk = devices
            .get(&number)
            .cloned()
            .ok_or_else(|| Error::new(Errno::ENODEV))?;
        disk.prepare_remove()?;
        if let Err(error) = block::unregister(disk.id()) {
            disk.restore_detached();
            return Err(error);
        }
        devices.remove(&number);
        Ok(0)
    }

    pub(super) fn get_free(&self) -> Result<i32> {
        let mut devices = self.devices.lock();
        for (&number, disk) in devices.iter() {
            if disk.is_free() {
                return Ok(number as i32);
            }
        }
        let number = (0..MAX_DISKS)
            .find(|number| !devices.contains_key(number))
            .ok_or_else(|| Error::new(Errno::ENOSPC))?;
        self.add_locked(number, &mut devices)
    }
}

pub(super) fn pool() -> Result<&'static Pool> {
    POOL.get()
        .ok_or_else(|| Error::with_message(Errno::ENODEV, "loop devices are not initialized"))
}

pub(super) fn check_admin() -> Result<()> {
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
