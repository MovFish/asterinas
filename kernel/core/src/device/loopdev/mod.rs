// SPDX-License-Identifier: MPL-2.0

//! Loop block devices and the `/dev/loop-control` character device.
//!
//! Each loop device is an [`aster_block::BlockDevice`] (`ClassDevice<BlockClass>`)
//! created in the shared block class, exposing `/dev/loopN`, `/sys/block/loopN`,
//! and `/sys/class/block/loopN` through `aster_device`. A BIO worker exists only
//! while a backing file is attached, and opening `/dev/loopN` is handled by
//! [`file::open`] registered for the loop major ID.

mod backing;
mod c_types;
mod control;
mod disk;
mod file;
mod ioctl_defs;

use alloc::format;

use aster_block::{AnyBlockDevice, BlockDevice, MajorIdOwner};
use aster_device::common::DevNum;
use device_id::MajorId;
use spin::Once;

use self::disk::LoopDisk;
use crate::{device::registry, prelude::*};

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
    registry::register_opener(&major, file::open);

    let mut initial_devices = BTreeMap::new();
    for number in 0..INITIAL_DISKS {
        if let Err(error) = add_device_locked(number, &mut initial_devices) {
            rollback_devices(&mut initial_devices);
            return Err(error);
        }
    }

    if let Err(error) = control::register() {
        rollback_devices(&mut initial_devices);
        return Err(error);
    }

    LOOP_MAJOR_OWNER.call_once(|| major);
    POOL.call_once(|| Pool {
        devices: Mutex::new(initial_devices),
    });
    Ok(())
}

fn rollback_devices(devices: &mut BTreeMap<u32, Arc<BlockDevice>>) {
    for (_, device) in core::mem::take(devices) {
        if let Err(error) = aster_device::remove_device(&device) {
            warn!(
                "failed to roll back loop device {}: {:?}",
                device.name(),
                error
            );
        }
    }
}

fn add_device_locked(number: u32, devices: &mut BTreeMap<u32, Arc<BlockDevice>>) -> Result<i32> {
    if number >= MAX_DISKS {
        return_errno!(Errno::ENOSPC);
    }
    if devices.contains_key(&number) {
        return_errno!(Errno::EEXIST);
    }
    let block_class = aster_block::BLOCK_CLASS
        .get()
        .ok_or_else(|| Error::with_message(Errno::ENODEV, "the block class is not registered"))?;
    let name = format!("loop{number}");
    let disk = LoopDisk::new(number, name.clone());
    let id = disk.id();
    let device = BlockDevice::builder(block_class, name, Box::new(disk))
        .dev_type(&aster_block::DISK_TYPE)
        .devnum(DevNum::block(id))
        .build();
    aster_device::add_device(&device)?;
    devices.insert(number, device);
    Ok(number as i32)
}

fn next_unused_number(devices: &BTreeMap<u32, Arc<BlockDevice>>) -> Result<u32> {
    (0..MAX_DISKS)
        .find(|number| !devices.contains_key(number))
        .ok_or_else(|| Error::new(Errno::ENOSPC))
}

pub(super) struct Pool {
    devices: Mutex<BTreeMap<u32, Arc<BlockDevice>>>,
}

impl Pool {
    pub(super) fn add(&self, number: u32) -> Result<i32> {
        let mut devices = self.devices.lock();
        add_device_locked(number, &mut devices)
    }

    pub(super) fn add_any(&self) -> Result<i32> {
        let mut devices = self.devices.lock();
        let number = next_unused_number(&devices)?;
        add_device_locked(number, &mut devices)
    }

    pub(super) fn remove(&self, number: u32) -> Result<i32> {
        let mut devices = self.devices.lock();
        let device = devices
            .get(&number)
            .cloned()
            .ok_or_else(|| Error::new(Errno::ENODEV))?;
        let disk = loop_disk(&device);
        disk.prepare_remove()?;
        if let Err(error) = aster_device::remove_device(&device) {
            disk.restore_detached();
            return Err(error.into());
        }
        devices.remove(&number);
        Ok(0)
    }

    pub(super) fn get_free(&self) -> Result<i32> {
        let mut devices = self.devices.lock();
        for (&number, device) in devices.iter() {
            if loop_disk(device).is_free() {
                return Ok(number as i32);
            }
        }
        let number = next_unused_number(&devices)?;
        add_device_locked(number, &mut devices)
    }
}

fn loop_disk(device: &BlockDevice) -> &LoopDisk {
    device
        .payload()
        .downcast_ref::<LoopDisk>()
        .expect("pool entries are always loop disks")
}

pub(super) fn pool() -> Result<&'static Pool> {
    POOL.get()
        .ok_or_else(|| Error::with_message(Errno::ENODEV, "loop devices are not initialized"))
}
