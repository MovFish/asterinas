// SPDX-License-Identifier: MPL-2.0

use alloc::borrow::ToOwned;
use core::fmt::Write;

use aster_block::{BLOCK_SIZE, BlockDevice as RawBlockDevice, SECTOR_SIZE, bio::BioStatus};
use aster_device::{
    class::{self, Class, ClassDevice, ClassHandle},
    common::{AnyDevice, Attr, DevNum, DeviceType as ModelDeviceType},
    uevent::UeventVars,
};
use aster_nvme::NvmeBlockDevice;
use aster_virtio::device::block::device::BlockDevice as VirtIoBlockDevice;
use device_id::DeviceId;
use ostd::mm::VmIo;
use spin::Once;

use crate::{
    context::current_userspace,
    device::{Device, DeviceType},
    dispatch_ioctl,
    events::IoEvents,
    fs::{
        devtmpfs::DevtmpfsNodeMeta,
        file::{PerOpenFileOps, SettableStatusFlags, StatusFlags, SyncMode},
        vfs::{inode::FileOps, path::Path},
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    thread::kernel_thread::ThreadOptions,
    util::ioctl::RawIoctl,
};

pub(super) fn init_in_first_kthread() {
    match class::register(BlockClass) {
        Ok(class) => {
            BLOCK_CLASS.call_once(|| class);
        }
        Err(error) => warn!("cannot register the block class: {:?}", error),
    }

    for device in aster_block::collect_all() {
        if device.parent_device_id().is_some() {
            continue;
        }

        // Spawn threads for virtio block devices
        if device.downcast_ref::<VirtIoBlockDevice>().is_some() {
            let device_clone = device.clone();
            let task_fn = move || {
                info!("spawn the virtio-block thread");
                let virtio_block_device = device_clone.downcast_ref::<VirtIoBlockDevice>().unwrap();
                loop {
                    virtio_block_device.handle_requests();
                }
            };
            ThreadOptions::new(task_fn).spawn();
        }
        // Spawn threads for NVMe block devices
        else if device.downcast_ref::<NvmeBlockDevice>().is_some() {
            let device_clone = device.clone();
            let task_fn = move || {
                info!("spawn the nvme-block thread");
                let nvme_block_device = device_clone.downcast_ref::<NvmeBlockDevice>().unwrap();
                loop {
                    nvme_block_device.handle_requests();
                }
            };
            ThreadOptions::new(task_fn).spawn();
        }
    }

    // Partition scanning performs synchronous block I/O, so the request
    // handling threads above must be available first.
    aster_block::scan_partitions();

    // Hard-coded devices and partitions enter the registry while the
    // components are initialized. Adopt whole disks first so that each
    // partition can be placed under its disk, then adopt the partitions.
    if BLOCK_CLASS.get().is_none() {
        return;
    }
    let devices = aster_block::collect_all();
    for device in devices
        .iter()
        .filter(|device| device.parent_device_id().is_none())
    {
        if let Err(error) = adopt(device.clone()) {
            warn!("cannot add a block device to the block class: {:?}", error);
        }
    }
    for device in devices
        .iter()
        .filter(|device| device.parent_device_id().is_some())
    {
        if let Err(error) = adopt(device.clone()) {
            warn!("cannot add a partition to the block class: {:?}", error);
        }
    }
}

/// A block device exposed through `/sys/class/block` and `/dev`.
///
/// This is the kernel-side view of a block device. The `aster_block` backend
/// performs I/O, while this trait supplies the file operations used when the
/// device node is opened. Most devices use the generic [`RawBlockFile`]
/// adapter; a device with extra ioctls, such as a loop device, implements this
/// trait directly.
pub(in crate::device) trait BlockDevice: Send + Sync {
    /// Returns the backend registered with `aster_block`.
    fn backend(&self) -> &dyn RawBlockDevice;

    /// Returns an owned handle to the backend.
    fn into_backend(self: Arc<Self>) -> Arc<dyn RawBlockDevice>;

    /// Opens the device for user-space I/O.
    ///
    /// `device` is the registered device-model node. Devices that emit change
    /// events from an open file, such as loop devices, keep a weak reference
    /// to it.
    fn open(self: Arc<Self>, device: &Arc<dyn AnyDevice>) -> Result<Box<dyn PerOpenFileOps>>;

    /// Returns whether the device currently rejects writes.
    fn is_read_only(&self) -> bool {
        false
    }

    /// Returns whether the device can be removed while the system is running.
    fn is_removable(&self) -> bool {
        false
    }
}

/// The `block` class in the device model.
pub(in crate::device) struct BlockClass;

impl Class for BlockClass {
    const NAME: &'static str = "block";
    type Device = Arc<dyn BlockDevice>;

    fn dev_attrs(&self) -> &'static [Attr<BlockDeviceNode>] {
        BLOCK_ATTRS
    }

    fn append_uevent_vars(
        &self,
        _dev: &ClassDevice<Self>,
        _vars: &mut UeventVars,
    ) -> aster_device::common::Result<()> {
        Ok(())
    }
}

const BLOCK_ATTRS: &[Attr<BlockDeviceNode>] =
    &[Attr::ro("size", show_size), Attr::ro("ro", show_read_only)];

/// A block device as represented in the device model.
pub(in crate::device) type BlockDeviceNode = ClassDevice<BlockClass>;

/// A block device whose opened files use the generic block-device operations.
#[derive(Debug)]
struct RawBlockFile(Arc<dyn RawBlockDevice>);

impl RawBlockFile {
    fn new(device: Arc<dyn RawBlockDevice>) -> Self {
        Self(device)
    }
}

impl BlockDevice for RawBlockFile {
    fn backend(&self) -> &dyn RawBlockDevice {
        self.0.as_ref()
    }

    fn into_backend(self: Arc<Self>) -> Arc<dyn RawBlockDevice> {
        self.0.clone()
    }

    fn open(self: Arc<Self>, _device: &Arc<dyn AnyDevice>) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(OpenBlockFile::new(self.0.clone())))
    }
}

impl Device for BlockDeviceNode {
    fn type_(&self) -> DeviceType {
        DeviceType::Block
    }

    fn id(&self) -> DeviceId {
        self.devnum()
            .expect("block devices always have a device number")
            .id()
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsNodeMeta> {
        // The device model creates the devtmpfs node when the device is added.
        None
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        let device = self.to_arc();
        self.payload().clone().open(&device)
    }
}

fn show_size(dev: &BlockDeviceNode, writer: &mut dyn Write) -> aster_device::common::Result<()> {
    writeln!(writer, "{}", dev.payload().backend().metadata().nr_sectors)?;
    Ok(())
}

fn show_read_only(
    dev: &BlockDeviceNode,
    writer: &mut dyn Write,
) -> aster_device::common::Result<()> {
    writeln!(writer, "{}", u8::from(dev.payload().is_read_only()))?;
    Ok(())
}

fn show_removable(
    dev: &BlockDeviceNode,
    writer: &mut dyn Write,
) -> aster_device::common::Result<()> {
    writeln!(writer, "{}", u8::from(dev.payload().is_removable()))?;
    Ok(())
}

/// Adds an already-registered backend to the block class.
fn adopt(device: Arc<dyn RawBlockDevice>) -> Result<Arc<BlockDeviceNode>> {
    let _guard = REGISTRATION_LOCK.lock();
    if let Some(device) = DEVICE_REGISTRY.lock().get(&device.id().to_raw()) {
        return Ok(device.clone());
    }

    add_to_class(Arc::new(RawBlockFile::new(device)))
}

fn add_to_class(device: Arc<dyn BlockDevice>) -> Result<Arc<BlockDeviceNode>> {
    let backend = device.backend();
    let id = backend.id();
    let name = backend.name().to_owned();
    let parent_id = backend.parent_device_id();
    let parent = match parent_id {
        Some(parent_id) => {
            let parent = DEVICE_REGISTRY
                .lock()
                .get(&parent_id.to_raw())
                .cloned()
                .ok_or_else(|| {
                    Error::with_message(Errno::ENOENT, "the parent block device is not registered")
                })?;
            Some(parent)
        }
        None => None,
    };

    let builder = BlockDeviceNode::builder(
        BLOCK_CLASS.get().ok_or_else(|| {
            Error::with_message(Errno::ENODEV, "the block class is not registered")
        })?,
        name,
        device,
    )
    .devnum(DevNum::block(id))
    .dev_type(if parent_id.is_some() {
        &PARTITION_TYPE
    } else {
        &DISK_TYPE
    });
    let builder = match parent {
        Some(parent) => builder.parent(parent),
        None => builder,
    };
    let node = builder.build();

    // Publish the registry entry before the device model creates the
    // `/dev` node and broadcasts the add uevent. Otherwise an opener that
    // reacts to either event can observe the node without its registry entry.
    {
        let mut registry = DEVICE_REGISTRY.lock();
        if registry.contains_key(&id.to_raw()) {
            return_errno_with_message!(Errno::EEXIST, "the block device is already registered");
        }
        registry.insert(id.to_raw(), node.clone());
    }
    if let Err(error) = aster_device::add_device(&node) {
        DEVICE_REGISTRY.lock().remove(&id.to_raw());
        return Err(error.into());
    }

    Ok(node)
}

mod ioctl_defs {
    use crate::{
        ioc,
        util::ioctl::{NoData, OutData},
    };

    // Reference: <https://elixir.bootlin.com/linux/v6.18/source/include/uapi/linux/fs.h>

    /// Returns the device size in bytes.
    pub(super) type BlkGetSize64 = ioc!(BLKGETSIZE64, 0x12, 114, OutData<u64>);

    /// Returns the logical sector size of the block device.
    ///
    /// This is the smallest unit of I/O the device can address and,
    /// importantly, the minimum alignment required for `O_DIRECT` I/O on
    /// files backed by this device. Both buffer address and offset must be a
    /// multiple of this value.
    ///
    /// Benchmarks and filesystem tests (for example, `xfstests`, LTP
    /// `preadv03`/`pwritev03`) rely on this ioctl to size `O_DIRECT` buffers.
    /// If the effective alignment enforced by the filesystem layered on top
    /// is larger than the hardware sector, such as `ext2`'s 4 KiB block, this
    /// ioctl must return that larger value. Otherwise user programs will align
    /// correctly for the device but still hit `EINVAL` at the filesystem.
    pub(super) type BlkGetSectorSize = ioc!(BLKSSZGET, 0x12, 104, NoData);
}

/// Represents an opened block device file ready for I/O operations.
pub(in crate::device) struct OpenBlockFile(Arc<dyn RawBlockDevice>);

impl OpenBlockFile {
    /// Creates an opened file for a block device.
    pub(in crate::device) fn new(device: Arc<dyn RawBlockDevice>) -> Self {
        Self(device)
    }

    fn raw(&self) -> &dyn RawBlockDevice {
        self.0.as_ref()
    }
}

impl FileOps for OpenBlockFile {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let total = writer.avail();
        if total == 0 {
            return Ok(0);
        }

        let device_size = self.raw().metadata().nr_sectors * SECTOR_SIZE;
        if offset >= device_size {
            return Ok(0);
        }

        let read_len = total.min(device_size - offset);
        {
            // `VmIo::read` does not allow short writes,
            // so the writer must be precisely limited here.
            let mut limited_writer = writer.clone_exclusive();
            limited_writer.limit(read_len);
            self.raw().read(offset, &mut limited_writer)?;
        }
        writer.skip(read_len);
        Ok(read_len)
    }

    fn write_at(
        &self,
        offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let total = reader.remain();
        if total == 0 {
            return Ok(0);
        }

        let device_size = self.raw().metadata().nr_sectors * SECTOR_SIZE;
        if offset >= device_size {
            return_errno_with_message!(
                Errno::ENOSPC,
                "the write offset is beyond the block device"
            );
        }

        let write_len = total.min(device_size - offset);
        {
            // `VmIo::write` does not allow short writes,
            // so the reader must be precisely limited here.
            let mut limited_reader = reader.clone();
            limited_reader.limit(write_len);
            self.raw().write(offset, &mut limited_reader)?;
        }
        reader.skip(write_len);
        Ok(write_len)
    }
}

impl Pollable for OpenBlockFile {
    fn poll(&self, mask: IoEvents, _: Option<&mut PollHandle>) -> IoEvents {
        let events = IoEvents::IN | IoEvents::OUT;
        events & mask
    }
}

impl PerOpenFileOps for OpenBlockFile {
    fn check_seekable(&self) -> Result<()> {
        Ok(())
    }

    fn is_offset_aware(&self) -> bool {
        true
    }

    fn seek_end(&self) -> Result<Option<usize>> {
        Ok(Some(self.raw().metadata().nr_sectors * SECTOR_SIZE))
    }

    fn ioctl(&self, _path: &Path, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;

        dispatch_ioctl!(match raw_ioctl {
            _cmd @ BlkGetSectorSize => {
                // TODO: Query the per-device logical block size once block device metadata
                // exposes it. For now, report the effective minimum I/O granularity enforced
                // by Asterinas filesystems so userspace can use `BLKSSZGET` for `O_DIRECT`
                // alignment.
                let sector_size = SECTOR_SIZE.max(BLOCK_SIZE) as i32;
                current_userspace!().write_val(raw_ioctl.arg(), &sector_size)?;
                Ok(0)
            }
            cmd @ BlkGetSize64 => {
                let size = (self.raw().metadata().nr_sectors * SECTOR_SIZE) as u64;
                cmd.write(&size)?;
                Ok(0)
            }
            _ => return_errno_with_message!(
                Errno::ENOTTY,
                "the ioctl command is not supported by block devices"
            ),
        })
    }

    fn settable_status_flags(&self) -> SettableStatusFlags {
        SettableStatusFlags::minimal().with_o_direct()
    }

    fn sync(&self, _mode: SyncMode) -> Result<()> {
        match self.raw().sync()? {
            // Linux treats an unsupported block-device flush as success.
            // Reference: <https://github.com/torvalds/linux/blob/v6.16/block/fops.c#L609-L611>
            BioStatus::Complete | BioStatus::NotSupported => Ok(()),
            status @ (BioStatus::NoSpace | BioStatus::IoError) => Err(status.into()),
            BioStatus::Init | BioStatus::Submit | BioStatus::Zeros => {
                return_errno_with_message!(Errno::EIO, "invalid block device flush status")
            }
        }
    }
}

/// Looks up a block device by its device ID.
pub(super) fn lookup(id: DeviceId) -> Option<Arc<dyn Device>> {
    DEVICE_REGISTRY
        .lock()
        .get(&id.to_raw())
        .cloned()
        .map(|device| device as Arc<dyn Device>)
}

// TODO: The `aster_block` registry and this one are keyed by the same device IDs.
// Keep them one-to-one; the class adoption path is the only place that reads the
// former to build the latter.
static BLOCK_CLASS: Once<Arc<ClassHandle<BlockClass>>> = Once::new();
static DISK_TYPE: ModelDeviceType<BlockDeviceNode> = ModelDeviceType {
    name: "disk",
    attrs: &[Attr::ro("removable", show_removable)],
    devnode: None,
    has_device_link: true,
    append_uevent_vars_fn: None,
};
static PARTITION_TYPE: ModelDeviceType<BlockDeviceNode> = ModelDeviceType::named("partition");
static DEVICE_REGISTRY: Mutex<BTreeMap<u32, Arc<BlockDeviceNode>>> = Mutex::new(BTreeMap::new());

/// Serializes registration and removal so that the two registries and the
/// device model change together for one device ID.
static REGISTRATION_LOCK: Mutex<()> = Mutex::new(());
