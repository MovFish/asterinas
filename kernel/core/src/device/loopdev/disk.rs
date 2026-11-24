// SPDX-License-Identifier: MPL-2.0

//! The loop block device core: runtime configuration, attachment state, and BIO worker.

use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use aster_block::{
    AnyBlockDevice, BlockDevice, BlockDeviceKind, BlockDeviceMeta, WholeDisk,
    bio::{BioEnqueueError, BioSegment, BioStatus, BioType, SubmittedBio},
};
use aster_device::uevent::{self, UeventAction};
use device_id::{DeviceId, MajorId, MinorId};
use ostd::{mm::io::util::HasVmReaderWriter, sync::WaitQueue};

use super::{
    backing::BackingFile,
    c_types::{self, Info64},
};
use crate::{prelude::*, thread::kernel_thread::ThreadOptions};

pub(super) const LOOP_MAJOR: u16 = 7;
const MAX_NR_SEGMENTS_PER_BIO: usize = 128;

bitflags! {
    /// Linux `lo_flags`.
    ///
    /// Unsupported flags (`AUTOCLEAR`, `PARTSCAN`, `DIRECT_IO`) are rejected
    /// rather than silently ignored.
    ///
    /// TODO: Support `LO_FLAGS_AUTOCLEAR` and reject detaching a mounted loop
    /// device once mounted filesystems hold an open lease on their underlying
    /// block device.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) struct LoopFlags: u32 {
        /// The device rejects writes.
        const READ_ONLY = 1;
    }
}

/// The runtime configuration of an attached loop device.
#[derive(Clone, Copy, Debug)]
pub(super) struct LoopConfig {
    pub offset: u64,
    pub size_limit: u64,
    pub flags: LoopFlags,
    pub file_name: [u8; c_types::LO_NAME_SIZE],
}

impl Default for LoopConfig {
    /// Returns the default configuration applied by `LOOP_SET_FD`, which binds without a window.
    fn default() -> Self {
        Self {
            offset: 0,
            size_limit: 0,
            flags: LoopFlags::empty(),
            file_name: [0; c_types::LO_NAME_SIZE],
        }
    }
}

impl LoopConfig {
    /// Forces `READ_ONLY` on this configuration.
    pub(super) fn into_read_only(mut self) -> Self {
        self.flags.insert(LoopFlags::READ_ONLY);
        self
    }
}

/// A loop block device backend.
///
/// Lock order: `Pool.devices` -> `state` -> `config` -> `active`/`geometry`/`queue`.
///
/// State transitions release `state` before broadcasting a uevent: broadcasting
/// takes subsystem locks of its own and must never run under a lock that a
/// concurrent opener needs.
pub(super) struct LoopDisk {
    number: u32,
    name: String,
    state: Mutex<LoopState>,
    /// Fast path for BIO submission and metadata reads.
    active: SpinLock<Option<Arc<AttachedLoop>>>,
}

/// The mutable state of a loop disk.
struct LoopState {
    disk: DiskState,
    /// The number of open block-device file handles.
    opens: usize,
}

enum DiskState {
    Detached,
    Attached(Arc<AttachedLoop>),
    Removed,
}

struct AttachedLoop {
    file: BackingFile,
    /// Serializes `set_status`/`set_capacity` with the single worker's I/O.
    config: Mutex<LoopConfig>,
    /// Kept consistent with `config` under `config`.
    geometry: SpinLock<Geometry>,
    /// Shared with the worker.
    ///
    /// This is a sleeping mutex (like `aster_block::request_queue`): the queue
    /// is unbounded, so enqueueing may allocate, which must not happen under a
    /// spinlock held with interrupts disabled.
    queue: Mutex<BioQueue>,
    work: WaitQueue,
    drained: WaitQueue,
    pending: AtomicUsize,
    /// Signaled after the worker thread has dropped its `AttachedLoop` reference.
    exit: Arc<WorkerExit>,
}

/// Completion notification for the worker thread.
///
/// Kept outside [`AttachedLoop`] so that the thread can drop its reference
/// before notifying `wait_worker`.
struct WorkerExit {
    exited: AtomicBool,
    done: WaitQueue,
}

impl WorkerExit {
    fn new() -> Self {
        Self {
            exited: AtomicBool::new(false),
            done: WaitQueue::new(),
        }
    }

    fn notify(&self) {
        self.exited.store(true, Ordering::Release);
        self.done.wake_all();
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Geometry {
    nr_sectors: usize,
    read_only: bool,
}

struct BioQueue {
    bios: VecDeque<SubmittedBio>,
    accepting: bool,
    stopped: bool,
}

#[derive(Clone, Copy)]
enum TransferDirection {
    Read,
    Write,
}

impl AttachedLoop {
    fn new(file: BackingFile, config: LoopConfig) -> Self {
        let config = if file.is_writable() {
            config
        } else {
            config.into_read_only()
        };
        let geometry = geometry(&file, &config);
        Self {
            file,
            config: Mutex::new(config),
            geometry: SpinLock::new(geometry),
            queue: Mutex::new(BioQueue {
                bios: VecDeque::new(),
                accepting: true,
                stopped: false,
            }),
            work: WaitQueue::new(),
            drained: WaitQueue::new(),
            pending: AtomicUsize::new(0),
            exit: Arc::new(WorkerExit::new()),
        }
    }

    fn start(self: &Arc<Self>) {
        let attached = self.clone();
        let exit = self.exit.clone();
        ThreadOptions::new(move || {
            attached.worker();
            drop(attached);
            exit.notify();
        })
        .spawn();
    }

    fn enqueue(&self, bio: SubmittedBio) -> core::result::Result<(), BioEnqueueError> {
        let mut queue = self.queue.lock();
        if !queue.accepting || queue.stopped {
            drop(queue);
            // A flush racing with detach must behave like one issued just
            // after the device reached `Detached`: the detach path syncs the
            // backing file itself before switching states, so there is nothing
            // left to flush. Every other request is refused because the worker
            // is no longer guaranteed to run.
            if bio.type_() == BioType::Flush {
                bio.complete(BioStatus::Complete);
                return Ok(());
            }
            return Err(BioEnqueueError::Refused);
        }
        self.pending.fetch_add(1, Ordering::Relaxed);
        queue.bios.push_back(bio);
        drop(queue);
        self.work.wake_one();
        Ok(())
    }

    fn worker(&self) {
        loop {
            let next = self.work.wait_until(|| {
                let mut queue = self.queue.lock();
                if let Some(bio) = queue.bios.pop_front() {
                    Some(Some(bio))
                } else if queue.stopped {
                    Some(None)
                } else {
                    None
                }
            });
            let Some(bio) = next else { break };
            let status = match self.perform(&bio) {
                Ok(()) => BioStatus::Complete,
                Err(error) if error.error() == Errno::ENOSPC => BioStatus::NoSpace,
                Err(_) => BioStatus::IoError,
            };
            bio.complete(status);
            self.pending.fetch_sub(1, Ordering::Release);
            self.drained.wake_all();
        }
    }

    fn perform(&self, bio: &SubmittedBio) -> Result<()> {
        let config = self.config.lock();
        let geometry = *self.geometry.disable_irq().lock();
        match bio.type_() {
            BioType::Flush => self.file.sync(),
            BioType::Read => self.transfer(bio, &config, geometry, TransferDirection::Read),
            BioType::Write => {
                if geometry.read_only {
                    return_errno!(Errno::EPERM);
                }
                self.transfer(bio, &config, geometry, TransferDirection::Write)
            }
        }
    }

    fn transfer(
        &self,
        bio: &SubmittedBio,
        config: &LoopConfig,
        geometry: Geometry,
        direction: TransferDirection,
    ) -> Result<()> {
        let start_sector = bio
            .sid_range()
            .start
            .to_raw()
            .checked_add(bio.sid_offset())
            .ok_or_else(|| Error::new(Errno::EIO))?;
        let end_sector = bio
            .sid_range()
            .end
            .to_raw()
            .checked_add(bio.sid_offset())
            .ok_or_else(|| Error::new(Errno::EIO))?;
        if start_sector > end_sector || end_sector > geometry.nr_sectors as u64 {
            return_errno!(Errno::EIO);
        }
        let mut offset = usize::try_from(start_sector)
            .ok()
            .and_then(|sector| sector.checked_mul(aster_block::SECTOR_SIZE))
            .and_then(|offset| offset.checked_add(config.offset as usize))
            .ok_or_else(|| Error::new(Errno::EIO))?;
        let expected = usize::try_from(end_sector - start_sector)
            .ok()
            .and_then(|sectors| sectors.checked_mul(aster_block::SECTOR_SIZE))
            .ok_or_else(|| Error::new(Errno::EIO))?;
        let actual = bio
            .segments()
            .iter()
            .try_fold(0usize, |total, segment| total.checked_add(segment.nbytes()))
            .ok_or_else(|| Error::new(Errno::EIO))?;
        if actual != expected {
            return_errno!(Errno::EIO);
        }

        let transfer_fn: fn(&BackingFile, &mut usize, &BioSegment) -> Result<()> = match direction {
            TransferDirection::Read => read_segment,
            TransferDirection::Write => write_segment,
        };
        for segment in bio.segments() {
            transfer_fn(&self.file, &mut offset, segment)?;
        }
        Ok(())
    }

    fn stop_accepting(&self) {
        self.queue.lock().accepting = false;
    }

    fn resume(&self) {
        self.queue.lock().accepting = true;
    }

    fn wait_drained(&self) {
        self.drained
            .wait_until(|| (self.pending.load(Ordering::Acquire) == 0).then_some(()));
    }

    fn stop(&self) {
        self.queue.lock().stopped = true;
        self.work.wake_all();
    }

    fn wait_worker(&self) {
        self.exit
            .done
            .wait_until(|| self.exit.exited.load(Ordering::Acquire).then_some(()));
    }
}

fn read_segment(file: &BackingFile, offset: &mut usize, segment: &BioSegment) -> Result<()> {
    let mut writer = segment.dma_slice().writer()?.to_fallible();
    while writer.avail() != 0 {
        let count = file.read_at(*offset, &mut writer)?;
        if count == 0 {
            // The backing file was truncated below the device window. Linux
            // reads zeroes for the missing tail instead of failing the BIO.
            let remaining = writer.avail();
            writer.fill_zeros(remaining)?;
            break;
        }
        *offset = offset
            .checked_add(count)
            .ok_or_else(|| Error::new(Errno::EIO))?;
    }
    Ok(())
}

fn write_segment(file: &BackingFile, offset: &mut usize, segment: &BioSegment) -> Result<()> {
    let mut reader = segment.dma_slice().reader()?.to_fallible();
    while reader.remain() != 0 {
        let count = file.write_at(*offset, &mut reader)?;
        if count == 0 {
            return_errno!(Errno::EIO);
        }
        *offset = offset
            .checked_add(count)
            .ok_or_else(|| Error::new(Errno::EIO))?;
    }
    Ok(())
}

fn geometry(file: &BackingFile, config: &LoopConfig) -> Geometry {
    Geometry {
        nr_sectors: capacity(file, config),
        read_only: config.flags.contains(LoopFlags::READ_ONLY),
    }
}

fn capacity(file: &BackingFile, config: &LoopConfig) -> usize {
    capacity_sectors(file.size(), config.offset, config.size_limit)
}

fn capacity_sectors(file_size: usize, offset: u64, size_limit: u64) -> usize {
    let available = file_size.saturating_sub(offset as usize);
    let bytes = if size_limit == 0 {
        available
    } else {
        available.min(size_limit as usize)
    };
    bytes / aster_block::SECTOR_SIZE
}

/// Emits a `change` uevent after a loop disk transition.
///
/// A failed broadcast cannot undo a completed transition, so it is only logged.
pub(super) fn emit_change(device: &BlockDevice) {
    if let Err(error) = uevent::emit(device, UeventAction::Change) {
        warn!("failed to broadcast loop change: {:?}", error);
    }
}

impl LoopDisk {
    pub(super) fn new(number: u32, name: String) -> Self {
        Self {
            number,
            name,
            state: Mutex::new(LoopState {
                disk: DiskState::Detached,
                opens: 0,
            }),
            active: SpinLock::new(None),
        }
    }

    /// Returns the current sector capacity for block metadata.
    fn nr_sectors(&self) -> usize {
        self.active
            .disable_irq()
            .lock()
            .as_ref()
            .map_or(0, |attached| {
                attached.geometry.disable_irq().lock().nr_sectors
            })
    }

    /// Returns whether the loop device is currently read-only.
    pub(super) fn is_read_only(&self) -> bool {
        self.active
            .disable_irq()
            .lock()
            .as_ref()
            .is_some_and(|attached| attached.geometry.disable_irq().lock().read_only)
    }

    /// Returns whether `LOOP_CTL_GET_FREE` may hand out this device.
    pub(super) fn is_free(&self) -> bool {
        // Read the `active` spinlock snapshot instead of `state`: detach holds
        // `state` across a blocking `file.sync()`, and probing for a free
        // device must not stall behind it. A removed disk is never observed
        // here because `Pool::remove` unregisters it under `Pool.devices`.
        self.active.disable_irq().lock().is_none()
    }

    pub(super) fn try_open(&self) -> Result<()> {
        let mut state = self.state.lock();
        if matches!(state.disk, DiskState::Removed) {
            return_errno!(Errno::ENODEV);
        }
        state.opens += 1;
        Ok(())
    }

    pub(super) fn close(&self) {
        let mut state = self.state.lock();
        debug_assert!(state.opens > 0, "unbalanced loop device close");
        state.opens -= 1;
    }

    /// Marks the device removed if it has no opens and no backing file.
    pub(super) fn prepare_remove(&self) -> Result<()> {
        let mut state = self.state.lock();
        if state.opens != 0 {
            return_errno!(Errno::EBUSY);
        }
        match state.disk {
            DiskState::Detached => {
                state.disk = DiskState::Removed;
                Ok(())
            }
            DiskState::Attached(_) => return_errno!(Errno::EBUSY),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        }
    }

    /// Restores a detached state if registration removal failed.
    pub(super) fn restore_detached(&self) {
        let mut state = self.state.lock();
        if matches!(state.disk, DiskState::Removed) {
            state.disk = DiskState::Detached;
        }
    }

    /// Binds a backing file and publishes the attachment.
    pub(super) fn attach(&self, fd: i32, config: LoopConfig) -> Result<()> {
        let mut state = self.state.lock();
        match state.disk {
            DiskState::Detached => {}
            DiskState::Attached(_) => return_errno!(Errno::EBUSY),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        }
        let file = BackingFile::from_fd(fd)?;
        let attached = Arc::new(AttachedLoop::new(file, config));
        // Start the worker before publishing the attachment, so an opener
        // cannot reach a queue that nobody serves.
        attached.start();
        *self.active.disable_irq().lock() = Some(attached.clone());
        state.disk = DiskState::Attached(attached);
        Ok(())
    }

    /// Detaches the backing file.
    ///
    /// Fails with `EBUSY` if other openers hold the device.
    pub(super) fn detach(&self) -> Result<()> {
        let mut state = self.state.lock();
        let attached = match &state.disk {
            DiskState::Attached(attached) => attached.clone(),
            DiskState::Detached => return_errno!(Errno::ENXIO),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        };
        if state.opens > 1 {
            return_errno_with_message!(Errno::EBUSY, "the loop device has other openers");
        }
        attached.stop_accepting();
        attached.wait_drained();
        if let Err(error) = attached.file.sync() {
            attached.resume();
            return Err(error);
        }
        attached.stop();
        attached.wait_worker();
        *self.active.disable_irq().lock() = None;
        state.disk = DiskState::Detached;
        Ok(())
    }

    pub(super) fn status(&self) -> Result<Info64> {
        let state = self.state.lock();
        let attached = match &state.disk {
            DiskState::Attached(attached) => attached,
            DiskState::Detached => return_errno!(Errno::ENXIO),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        };
        let config = attached.config.lock();
        let device = attached.file.device_number()?;
        Ok(Info64::from_config(
            &config,
            self.number,
            device,
            attached.file.inode_number(),
        ))
    }

    /// Applies a new status while preserving the binding-derived read-only flag.
    ///
    /// Linux never lets `LOOP_SET_STATUS*` toggle `LO_FLAGS_READ_ONLY`; only
    /// binding a backing file decides it. Returns whether the capacity changed.
    pub(super) fn set_status(&self, mut config: LoopConfig) -> Result<bool> {
        let state = self.state.lock();
        let attached = match &state.disk {
            DiskState::Attached(attached) => attached,
            DiskState::Detached => return_errno!(Errno::ENXIO),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        };
        let mut current = attached.config.lock();
        config.flags.remove(LoopFlags::READ_ONLY);
        config.flags.insert(current.flags & LoopFlags::READ_ONLY);
        *current = config;

        let new_geometry = geometry(&attached.file, &config);
        let mut geometry = attached.geometry.disable_irq().lock();
        let old_sectors = geometry.nr_sectors;
        *geometry = new_geometry;
        Ok(old_sectors != new_geometry.nr_sectors)
    }

    /// Re-reads the backing file size after it changed.
    ///
    /// Returns whether the capacity changed.
    pub(super) fn set_capacity(&self) -> Result<bool> {
        let state = self.state.lock();
        let attached = match &state.disk {
            DiskState::Attached(attached) => attached,
            DiskState::Detached => return_errno!(Errno::ENXIO),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        };
        let config = attached.config.lock();
        let new_geometry = geometry(&attached.file, &config);
        let mut geometry = attached.geometry.disable_irq().lock();
        let old_sectors = geometry.nr_sectors;
        *geometry = new_geometry;
        Ok(old_sectors != new_geometry.nr_sectors)
    }
}

impl Debug for LoopDisk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LoopDisk")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl AnyBlockDevice for LoopDisk {
    fn enqueue(&self, bio: SubmittedBio) -> core::result::Result<(), BioEnqueueError> {
        let attached = self.active.disable_irq().lock().clone();
        match attached {
            Some(attached) => attached.enqueue(bio),
            None if bio.type_() == BioType::Flush => {
                // A detached loop device has no backing file to flush.
                bio.complete(BioStatus::Complete);
                Ok(())
            }
            None => Err(BioEnqueueError::Refused),
        }
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: MAX_NR_SEGMENTS_PER_BIO,
            nr_sectors: self.nr_sectors(),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(MajorId::new(LOOP_MAJOR), MinorId::new(self.number))
    }

    fn kind(&self) -> BlockDeviceKind<'_> {
        BlockDeviceKind::Disk(self)
    }
}

impl WholeDisk for LoopDisk {
    fn handle_requests(&self) -> Option<()> {
        // Loop devices manage attach-scoped worker threads dynamically.
        None
    }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn capacity_sectors_handles_windows_and_truncation() {
        assert_eq!(capacity_sectors(8192, 0, 0), 16);
        assert_eq!(capacity_sectors(8192, 1024, 0), 14);
        assert_eq!(capacity_sectors(8192, 1024, 2048), 4);
        assert_eq!(capacity_sectors(8192, 1024, 16384), 14);
        assert_eq!(capacity_sectors(8192, 16384, 0), 0);
        // Trailing bytes shorter than one sector are dropped.
        assert_eq!(capacity_sectors(1500, 0, 0), 2);
        assert_eq!(capacity_sectors(8192, 0, 1023), 1);
    }
}
