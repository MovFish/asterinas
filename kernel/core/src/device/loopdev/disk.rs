// SPDX-License-Identifier: MPL-2.0

//! The loop block device core: runtime configuration, attachment state, and BIO worker.

use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use aster_block::{
    BlockDevice, BlockDeviceMeta, SECTOR_SIZE,
    bio::{BioEnqueueError, BioSegment, BioStatus, BioType, SubmittedBio},
};
use device_id::{DeviceId, MajorId, MinorId};
use ostd::{mm::io::util::HasVmReaderWriter, sync::WaitQueue};

use super::{abi::Info64, backing::BackingFile};
use crate::{prelude::*, thread::kernel_thread::ThreadOptions};

pub(super) const LOOP_MAJOR: u16 = 7;
const QUEUE_DEPTH: usize = 128;
const MAX_NR_SEGMENTS_PER_BIO: usize = 128;

bitflags! {
    /// Linux `lo_flags`.
    ///
    /// Only the read-only flag is supported. `AUTOCLEAR`, `PARTSCAN`, and
    /// backing-file `DIRECT_IO` must not be silently accepted.
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
    pub file_name: [u8; 64],
}

impl LoopConfig {
    /// Applies the restrictions of the backing file.
    pub(super) fn with_backing_file(self, writable: bool) -> Self {
        let mut config = self;
        if !writable {
            config.flags.insert(LoopFlags::READ_ONLY);
        }
        config
    }
}

/// A loop block device backend.
///
/// Lock order: `Pool.devices` -> `state` -> `config` -> `active`/`geometry`/`queue`.
pub(in crate::device) struct LoopDisk {
    number: u32,
    name: String,
    state: Mutex<DiskState>,
    /// Fast path for BIO submission and sysfs reads.
    active: SpinLock<Option<Arc<AttachedLoop>>>,
    opens: AtomicUsize,
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
    queue: SpinLock<BioQueue>,
    work: WaitQueue,
    drained: WaitQueue,
    pending: AtomicUsize,
    /// Signaled after the worker thread has dropped its `AttachedLoop` reference.
    exit: Arc<WorkerExit>,
}

/// Completion notification for the worker thread.
///
/// Kept outside [`AttachedLoop`] so that the thread can drop its reference
/// (and thus release the backing file) before notifying `wait_worker`.
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

impl AttachedLoop {
    fn new(file: BackingFile, config: LoopConfig) -> Self {
        let config = config.with_backing_file(file.is_writable());
        let geometry = geometry(&file, &config);
        Self {
            file,
            config: Mutex::new(config),
            geometry: SpinLock::new(geometry),
            queue: SpinLock::new(BioQueue {
                bios: VecDeque::with_capacity(QUEUE_DEPTH),
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
        let mut queue = self.queue.disable_irq().lock();
        if !queue.accepting || queue.stopped {
            return Err(BioEnqueueError::Refused);
        }
        if queue.bios.len() == QUEUE_DEPTH {
            return Err(BioEnqueueError::IsFull);
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
                let mut queue = self.queue.disable_irq().lock();
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
            BioType::Read => self.transfer(bio, &config, geometry, false),
            BioType::Write => {
                if geometry.read_only {
                    return_errno!(Errno::EPERM);
                }
                self.transfer(bio, &config, geometry, true)
            }
        }
    }

    fn transfer(
        &self,
        bio: &SubmittedBio,
        config: &LoopConfig,
        geometry: Geometry,
        write: bool,
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
            .and_then(|sector| sector.checked_mul(SECTOR_SIZE))
            .and_then(|offset| offset.checked_add(config.offset as usize))
            .ok_or_else(|| Error::new(Errno::EIO))?;
        let expected = usize::try_from(end_sector - start_sector)
            .ok()
            .and_then(|sectors| sectors.checked_mul(SECTOR_SIZE))
            .ok_or_else(|| Error::new(Errno::EIO))?;
        let actual = bio
            .segments()
            .iter()
            .try_fold(0usize, |total, segment| total.checked_add(segment.nbytes()))
            .ok_or_else(|| Error::new(Errno::EIO))?;
        if actual != expected {
            return_errno!(Errno::EIO);
        }

        let transfer: fn(&BackingFile, &mut usize, &BioSegment) -> Result<()> =
            if write { write_segment } else { read_segment };
        for segment in bio.segments() {
            transfer(&self.file, &mut offset, segment)?;
        }
        Ok(())
    }

    fn stop_accepting(&self) {
        self.queue.disable_irq().lock().accepting = false;
    }

    fn resume(&self) {
        self.queue.disable_irq().lock().accepting = true;
    }

    fn wait_drained(&self) {
        self.drained
            .wait_until(|| (self.pending.load(Ordering::Acquire) == 0).then_some(()));
    }

    fn stop(&self) {
        self.queue.disable_irq().lock().stopped = true;
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
            return_errno!(Errno::EIO);
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
    let available = file.size().saturating_sub(config.offset as usize);
    let bytes = if config.size_limit == 0 {
        available
    } else {
        available.min(config.size_limit as usize)
    };
    bytes / SECTOR_SIZE
}

impl LoopDisk {
    pub(in crate::device) fn new(number: u32, name: String) -> Arc<Self> {
        Arc::new(Self {
            number,
            name,
            state: Mutex::new(DiskState::Detached),
            active: SpinLock::new(None),
            opens: AtomicUsize::new(0),
        })
    }

    /// Returns the current sector capacity for block metadata.
    fn sectors(&self) -> usize {
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

    pub(super) fn is_free(&self) -> bool {
        matches!(*self.state.lock(), DiskState::Detached)
    }

    pub(super) fn try_open(&self) -> Result<()> {
        let state = self.state.lock();
        if matches!(*state, DiskState::Removed) {
            return_errno!(Errno::ENODEV);
        }
        self.opens.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn close(&self) {
        self.opens.fetch_sub(1, Ordering::Release);
    }

    /// Marks the device removed if it has no opens and no backing file.
    pub(super) fn prepare_remove(&self) -> Result<()> {
        let mut state = self.state.lock();
        if self.opens.load(Ordering::Acquire) != 0 {
            return_errno!(Errno::EBUSY);
        }
        match &*state {
            DiskState::Detached => {
                *state = DiskState::Removed;
                Ok(())
            }
            DiskState::Attached(_) => return_errno!(Errno::EBUSY),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        }
    }

    /// Restores a detached state if registration removal failed.
    pub(super) fn restore_detached(&self) {
        let mut state = self.state.lock();
        if matches!(*state, DiskState::Removed) {
            *state = DiskState::Detached;
        }
    }

    pub(super) fn attach(&self, fd: i32) -> Result<()> {
        let mut state = self.state.lock();
        match &*state {
            DiskState::Detached => {}
            DiskState::Attached(_) => return_errno!(Errno::EBUSY),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        }
        let file = BackingFile::from_fd(fd)?;
        let config = LoopConfig {
            offset: 0,
            size_limit: 0,
            flags: LoopFlags::empty(),
            file_name: [0; 64],
        };
        let attached = Arc::new(AttachedLoop::new(file, config));
        // Start the worker before publishing the attachment, so an opener
        // cannot reach a queue that nobody serves.
        attached.start();
        *self.active.disable_irq().lock() = Some(attached.clone());
        *state = DiskState::Attached(attached);
        Ok(())
    }

    pub(super) fn detach(&self) -> Result<()> {
        let mut state = self.state.lock();
        let attached = match &*state {
            DiskState::Attached(attached) => attached.clone(),
            DiskState::Detached => return_errno!(Errno::ENXIO),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        };
        if self.opens.load(Ordering::Acquire) > 1 {
            return_errno!(Errno::EBUSY);
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
        *state = DiskState::Detached;
        Ok(())
    }

    pub(super) fn status(&self) -> Result<Info64> {
        let state = self.state.lock();
        let attached = match &*state {
            DiskState::Attached(attached) => attached,
            DiskState::Detached => return_errno!(Errno::ENXIO),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        };
        let config = attached.config.lock();
        Ok(Info64::from_config(
            &config,
            self.number,
            attached.file.device_number(),
            attached.file.inode_number(),
        ))
    }

    /// Applies a new status while preserving the binding-derived read-only
    /// flag.
    ///
    /// Linux never lets `LOOP_SET_STATUS` toggle `LO_FLAGS_READ_ONLY`; only
    /// binding a backing file decides it. Returns whether the capacity changed.
    pub(super) fn set_status(&self, mut config: LoopConfig) -> Result<bool> {
        let state = self.state.lock();
        let attached = match &*state {
            DiskState::Attached(attached) => attached,
            DiskState::Detached => return_errno!(Errno::ENXIO),
            DiskState::Removed => return_errno!(Errno::ENODEV),
        };
        let mut current = attached.config.lock();
        config.flags = current.flags;
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
        let attached = match &*state {
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

impl BlockDevice for LoopDisk {
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
            nr_sectors: self.sectors(),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(MajorId::new(LOOP_MAJOR), MinorId::new(self.number))
    }
}
