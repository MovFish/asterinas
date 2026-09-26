// SPDX-License-Identifier: MPL-2.0

//! Unit and integration tests for device uevents and lifecycle changes.

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use device_id::{DeviceId, MajorId, MinorId};
use ostd::{prelude::ktest, sync::Mutex, task::Task};
use spin::Once;

use crate::{
    Bus, BusDevice, BusHandle, Class, ClassDevice, ClassHandle, DevNode, DevNum, DeviceType,
    Driver, Error, Result, add, emit_uevent,
    hooks::test_support::{FAIL_DEVNODE_CREATE, clear_test_observers, register_test_observer},
    register_bus, register_class, remove,
    uevent::{Uevent, UeventAction},
};

// Global sequence tracker for unique device names across tests.
static TEST_DEV_ID: AtomicU64 = AtomicU64::new(100);

fn next_test_id() -> u64 {
    TEST_DEV_ID.fetch_add(1, Ordering::Relaxed)
}

fn init_test() {
    crate::init_for_ktest();
    clear_test_observers();
}

struct SimpleClass;

impl Class for SimpleClass {
    const NAME: &'static str = "simple_cls";
    type Device = ();
}

static SIMPLE_CLASS: Once<Arc<ClassHandle<SimpleClass>>> = Once::new();

fn simple_class() -> Arc<ClassHandle<SimpleClass>> {
    SIMPLE_CLASS
        .call_once(|| register_class(SimpleClass).unwrap())
        .clone()
}

#[ktest]
fn auto_add_and_remove() {
    init_test();
    let events = Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();
    register_test_observer(Arc::new(move |ev: &Uevent| {
        events_clone.lock().push(ev.clone());
    }));

    let id = next_test_id();
    let cls = simple_class();
    let devnum = DevNum::char(DeviceId::new(MajorId::new(240), MinorId::new(id as u32)));
    let dev = ClassDevice::builder(&cls, format!("sdev{}", id), ())
        .devnum(devnum)
        .build();

    add(&dev).expect("device add should succeed");

    // Verify Add event
    {
        let evs = events.lock();
        assert!(!evs.is_empty());
        let add_ev = evs
            .iter()
            .find(|e| e.action() == UeventAction::Add)
            .expect("Add event not found");
        assert_eq!(add_ev.subsystem(), "simple_cls");
        assert!(add_ev.devpath().contains(&format!("sdev{}", id)));
        let vars: Vec<_> = add_ev.vars().iter().collect();
        assert!(vars.contains(&("MAJOR", "240")));
        assert!(vars.contains(&("MINOR", &id.to_string())));
        assert!(vars.contains(&("DEVNAME", &format!("sdev{}", id))));
    }

    // Now remove device
    remove(&dev).expect("device remove should succeed");

    // Verify Remove event
    {
        let evs = events.lock();
        let rem_ev = evs
            .iter()
            .find(|e| e.action() == UeventAction::Remove)
            .expect("Remove event not found");
        assert_eq!(rem_ev.subsystem(), "simple_cls");
        assert!(rem_ev.devpath().contains(&format!("sdev{}", id)));
    }

    // Duplicate remove fails with NotAdded and does not emit duplicate Remove
    let count_before = events.lock().len();
    assert!(matches!(remove(&dev), Err(Error::NotAdded)));
    assert_eq!(events.lock().len(), count_before);
}

#[ktest]
fn create_devnode_failure_rollback() {
    init_test();
    let id = next_test_id();
    let cls = simple_class();
    let devnum = DevNum::char(DeviceId::new(MajorId::new(241), MinorId::new(id as u32)));

    // Force create_devnode to fail
    FAIL_DEVNODE_CREATE.store(true, Ordering::Relaxed);
    let dev1 = ClassDevice::builder(&cls, format!("faildev{}", id), ())
        .devnum(devnum)
        .build();

    assert!(matches!(add(&dev1), Err(Error::Hook)));

    // Re-enable create_devnode
    FAIL_DEVNODE_CREATE.store(false, Ordering::Relaxed);

    // Register a second device with the EXACT SAME devnum.
    // If rollback failed to clean up /sys/dev, this will fail with NameConflict or AlreadyExists.
    let dev2 = ClassDevice::builder(&cls, format!("okdev{}", id), ())
        .devnum(devnum)
        .build();

    add(&dev2).expect("adding device with reused devnum must succeed after rollback");
    remove(&dev2).expect("remove must succeed");
}

#[ktest]
fn active_change_and_bare_device() {
    init_test();
    let events = Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();
    register_test_observer(Arc::new(move |ev: &Uevent| {
        events_clone.lock().push(ev.clone());
    }));

    let id = next_test_id();
    let cls = simple_class();
    // Device without devnum
    let dev = ClassDevice::builder(&cls, format!("nodev{}", id), ()).build();
    add(&dev).unwrap();

    emit_uevent(&dev, UeventAction::Change).expect("active change must succeed");
    {
        let evs = events.lock();
        let change_ev = evs
            .iter()
            .find(|e| e.action() == UeventAction::Change)
            .expect("Change event not found");
        let vars: Vec<_> = change_ev.vars().iter().collect();
        // Devnum fields must NOT be present
        assert!(
            !vars
                .iter()
                .any(|(k, _)| *k == "MAJOR" || *k == "MINOR" || *k == "DEVNAME")
        );
    }
    remove(&dev).unwrap();

    // Bare device: without subsystem, events are filtered out and seq is not incremented
    let bare = crate::BareDevice::new_root(format!("bare{}", id));
    add(&bare).unwrap();
    let count_before = events.lock().len();
    emit_uevent(&bare, UeventAction::Change).expect("bare change must return Ok(())");
    assert_eq!(events.lock().len(), count_before);
    remove(&bare).unwrap();
}

struct DevmodePayload {
    mode: Option<u16>,
}

struct DevmodeClass;

impl Class for DevmodeClass {
    const NAME: &'static str = "devmode_cls";
    type Device = DevmodePayload;

    fn devnode(&self, dev: &ClassDevice<Self>) -> Option<DevNode> {
        Some(DevNode {
            path: None,
            mode: dev.payload().mode,
        })
    }
}

static DEVMODE_CLASS: Once<Arc<ClassHandle<DevmodeClass>>> = Once::new();

#[ktest]
fn show_and_devmode_parameterized() {
    init_test();
    let cls = DEVMODE_CLASS
        .call_once(|| register_class(DevmodeClass).unwrap())
        .clone();

    let cases = [
        (Some(0o1640), Some("DEVMODE=0640")),
        (Some(0o7), Some("DEVMODE=07")),
        (Some(0o1000), Some("DEVMODE=0")),
        (Some(0), None),
        (None, None), // default mode
    ];

    for (mode, expected_devmode) in cases {
        let id = next_test_id();
        let devnum = DevNum::char(DeviceId::new(MajorId::new(242), MinorId::new(id as u32)));
        let dev = ClassDevice::builder(&cls, format!("dmdev{}", id), DevmodePayload { mode })
            .devnum(devnum)
            .build();
        add(&dev).unwrap();

        // Read show_uevent via base build_uevent_vars
        let vars = crate::device::build_uevent_vars(dev.as_ref(), None).unwrap();
        let mut show_output = String::new();
        for (k, v) in vars.iter() {
            show_output.push_str(&format!("{}={}\n", k, v));
        }

        if let Some(expected) = expected_devmode {
            assert!(
                show_output.contains(expected),
                "expected '{}' in show output for mode {:?}, got:\n{}",
                expected,
                mode,
                show_output
            );
        } else {
            assert!(
                !show_output.contains("DEVMODE"),
                "DEVMODE should be omitted for mode {:?}, got:\n{}",
                mode,
                show_output
            );
        }

        remove(&dev).unwrap();
    }
}

struct ModaliasBus;

impl Bus for ModaliasBus {
    const NAME: &'static str = "modalias_bus";
    type Device = ();
    type MatchData = ();

    fn matches(&self, _dev: &Self::Device, _data: &Self::MatchData) -> bool {
        true
    }

    fn uevent(&self, _dev: &Self::Device, vars: &mut crate::uevent::UeventVars) -> Result<()> {
        vars.add("MODALIAS", "modalias:one")?;
        vars.add("MODALIAS", "modalias:two")?;
        vars.add("SYNTH_ARG_MODALIAS", "preserved")?;
        Ok(())
    }
}

static MODALIAS_BUS: Once<Arc<BusHandle<ModaliasBus>>> = Once::new();

struct TestDriver {
    name: &'static str,
}

impl Driver<ModaliasBus> for TestDriver {
    fn name(&self) -> &str {
        self.name
    }

    fn match_data(&self) -> &() {
        &()
    }

    fn probe(&self, _dev: &Arc<BusDevice<ModaliasBus>>) -> Result<()> {
        Ok(())
    }
}

#[ktest]
fn bind_unbind_and_modalias_removal() {
    init_test();
    let events = Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();
    register_test_observer(Arc::new(move |ev: &Uevent| {
        events_clone.lock().push(ev.clone());
    }));

    let bus = MODALIAS_BUS
        .call_once(|| register_bus(ModaliasBus).unwrap())
        .clone();

    let id = next_test_id();
    let dev = BusDevice::builder(&bus, format!("mdev{}", id), ()).build();
    add(&dev).unwrap();

    // Registering a matching driver automatically binds the existing device.
    let driver = bus
        .register_driver(Arc::new(TestDriver { name: "test_drv" }))
        .unwrap();

    // Unbind driver
    bus.unbind(&dev).expect("driver unbind should succeed");

    // Verify Bind and Unbind events
    let evs = events.lock();
    let bind_ev = evs
        .iter()
        .find(|e| e.action() == UeventAction::Bind)
        .expect("Bind event not found");
    let bind_vars: Vec<_> = bind_ev.vars().iter().collect();
    assert!(bind_vars.contains(&("MODALIAS", "modalias:one")));
    assert!(bind_vars.contains(&("MODALIAS", "modalias:two")));

    let unbind_ev = evs
        .iter()
        .find(|e| e.action() == UeventAction::Unbind)
        .expect("Unbind event not found");
    let unbind_vars: Vec<_> = unbind_ev.vars().iter().collect();
    // All MODALIAS entries must be removed on Unbind
    assert!(!unbind_vars.iter().any(|(k, _)| *k == "MODALIAS"));
    // SYNTH_ARG_MODALIAS is preserved
    assert!(unbind_vars.contains(&("SYNTH_ARG_MODALIAS", "preserved")));

    drop(evs);
    bus.unregister_driver(&driver).unwrap();
    remove(&dev).unwrap();
}

static GATE_ARMED: AtomicBool = AtomicBool::new(false);
static GATE_ENTERED: AtomicBool = AtomicBool::new(false);
static GATE_RELEASE: AtomicBool = AtomicBool::new(false);

fn gating_uevent_cb(
    _dev: &ClassDevice<SimpleClass>,
    _vars: &mut crate::uevent::UeventVars,
) -> Result<()> {
    if !GATE_ARMED.swap(false, Ordering::AcqRel) {
        return Ok(());
    }
    GATE_ENTERED.store(true, Ordering::Release);
    while !GATE_RELEASE.load(Ordering::Acquire) {
        Task::yield_now();
    }
    Ok(())
}

const GATED_TYPE: DeviceType<ClassDevice<SimpleClass>> = DeviceType {
    name: "gated_type",
    attrs: &[],
    devnode: None,
    uevent_fn: Some(gating_uevent_cb),
    has_device_link: true,
};

#[ktest]
fn concurrency_gate_change_and_remove() {
    init_test();
    let events = Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();
    register_test_observer(Arc::new(move |ev: &Uevent| {
        events_clone.lock().push(ev.clone());
    }));

    let id = next_test_id();
    let cls = simple_class();
    let dev = ClassDevice::builder(&cls, format!("gatedev{}", id), ())
        .dev_type(&GATED_TYPE)
        .build();
    add(&dev).unwrap();

    GATE_ENTERED.store(false, Ordering::Relaxed);
    GATE_RELEASE.store(false, Ordering::Relaxed);
    GATE_ARMED.store(true, Ordering::Release);

    // Spawn a task that calls emit_uevent(Change)
    let dev_clone = dev.clone();
    let change_res = Arc::new(Mutex::new(None));
    let change_res_clone = change_res.clone();
    let _ = ostd::task::TaskOptions::new(move || {
        let res = emit_uevent(&dev_clone, UeventAction::Change);
        *change_res_clone.lock() = Some(res);
    })
    .data(())
    .spawn();

    // Wait until task 1 enters the callback
    while !GATE_ENTERED.load(Ordering::Acquire) {
        Task::yield_now();
    }

    // Task 2 calls remove while Task 1 is paused in callback
    remove(&dev).expect("remove during paused callback must succeed");

    // Now release Task 1
    GATE_RELEASE.store(true, Ordering::Release);

    // Wait for Task 1 to finish
    while change_res.lock().is_none() {
        Task::yield_now();
    }

    // Task 1 must have failed with NotAdded
    let res = change_res.lock().take().unwrap();
    assert!(
        matches!(res, Err(Error::NotAdded)),
        "Change must fail with NotAdded when removed concurrently"
    );

    // Observer must see Remove, and NO Change event
    let evs = events.lock();
    assert!(evs.iter().any(|e| e.action() == UeventAction::Remove));
    assert!(
        !evs.iter().any(|e| e.action() == UeventAction::Change),
        "No Change event should have been broadcast"
    );
}

#[ktest]
fn concurrency_probe_and_remove_ordering() {
    init_test();
    let events = Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();
    register_test_observer(Arc::new(move |ev: &Uevent| {
        events_clone.lock().push(ev.clone());
    }));

    let bus = MODALIAS_BUS
        .call_once(|| register_bus(ModaliasBus).unwrap())
        .clone();

    let id = next_test_id();
    let dev = BusDevice::builder(&bus, format!("orddev{}", id), ()).build();
    add(&dev).unwrap();

    let driver = bus
        .register_driver(Arc::new(TestDriver { name: "ord_drv" }))
        .unwrap();

    remove(&dev).unwrap();
    bus.unregister_driver(&driver).unwrap();

    let evs = events.lock();
    let actions: Vec<_> = evs.iter().map(|e| e.action()).collect();
    assert_eq!(
        actions,
        vec![
            UeventAction::Add,
            UeventAction::Bind,
            UeventAction::Unbind,
            UeventAction::Remove,
        ]
    );
}
