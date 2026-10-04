// SPDX-License-Identifier: MPL-2.0

//! Public device and sysfs uevent contracts.

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use aster_systree::{SysNode, SysObj};
use device_id::{DeviceId, MajorId, MinorId};
use ostd::{prelude::ktest, sync::Mutex};

use super::utils;
use crate::{
    bus::{self, Bus, BusDevice, BusHandle, Driver},
    class::{self, Class, ClassDevice, ClassHandle},
    common::{AnyDevice, Attr, BareDevice, DevNode, DevNum, DeviceType, Error, Result},
    uevent::{self, UeventAction, UeventVars},
};

#[ktest]
fn sysfs_reports_frozen_devnode_policy_and_ordered_callbacks() {
    let (class, _) = subsystems();
    let dev = ClassDevice::builder(&class, "env!node", NodePayload::new())
        .devnum(DevNum::char(DeviceId::new(
            MajorId::new(240),
            MinorId::new(1),
        )))
        .dev_type(&NODE_TYPE)
        .build();
    crate::add_device(&dev).unwrap();
    assert_eq!(dev.path(), "/devices/virtual/uevent-test-class/env!node");
    assert_eq!(dev.node_policy_calls.load(Ordering::Relaxed), 1);
    dev.change_node_name.store(true, Ordering::Relaxed);

    let before = uevent::current_seqnum();
    assert_eq!(
        dev.show_attr("uevent").unwrap(),
        "MAJOR=240\nMINOR=1\nDEVNAME=events/original\nDEVMODE=0660\nDEVTYPE=event-node\nSOURCE=class\nSOURCE=type\n"
    );
    assert_eq!(
        uevent::current_seqnum(),
        before,
        "reading must not allocate a sequence number"
    );
    assert_eq!(
        dev.node_policy_calls.load(Ordering::Relaxed),
        1,
        "uevents must reuse the published node policy"
    );
    crate::remove_device(&dev).unwrap();
    assert!(matches!(
        dev.show_attr("uevent"),
        Err(aster_systree::Error::IsDead)
    ));
}
#[ktest]
fn sysfs_distinguishes_absent_zero_and_explicit_node_modes() {
    let (class, _) = subsystems();
    for (mode, expected) in [
        (None, None),
        (Some(0), None),
        (Some(0o600), Some("0600")),
        (Some(0o1660), Some("0660")),
        (Some(0o1000), Some("0")),
    ] {
        let mut payload = NodePayload::new();
        payload.mode = mode;
        let dev = ClassDevice::builder(&class, "mode-policy", payload)
            .devnum(DevNum::char(DeviceId::new(
                MajorId::new(240),
                MinorId::new(2),
            )))
            .build();
        crate::add_device(&dev).unwrap();
        let environment = dev.show_attr("uevent").unwrap();
        assert_eq!(
            environment
                .lines()
                .find_map(|line| line.strip_prefix("DEVMODE=")),
            expected,
            "unexpected event permissions for {mode:?}"
        );
        assert_eq!(dev.node_policy_calls.load(Ordering::Relaxed), 1);
        crate::remove_device(&dev).unwrap();
    }
}

#[ktest]
fn synthetic_sysfs_writes_keep_exact_grammar_and_do_not_change_membership() {
    let (class, _) = subsystems();
    let dev = ClassDevice::builder(&class, "synthetic", NodePayload::new()).build();
    crate::add_device(&dev).unwrap();
    let uuid = "12345678-ABCD-1234-abcd-123456789abc";
    for action in [
        "add", "remove", "change", "move", "online", "offline", "bind", "unbind",
    ] {
        for suffix in ["", "\n", "\0"] {
            let input = alloc::format!("{action}{suffix}");
            assert_eq!(dev.store_attr("uevent", &input).unwrap(), input.len());
        }
        let input = alloc::format!("{action} {uuid} A=1 A=2 Z9=v3\n");
        assert_eq!(dev.store_attr("uevent", &input).unwrap(), input.len());
    }
    assert!(
        class.find_device("synthetic").is_some(),
        "synthetic remove must not unregister the device"
    );
    let calls = dev.event_calls.load(Ordering::Relaxed);
    for input in [
        "",
        " add",
        "ADD",
        "unknown",
        "add ",
        "add\t",
        "add\r\n",
        "add\n\n",
        "add\0\0",
        "add\n\0",
        "ad\0d",
        "add 12345678-1234-1234-1234-123456789abé",
        "add 12345678-1234-1234-1234-123456789abc ",
        "add 12345678-1234-1234-1234-123456789abc A=1  B=2",
        "add 12345678-1234-1234-1234-123456789abc A_B=1",
        "add 12345678-1234-1234-1234-123456789abc A=1_2",
        "add 12345678-1234-1234-1234-123456789abc A=1=2",
        "add 12345678-1234-1234-1234-123456789abc =1",
        "add 12345678-1234-1234-1234-123456789abc A=",
    ] {
        assert!(
            matches!(
                dev.store_attr("uevent", input),
                Err(aster_systree::Error::InvalidOperation)
            ),
            "accepted malformed request {input:?}"
        );
    }
    assert_eq!(
        dev.event_calls.load(Ordering::Relaxed),
        calls,
        "invalid requests must not reach callbacks"
    );

    // The parser can hold this environment, but adding the base fields and class
    // callback exceeds 64 entries. This is ENOMEM, not a syntax error.
    let mut request = alloc::format!("change {uuid}");
    for index in 0..60 {
        request.push_str(&alloc::format!(" K{index}=v"));
    }
    assert!(matches!(
        dev.store_attr("uevent", &request),
        Err(aster_systree::Error::NoMemory)
    ));
    request.push_str(" K60=v K61=v K62=v K63=v");
    assert!(matches!(
        dev.store_attr("uevent", &request),
        Err(aster_systree::Error::InvalidOperation)
    ));
    crate::remove_device(&dev).unwrap();
    assert!(matches!(
        dev.store_attr("uevent", "change"),
        Err(aster_systree::Error::IsDead)
    ));
}

#[ktest]
fn lifecycle_callbacks_observe_registration_and_driver_binding() {
    let (_, bus) = subsystems();
    let root = BareDevice::new_root("uevent-root");
    crate::add_device(&root).unwrap();
    let driver = bus.register_driver(Arc::new(EventDriver)).unwrap();
    let dev = BusDevice::builder(&bus, "lifecycle", Mutex::new(Vec::new()))
        .parent(root.clone())
        .dev_type(&BUS_TYPE)
        .build();
    crate::add_device(&dev).unwrap();
    assert_eq!(
        *dev.payload().lock(),
        vec![
            (None, "/devices/uevent-root/lifecycle".to_string()),
            (
                Some("event-driver".to_string()),
                "/devices/uevent-root/lifecycle".to_string()
            )
        ]
    );
    assert!(
        dev.show_attr("uevent")
            .unwrap()
            .contains("DRIVER=event-driver\n")
    );
    dev.payload().lock().clear();
    bus.unbind(&dev).unwrap();
    assert_eq!(
        *dev.payload().lock(),
        vec![(None, "/devices/uevent-root/lifecycle".to_string())]
    );
    let driver_dir = utils::lookup("/bus/uevent-test-bus/drivers/event-driver")
        .unwrap()
        .cast_to_node()
        .unwrap();
    driver_dir.store_attr("bind", "lifecycle\n").unwrap();
    dev.payload().lock().clear();
    crate::remove_device(&dev).unwrap();
    assert!(matches!(
        crate::emit_uevent(&dev, UeventAction::Change),
        Err(Error::NotAdded)
    ));
    crate::remove_device(&root).unwrap();
    bus.unregister_driver(&driver).unwrap();
}

#[ktest]
fn callback_failure_is_best_effort_only_for_lifecycle_events() {
    let (class, _) = subsystems();
    let dev = ClassDevice::builder(&class, "callback-failure", NodePayload::new()).build();
    dev.fail_event.store(true, Ordering::Relaxed);
    crate::add_device(&dev).unwrap();
    assert!(class.find_device("callback-failure").is_some());
    assert!(matches!(
        crate::emit_uevent(&dev, UeventAction::Change),
        Err(Error::Attribute)
    ));
    assert!(matches!(
        dev.store_attr("uevent", "change"),
        Err(aster_systree::Error::AttributeError)
    ));
    assert!(matches!(
        dev.show_attr("uevent"),
        Err(aster_systree::Error::AttributeError)
    ));
    crate::remove_device(&dev).unwrap();
    assert!(class.find_device("callback-failure").is_none());
}

#[ktest]
fn callback_removal_cancels_a_prepared_synthetic_event() {
    let (class, _) = subsystems();
    let dev = ClassDevice::builder(&class, "callback-removal", NodePayload::new()).build();
    crate::add_device(&dev).unwrap();
    dev.remove_on_event.store(true, Ordering::Relaxed);
    let before = uevent::current_seqnum();
    assert!(matches!(
        dev.store_attr("uevent", "change"),
        Err(aster_systree::Error::IsDead)
    ));
    assert_eq!(
        uevent::current_seqnum(),
        before + 1,
        "only the nested Remove event may consume a sequence"
    );
    assert!(class.find_device("callback-removal").is_none());
    assert!(utils::lookup("/devices/virtual/uevent-test-class/callback-removal").is_none());
}

#[ktest]
fn registration_rollback_does_not_announce_add_or_remove() {
    let (class, _) = subsystems();
    let first = ClassDevice::builder(&class, "rollback-event", NodePayload::new()).build();
    let duplicate = ClassDevice::builder(&class, "rollback-event", NodePayload::new()).build();
    crate::add_device(&first).unwrap();
    let before = uevent::current_seqnum();
    assert!(matches!(
        crate::add_device(&duplicate),
        Err(Error::NameConflict)
    ));
    assert_eq!(duplicate.event_calls.load(Ordering::Relaxed), 0);
    assert_eq!(uevent::current_seqnum(), before);
    assert!(
        class
            .find_device("rollback-event")
            .is_some_and(|dev| Arc::ptr_eq(&dev, &first))
    );
    crate::remove_device(&first).unwrap();
}

fn subsystems() -> (Arc<ClassHandle<EventClass>>, Arc<BusHandle<EventBus>>) {
    static SUBSYSTEMS: spin::Once<(Arc<ClassHandle<EventClass>>, Arc<BusHandle<EventBus>>)> =
        spin::Once::new();
    crate::init_for_ktest();
    SUBSYSTEMS
        .call_once(|| {
            (
                class::register(EventClass).unwrap(),
                bus::register(EventBus).unwrap(),
            )
        })
        .clone()
}

struct NodePayload {
    node_policy_calls: AtomicUsize,
    event_calls: AtomicUsize,
    change_node_name: AtomicBool,
    fail_event: AtomicBool,
    remove_on_event: AtomicBool,
    mode: Option<u16>,
}

impl NodePayload {
    fn new() -> Self {
        Self {
            node_policy_calls: AtomicUsize::new(0),
            event_calls: AtomicUsize::new(0),
            change_node_name: AtomicBool::new(false),
            fail_event: AtomicBool::new(false),
            remove_on_event: AtomicBool::new(false),
            mode: Some(0o1660),
        }
    }
}

struct EventClass;

impl Class for EventClass {
    const NAME: &'static str = "uevent-test-class";
    type Device = NodePayload;
    fn dev_attrs(&self) -> &'static [Attr<ClassDevice<Self>>] {
        &[]
    }
    fn devnode(&self, dev: &ClassDevice<Self>) -> Option<DevNode> {
        dev.node_policy_calls.fetch_add(1, Ordering::Relaxed);
        Some(DevNode {
            path: Some(
                if dev.change_node_name.load(Ordering::Relaxed) {
                    "events/changed"
                } else {
                    "events/original"
                }
                .into(),
            ),
            mode: dev.mode,
        })
    }
    fn uevent(&self, dev: &ClassDevice<Self>, vars: &mut UeventVars) -> Result<()> {
        dev.event_calls.fetch_add(1, Ordering::Relaxed);
        // Accesses state through the public registration path. On Add the
        // directory exists but removal still rejects `Adding`; explicit event
        // requests can remove it and must then fail their final state check.
        if dev.remove_on_event.swap(false, Ordering::Relaxed) {
            crate::remove_device(&dev.to_arc())?;
        }
        if dev.fail_event.load(Ordering::Relaxed) {
            return Err(Error::Attribute);
        }
        vars.add("SOURCE", "class")
    }
}

static NODE_TYPE: DeviceType<ClassDevice<EventClass>> = {
    let mut dev_type = DeviceType::named("event-node");
    dev_type.uevent_fn = Some(|_dev, vars| vars.add("SOURCE", "type"));
    dev_type
};

struct EventBus;

impl Bus for EventBus {
    const NAME: &'static str = "uevent-test-bus";
    type Device = Mutex<Vec<(Option<String>, String)>>;
    type MatchData = ();
    fn matches(&self, _dev: &Self::Device, _data: &Self::MatchData) -> bool {
        true
    }
    fn dev_attrs(&self) -> &'static [Attr<BusDevice<Self>>] {
        &[]
    }
    fn uevent(&self, dev: &BusDevice<Self>, vars: &mut UeventVars) -> Result<()> {
        // Re-enter the public state check without changing the registration.
        // This would deadlock if uevent callbacks ran under the state mutex.
        assert!(matches!(
            crate::add_device(&dev.to_arc()),
            Err(Error::AlreadyAdded)
        ));
        dev.payload().lock().push((
            dev.driver().map(|driver| driver.name().to_string()),
            dev.path().to_string(),
        ));
        vars.add("SOURCE", "bus")?;
        vars.add("MODALIAS", "uevent-test")
    }
}

static BUS_TYPE: DeviceType<BusDevice<EventBus>> = DeviceType::named("event-bus-device");
struct EventDriver;

impl Driver<EventBus> for EventDriver {
    fn name(&self) -> &str {
        "event-driver"
    }
    fn match_data(&self) -> &() {
        &()
    }
    fn on_probe(&self, _dev: &Arc<BusDevice<EventBus>>) -> Result<()> {
        Ok(())
    }
    fn dev_attrs(&self) -> &'static [Attr<BusDevice<EventBus>>] {
        &[]
    }
}
