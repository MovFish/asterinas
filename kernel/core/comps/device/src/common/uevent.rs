// SPDX-License-Identifier: MPL-2.0

//! Device environment construction and emission, separate from registration resources.

use alloc::string::ToString;
use core::fmt::Write;

use super::{AnyDevice, Error, Result, State, node::SysTreeEdit};
use crate::{
    hooks,
    uevent::{self, Uevent, UeventAction, UeventVars},
};

/// Emits an explicitly requested event for a registered device.
///
/// Environment callbacks run without the event gate or state lock. The final state
/// check, sequence allocation, and hook broadcast share the event gate with removal,
/// so an event whose callback races with removal cannot be broadcast after teardown.
pub(super) fn emit(dev: &dyn AnyDevice, action: UeventAction, extra: &UeventVars) -> Result<()> {
    if !dev.base().is_added() {
        return Err(Error::NotAdded);
    }
    emit_inner(dev, action, extra, EventOrigin::Requested)
}

/// Emits a best-effort lifecycle event while registration resources are still present.
pub(crate) fn emit_lifecycle(dev: &dyn AnyDevice, action: UeventAction) {
    if let Err(error) = emit_inner(dev, action, &UeventVars::new(), EventOrigin::Lifecycle) {
        ostd::debug!("cannot emit {action} for {}: {error}", dev.name());
    }
}

enum EventOrigin {
    Requested,
    Lifecycle,
}

fn emit_inner(
    dev: &dyn AnyDevice,
    action: UeventAction,
    extra: &UeventVars,
    origin: EventOrigin,
) -> Result<()> {
    let subsystem = dev.subsystem();
    let Some(subsystem_name) = subsystem.name() else {
        // Bare devices have no subsystem identity and do not generate events.
        return Ok(());
    };
    let devpath = dev.base().tree_path();
    let mut vars = build_vars(dev, Some(action))?;
    for (key, value) in extra.iter() {
        vars.add(key, value)?;
    }

    let _gate = dev.base().uevent_lock().lock();
    let is_live = {
        let state = dev.base().state().lock();
        matches!(*state, State::Adding(_) | State::Added(_))
            || (matches!(origin, EventOrigin::Lifecycle)
                && matches!(action, UeventAction::Remove | UeventAction::Unbind)
                && matches!(*state, State::Removed))
    };
    if !is_live {
        return Err(Error::NotAdded);
    }
    let event = Uevent::new(action, devpath, subsystem_name.to_string(), vars)?;
    hooks::broadcast_uevent(&event)
}

pub(super) fn show(dev: &dyn AnyDevice, writer: &mut dyn Write) -> Result<()> {
    let vars = build_vars(dev, None)?;
    if !dev.base().is_added() {
        return Err(Error::NotAdded);
    }
    for (key, value) in vars.iter() {
        writeln!(writer, "{key}={value}")?;
    }
    Ok(())
}

pub(super) fn store(dev: &dyn AnyDevice, text: &str) -> Result<()> {
    let (action, vars) = uevent::parse_synthetic(text)?;
    emit(dev, action, &vars)
}

fn build_vars(dev: &dyn AnyDevice, action: Option<UeventAction>) -> Result<UeventVars> {
    let mut vars = UeventVars::new();
    if let Some(devnum) = dev.devnum()
        && devnum.id().major().get() != 0
    {
        vars.add("MAJOR", devnum.id().major().get())?;
        vars.add("MINOR", devnum.id().minor().get())?;
        // Registration freezes the node policy. In particular, do not invoke a
        // devnode callback beneath this mutex or recompute a changed node name.
        let mode = {
            let node = dev.base().devnode().lock();
            let request = node.as_ref().ok_or(Error::NotAdded)?;
            vars.add("DEVNAME", &request.path)?;
            request.mode.map(|mode| mode & 0o777)
        };
        if let Some(mode) = mode {
            if mode == 0 {
                vars.add("DEVMODE", "0")?;
            } else {
                vars.add("DEVMODE", format_args!("0{mode:o}"))?;
            }
        }
    }
    if let Some(name) = dev.type_name() {
        vars.add("DEVTYPE", name)?;
    }
    if let Some(driver) = dev.driver_name() {
        vars.add("DRIVER", driver)?;
    }
    dev.append_uevent_vars(&mut vars)?;
    // Unbind must not invite userspace to load the just-released driver again.
    // Linux removes every MODALIAS contributed by the callback chain here.
    if action == Some(UeventAction::Unbind) {
        vars.remove_all("MODALIAS");
    }
    Ok(vars)
}
