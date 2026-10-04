// SPDX-License-Identifier: MPL-2.0

//! Device uevents and the strict grammar used by the writable sysfs `uevent` attribute.
//!
//! [`Uevent`] owns one complete notification, including its unique sequence number.
//! [`UeventVars`] holds the extra environment entries; the action, path, subsystem,
//! and sequence number are separate fields and count toward the same wire budget.
//! Buses, classes, and device types contribute entries through their uevent callbacks.

use alloc::{string::String, vec::Vec};
use core::{
    fmt::{self, Write},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::common::{Error, Result};

// Linux's UEVENT_NUM_ENVP and UEVENT_BUFFER_SIZE, including the four base entries:
// <https://github.com/torvalds/linux/blob/v6.16/include/linux/kobject.h>.
const MAX_UEVENT_VARS: usize = 64;
const MAX_UEVENT_BYTES: usize = 2048;
static CURRENT_SEQNUM: AtomicU64 = AtomicU64::new(0);

/// Returns the most recently allocated uevent sequence number without incrementing it.
pub fn current_seqnum() -> u64 {
    CURRENT_SEQNUM.load(Ordering::Relaxed)
}

/// The action represented by a device uevent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UeventAction {
    /// A device has been added.
    Add,
    /// A device has been removed.
    Remove,
    /// A device property has changed.
    Change,
    /// A device has moved.
    Move,
    /// A device has come online.
    Online,
    /// A device has gone offline.
    Offline,
    /// A device has been bound to a driver.
    Bind,
    /// A device has been unbound from a driver.
    Unbind,
}

impl UeventAction {
    /// Returns the lowercase action name used on the wire.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Change => "change",
            Self::Move => "move",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Bind => "bind",
            Self::Unbind => "unbind",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "add" => Self::Add,
            "remove" => Self::Remove,
            "change" => Self::Change,
            "move" => Self::Move,
            "online" => Self::Online,
            "offline" => Self::Offline,
            "bind" => Self::Bind,
            "unbind" => Self::Unbind,
            _ => return None,
        })
    }
}

impl fmt::Display for UeventAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An ordered, bounded collection of extra `KEY=VALUE` environment entries.
///
/// Duplicate keys retain their insertion order. Each entry consumes its key and value
/// lengths plus two bytes for `=` and the terminating NUL.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UeventVars {
    entries: Vec<(String, String)>,
    total_bytes: usize,
}

impl UeventVars {
    /// Creates an empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the serialized size, including separators and terminating NUL bytes.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Iterates over key-value pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    /// Appends a variable without changing the collection on failure.
    ///
    /// Keys must be nonempty and contain neither `=` nor NUL. Values must not contain
    /// NUL. Exceeding 64 entries or 2048 serialized bytes returns [`Error::NoMemory`].
    /// The complete event also needs room for its four base entries.
    pub fn add(&mut self, key: &str, value: impl fmt::Display) -> Result<()> {
        if key.is_empty() || key.contains('=') || key.contains('\0') {
            return Err(Error::InvalidValue);
        }
        let key_bytes = key.len().checked_add(2).ok_or(Error::NoMemory)?;
        let limit = MAX_UEVENT_BYTES
            .checked_sub(self.total_bytes)
            .and_then(|remaining| remaining.checked_sub(key_bytes))
            .ok_or(Error::NoMemory)?;
        if self.len() == MAX_UEVENT_VARS {
            return Err(Error::NoMemory);
        }
        // Bound formatting itself: a maliciously large value must not allocate
        // an unbounded temporary before the environment limit is checked.
        let mut writer = ValueWriter {
            value: String::new(),
            limit,
            error: None,
        };
        let result = write!(writer, "{value}");
        if let Some(error) = writer.error {
            return Err(error);
        }
        result?;
        self.total_bytes += key_bytes + writer.value.len();
        self.entries.push((String::from(key), writer.value));
        Ok(())
    }

    pub(crate) fn remove_all(&mut self, key: &str) {
        self.entries.retain(|(entry_key, value)| {
            if entry_key == key {
                self.total_bytes -= entry_key.len() + value.len() + 2;
                false
            } else {
                true
            }
        });
    }
}

struct ValueWriter {
    value: String,
    limit: usize,
    error: Option<Error>,
}

impl Write for ValueWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.error.is_some() {
            return Err(fmt::Error);
        }
        if text.contains('\0') {
            self.error = Some(Error::InvalidValue);
            return Err(fmt::Error);
        }
        if text.len() > self.limit - self.value.len() {
            self.error = Some(Error::NoMemory);
            return Err(fmt::Error);
        }
        self.value.push_str(text);
        Ok(())
    }
}

/// A fully budgeted device notification ready for broadcasting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Uevent {
    action: UeventAction,
    devpath: String,
    subsystem: String,
    vars: UeventVars,
    seqnum: u64,
}

impl Uevent {
    /// Constructs an event and allocates its sequence number exactly once.
    ///
    /// The 64-entry and 2048-byte limits include `ACTION`, `DEVPATH`, `SUBSYSTEM`,
    /// and `SEQNUM`. Invalid fields or an exhausted budget do not consume a sequence
    /// number. Device paths are absolute paths relative to the sysfs mount, not `/sys`.
    pub fn new(
        action: UeventAction,
        devpath: String,
        subsystem: String,
        vars: UeventVars,
    ) -> Result<Self> {
        if !devpath.starts_with('/')
            || devpath == "/sys"
            || devpath.starts_with("/sys/")
            || devpath.contains('\0')
            || subsystem.is_empty()
            || subsystem.contains('\0')
        {
            return Err(Error::InvalidValue);
        }
        if vars.len() > MAX_UEVENT_VARS - 4 {
            return Err(Error::NoMemory);
        }
        let base_bytes = vars
            .total_bytes()
            .checked_add("ACTION".len() + action.as_str().len() + 2)
            .and_then(|bytes| bytes.checked_add("DEVPATH".len() + 2))
            .and_then(|bytes| bytes.checked_add(devpath.len()))
            .and_then(|bytes| bytes.checked_add("SUBSYSTEM".len() + 2))
            .and_then(|bytes| bytes.checked_add(subsystem.len()))
            .ok_or(Error::NoMemory)?;
        let seqnum = allocate_seqnum(base_bytes)?;
        Ok(Self {
            action,
            devpath,
            subsystem,
            vars,
            seqnum,
        })
    }

    /// Returns the event action.
    pub fn action(&self) -> UeventAction {
        self.action
    }

    /// Returns the device's path, such as `/devices/virtual/mem/null`.
    pub fn devpath(&self) -> &str {
        &self.devpath
    }

    /// Returns the bus or class name.
    pub fn subsystem(&self) -> &str {
        &self.subsystem
    }

    /// Returns the extra environment entries.
    pub fn vars(&self) -> &UeventVars {
        &self.vars
    }

    /// Returns the event's unique sequence number.
    pub fn seqnum(&self) -> u64 {
        self.seqnum
    }
}

fn allocate_seqnum(base_bytes: usize) -> Result<u64> {
    let mut current = current_seqnum();
    loop {
        let next = current.checked_add(1).ok_or(Error::ResourceUnavailable)?;
        let seq_bytes = "SEQNUM".len() + decimal_digits(next) + 2;
        if base_bytes > MAX_UEVENT_BYTES - seq_bytes {
            return Err(Error::NoMemory);
        }
        match CURRENT_SEQNUM.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(next),
            Err(observed) => current = observed,
        }
    }
}

fn decimal_digits(mut value: u64) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

/// Parses the Linux synthetic request grammar, without whitespace normalization.
///
/// Exactly one final LF or NUL is optional. A bare action supplies `SYNTH_UUID=0`;
/// otherwise a canonical UUID is followed by space-separated alphanumeric `KEY=VALUE`
/// arguments, which become `SYNTH_ARG_KEY` entries. Temporary parser overflow is a
/// syntax error; complete-event overflow is reported separately at emission.
/// See <https://github.com/torvalds/linux/blob/v6.16/lib/kobject_uevent.c>.
pub(crate) fn parse_synthetic(input: &str) -> Result<(UeventAction, UeventVars)> {
    let request = input
        .strip_suffix('\n')
        .or_else(|| input.strip_suffix('\0'))
        .unwrap_or(input);
    if request.is_empty()
        || request
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r' | b'\t'))
    {
        return Err(Error::InvalidValue);
    }
    let (action, tail) = request
        .split_once(' ')
        .map_or((request, None), |(action, tail)| (action, Some(tail)));
    let action = UeventAction::parse(action).ok_or(Error::InvalidValue)?;
    let mut vars = UeventVars::new();
    let Some(tail) = tail else {
        vars.add("SYNTH_UUID", "0")?;
        return Ok((action, vars));
    };
    let (uuid, args) = tail
        .split_once(' ')
        .map_or((tail, None), |(uuid, args)| (uuid, Some(args)));
    if !is_valid_uuid(uuid) {
        return Err(Error::InvalidValue);
    }
    vars.add("SYNTH_UUID", uuid)
        .map_err(|_| Error::InvalidValue)?;
    if let Some(args) = args {
        for token in args.split(' ') {
            let (key, value) = token.split_once('=').ok_or(Error::InvalidValue)?;
            if key.is_empty()
                || value.is_empty()
                || !key.bytes().all(|byte| byte.is_ascii_alphanumeric())
                || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
            {
                return Err(Error::InvalidValue);
            }
            let synth_key = alloc::format!("SYNTH_ARG_{key}");
            vars.add(&synth_key, value)
                .map_err(|_| Error::InvalidValue)?;
        }
    }
    Ok((action, vars))
}

fn is_valid_uuid(uuid: &str) -> bool {
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(ktest)]
mod test {
    use alloc::{string::ToString, vec, vec::Vec};

    use ostd::prelude::ktest;

    use super::{Uevent, UeventAction, UeventVars};
    use crate::{common::Error, uevent};

    #[ktest]
    fn synthetic_environment_preserves_uuid_and_duplicate_argument_order() {
        let (action, vars) = uevent::parse_synthetic(
            "change 12345678-ABCD-1234-abcd-123456789abc FOO=1 BAR=2 FOO=3\0",
        )
        .unwrap();
        assert_eq!(action, UeventAction::Change);
        assert_eq!(
            vars.iter().collect::<Vec<_>>(),
            vec![
                ("SYNTH_UUID", "12345678-ABCD-1234-abcd-123456789abc"),
                ("SYNTH_ARG_FOO", "1"),
                ("SYNTH_ARG_BAR", "2"),
                ("SYNTH_ARG_FOO", "3"),
            ]
        );
        let (action, vars) = uevent::parse_synthetic("add\n").unwrap();
        assert_eq!(action, UeventAction::Add);
        assert_eq!(vars.iter().collect::<Vec<_>>(), vec![("SYNTH_UUID", "0")]);
    }

    #[ktest]
    fn variable_validation_does_not_modify_an_existing_environment() {
        let mut vars = UeventVars::new();
        vars.add("KEEP", "value").unwrap();
        let expected = vars.clone();
        for (key, value) in [("", "x"), ("K=V", "x"), ("K\0", "x"), ("K", "x\0y")] {
            assert!(matches!(vars.add(key, value), Err(Error::InvalidValue)));
            assert_eq!(vars, expected);
        }
        assert!(matches!(
            vars.add("BIG", "v".repeat(2048)),
            Err(Error::NoMemory)
        ));
        assert_eq!(vars, expected);
    }
    #[ktest]
    fn complete_events_count_base_fields_and_preserve_failed_append_state() {
        let mut vars = UeventVars::new();
        vars.add("K", "v".repeat(2045)).unwrap();
        assert_eq!(vars.total_bytes(), 2048);
        let snapshot = vars.clone();
        assert!(matches!(vars.add("NEXT", "v"), Err(Error::NoMemory)));
        assert_eq!(vars, snapshot);
        assert!(matches!(
            Uevent::new(
                UeventAction::Change,
                "/devices/budget".into(),
                "test".into(),
                vars
            ),
            Err(Error::NoMemory)
        ));

        let mut vars = UeventVars::new();
        for _ in 0..60 {
            vars.add("K", "v").unwrap();
        }
        let event = Uevent::new(
            UeventAction::Change,
            "/devices/budget".into(),
            "test".into(),
            vars.clone(),
        )
        .unwrap();
        assert_eq!(event.vars().iter().count(), 60);
        vars.add("K", "v").unwrap();
        let before = uevent::current_seqnum();
        assert!(matches!(
            Uevent::new(
                UeventAction::Change,
                "/devices/budget".into(),
                "test".into(),
                vars
            ),
            Err(Error::NoMemory)
        ));
        assert_eq!(uevent::current_seqnum(), before);

        let seq_digits = (before + 1).to_string().len();
        let base_bytes = "ACTION=change\0DEVPATH=/devices/budget\0SUBSYSTEM=test\0".len();
        let value_len = 2048 - base_bytes - "SEQNUM=\0".len() - seq_digits - "K=\0".len();
        let mut vars = UeventVars::new();
        vars.add("K", "v".repeat(value_len)).unwrap();
        let event = Uevent::new(
            UeventAction::Change,
            "/devices/budget".into(),
            "test".into(),
            vars,
        )
        .unwrap();
        assert_eq!(event.seqnum(), before + 1);
        assert_eq!(
            base_bytes
                + "SEQNUM=\0".len()
                + event.seqnum().to_string().len()
                + event.vars().total_bytes(),
            2048
        );
        assert_eq!(event.devpath(), "/devices/budget");
        assert_eq!(event.subsystem(), "test");
        assert_eq!(event.action(), UeventAction::Change);
        let mut oversized = UeventVars::new();
        oversized.add("K", "v".repeat(value_len + 1)).unwrap();
        let before = uevent::current_seqnum();
        assert!(matches!(
            Uevent::new(
                UeventAction::Change,
                "/devices/budget".into(),
                "test".into(),
                oversized
            ),
            Err(Error::NoMemory)
        ));
        assert_eq!(uevent::current_seqnum(), before);
    }
}
