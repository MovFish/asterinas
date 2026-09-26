// SPDX-License-Identifier: MPL-2.0

//! Device uevents: actions, bounded variable collections, and synthetic request parsing.
//!
//! When devices appear, disappear, or change state in the kernel device model,
//! notifications known as uevents are sent to user space (typically via Netlink).
//! In addition to kernel-generated events, user space can trigger synthetic uevents
//! by writing to a device's `uevent` sysfs attribute.
//!
//! This module defines:
//! - [`UeventAction`]: The set of actions a device uevent can represent.
//! - [`UeventVars`]: A bounded, ordered key-value collection of environment variables.
//! - [`Uevent`]: A fully constructed event with action, devpath, subsystem, variables,
//!   and a monotonically incrementing sequence number.
//! - [`current_seqnum`]: A function to query the global sequence counter without mutating it.
//! - Synthetic request parser: Validates and parses user-supplied attribute strings
//!   into an action and synthetic environment variables according to the kernel uevent grammar.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{Error, Result};

/// Maximum number of environment variable entries permitted in an event.
///
/// This matches Linux's `UEVENT_NUM_ENVP` limit:
/// <https://github.com/torvalds/linux/blob/v6.16/include/linux/kobject.h>.
const MAX_UEVENT_VARS: usize = 64;

/// Maximum total size in bytes of environment variables in an event.
///
/// This matches Linux's `UEVENT_BUFFER_SIZE` limit:
/// <https://github.com/torvalds/linux/blob/v6.16/include/linux/kobject.h>.
const MAX_UEVENT_BYTES: usize = 2048;

/// The most recently allocated uevent sequence number.
static CURRENT_SEQNUM: AtomicU64 = AtomicU64::new(0);

/// Returns the current uevent sequence number without modifying the counter.
pub fn current_seqnum() -> u64 {
    CURRENT_SEQNUM.load(Ordering::Relaxed)
}

/// The action represented by a device uevent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UeventAction {
    /// A device has been added to the system.
    Add,
    /// A device has been removed from the system.
    Remove,
    /// A device property or state has changed.
    Change,
    /// A device has moved to a new path in the hierarchy.
    Move,
    /// A device has been brought online.
    Online,
    /// A device has been taken offline.
    Offline,
    /// A device has been bound to a driver.
    Bind,
    /// A device has been unbound from a driver.
    Unbind,
}

impl UeventAction {
    /// Returns the exact lowercase wire string representation of the action.
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
        match value {
            "add" => Some(Self::Add),
            "remove" => Some(Self::Remove),
            "change" => Some(Self::Change),
            "move" => Some(Self::Move),
            "online" => Some(Self::Online),
            "offline" => Some(Self::Offline),
            "bind" => Some(Self::Bind),
            "unbind" => Some(Self::Unbind),
            _ => None,
        }
    }
}

impl fmt::Display for UeventAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An ordered collection of `KEY=VALUE` environment variables for a uevent.
///
/// Duplicate keys are permitted and preserve insertion order.
/// Each variable contributes `key.len() + 1 + value.len() + 1` bytes (`=` and `\0`)
/// toward the environment size limit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UeventVars {
    entries: Vec<(String, String)>,
    total_bytes: usize,
}

impl UeventVars {
    /// Creates an empty environment variable collection.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            total_bytes: 0,
        }
    }

    /// Returns the number of variables in the collection.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the collection contains no variables.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the total serialized byte size of all variables including separators and NUL bytes.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns an iterator over the key-value pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Appends a key-value pair to the collection.
    ///
    /// The key must be non-empty and must not contain `=` or NUL bytes (`\0`).
    /// The formatted value must not contain NUL bytes.
    ///
    /// If adding the variable would exceed [`MAX_UEVENT_VARS`] or [`MAX_UEVENT_BYTES`],
    /// this function returns an error without modifying the collection.
    pub fn add(&mut self, key: &str, value: impl fmt::Display) -> Result<()> {
        if key.is_empty() || key.contains('=') || key.contains('\0') {
            return Err(Error::InvalidValue);
        }
        let val_str = value.to_string();
        if val_str.contains('\0') {
            return Err(Error::InvalidValue);
        }

        // Each entry consumes: key.len() + '=' (1) + val.len() + '\0' (1)
        let entry_len = key.len() + 1 + val_str.len() + 1;

        if self.entries.len() + 1 > MAX_UEVENT_VARS
            || self.total_bytes + entry_len > MAX_UEVENT_BYTES
        {
            return Err(Error::NoMemory);
        }

        self.entries.push((String::from(key), val_str));
        self.total_bytes += entry_len;
        Ok(())
    }

    /// Removes all occurrences of variables with the specified key.
    pub(crate) fn remove_all(&mut self, key_to_remove: &str) {
        self.entries.retain(|(k, v)| {
            if k == key_to_remove {
                let entry_len = k.len() + 1 + v.len() + 1;
                self.total_bytes -= entry_len;
                false
            } else {
                true
            }
        });
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

fn allocate_seqnum() -> Result<u64> {
    let previous = CURRENT_SEQNUM
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| Error::ResourceUnavailable)?;
    previous.checked_add(1).ok_or(Error::ResourceUnavailable)
}

/// A fully constructed and budgeted device uevent ready for distribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Uevent {
    action: UeventAction,
    devpath: String,
    subsystem: String,
    vars: UeventVars,
    seqnum: u64,
}

impl Uevent {
    /// Constructs a new `Uevent` after validating the complete environment budget
    /// and allocating a sequence number.
    ///
    /// The final environment budget includes:
    /// - 3 base fields: `ACTION=<action>`, `DEVPATH=<devpath>`, `SUBSYSTEM=<subsystem>`
    /// - All extra variables in `vars`
    /// - 1 sequence number field: `SEQNUM=<seqnum>`
    ///
    /// If the environment exceeds [`MAX_UEVENT_VARS`] or [`MAX_UEVENT_BYTES`],
    /// [`Error::NoMemory`] is returned.
    pub fn new(
        action: UeventAction,
        devpath: String,
        subsystem: String,
        vars: UeventVars,
    ) -> Result<Self> {
        // Base fields (3) + vars + SEQNUM (1)
        if vars.len() + 4 > MAX_UEVENT_VARS {
            return Err(Error::NoMemory);
        }

        if devpath.is_empty()
            || !devpath.starts_with('/')
            || devpath.starts_with("/sys/")
            || devpath == "/sys"
            || devpath.contains('\0')
        {
            return Err(Error::InvalidValue);
        }

        if subsystem.is_empty() || subsystem.contains('\0') {
            return Err(Error::InvalidValue);
        }

        let action_bytes = "ACTION".len() + 1 + action.as_str().len() + 1;
        let devpath_bytes = "DEVPATH".len() + 1 + devpath.len() + 1;
        let subsystem_bytes = "SUBSYSTEM".len() + 1 + subsystem.len() + 1;
        let base_bytes = action_bytes + devpath_bytes + subsystem_bytes + vars.total_bytes();

        // Even minimal SEQNUM=0\0 takes 9 bytes ("SEQNUM" 6 + "=" 1 + "0" 1 + "\0" 1 = 9).
        if base_bytes + 9 > MAX_UEVENT_BYTES {
            return Err(Error::NoMemory);
        }

        let seqnum = allocate_seqnum()?;
        let seq_bytes = "SEQNUM".len() + 1 + decimal_digits(seqnum) + 1;

        if base_bytes + seq_bytes > MAX_UEVENT_BYTES {
            // Sequence holes are permitted if the final size check fails.
            return Err(Error::NoMemory);
        }

        Ok(Self {
            action,
            devpath,
            subsystem,
            vars,
            seqnum,
        })
    }

    /// Returns the action of the event.
    pub fn action(&self) -> UeventAction {
        self.action
    }

    /// Returns the sysfs device path of the event (e.g. `/devices/virtual/mem/null`).
    pub fn devpath(&self) -> &str {
        &self.devpath
    }

    /// Returns the subsystem name of the event.
    pub fn subsystem(&self) -> &str {
        &self.subsystem
    }

    /// Returns the extra environment variables of the event.
    pub fn vars(&self) -> &UeventVars {
        &self.vars
    }

    /// Returns the unique sequence number of the event.
    pub fn seqnum(&self) -> u64 {
        self.seqnum
    }
}

/// Validates whether a string conforms to the 8-4-4-4-12 UUID layout.
fn is_valid_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let b = s.as_bytes();
    for (i, &byte) in b.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Parses a synthetic uevent request according to the Linux kernel synthetic grammar.
///
/// Strips exactly one trailing linefeed (`\n`) or NUL byte (`\0`).
/// No other whitespace trimming is performed.
///
/// On syntax or temporary environment overflow errors, [`Error::InvalidValue`] is returned.
/// See <https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-uevent> and
/// <https://github.com/torvalds/linux/blob/v6.16/lib/kobject_uevent.c>.
pub(crate) fn parse_synthetic(input: &str) -> Result<(UeventAction, UeventVars)> {
    if input.is_empty() {
        return Err(Error::InvalidValue);
    }

    let request = if input.ends_with('\n') || input.ends_with('\0') {
        &input[..input.len() - 1]
    } else {
        input
    };
    if request.is_empty()
        || request.contains('\0')
        || request.contains('\n')
        || request.contains('\r')
        || request.contains('\t')
        || request.starts_with(' ')
    {
        return Err(Error::InvalidValue);
    }

    let (action_str, tail) = match request.split_once(' ') {
        Some((action, tail)) => (action, Some(tail)),
        None => (request, None),
    };
    let action = UeventAction::parse(action_str).ok_or(Error::InvalidValue)?;

    let mut vars = UeventVars::new();
    let Some(tail) = tail else {
        vars.add("SYNTH_UUID", "0")
            .map_err(|_| Error::InvalidValue)?;
        return Ok((action, vars));
    };

    let (uuid, args) = parse_synthetic_tail(tail)?;
    vars.add("SYNTH_UUID", uuid)
        .map_err(|_| Error::InvalidValue)?;
    if let Some(args) = args {
        add_synthetic_args(args, &mut vars)?;
    }

    Ok((action, vars))
}

fn parse_synthetic_tail(tail: &str) -> Result<(&str, Option<&str>)> {
    if tail.starts_with(' ') {
        return Err(Error::InvalidValue);
    }

    let uuid = tail.get(..36).ok_or(Error::InvalidValue)?;
    if !is_valid_uuid(uuid) {
        return Err(Error::InvalidValue);
    }

    match tail.as_bytes().get(36) {
        None => Ok((uuid, None)),
        Some(b' ') => {
            let args = tail.get(37..).ok_or(Error::InvalidValue)?;
            if args.is_empty() || args.ends_with(' ') {
                return Err(Error::InvalidValue);
            }
            Ok((uuid, Some(args)))
        }
        Some(_) => Err(Error::InvalidValue),
    }
}

fn add_synthetic_args(args: &str, vars: &mut UeventVars) -> Result<()> {
    for token in args.split(' ') {
        if token.is_empty() {
            return Err(Error::InvalidValue);
        }
        let (key, value) = token.split_once('=').ok_or(Error::InvalidValue)?;
        if value.contains('=') || key.is_empty() || value.is_empty() {
            return Err(Error::InvalidValue);
        }
        if !key.chars().all(|c| c.is_ascii_alphanumeric())
            || !value.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Err(Error::InvalidValue);
        }

        let mut synth_key = String::with_capacity(10 + key.len());
        synth_key.push_str("SYNTH_ARG_");
        synth_key.push_str(key);
        vars.add(&synth_key, value)
            .map_err(|_| Error::InvalidValue)?;
    }
    Ok(())
}

#[cfg(ktest)]
mod test {
    use alloc::vec;

    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn synthetic_actions_and_uuids() {
        let actions = [
            ("add", UeventAction::Add),
            ("remove", UeventAction::Remove),
            ("change", UeventAction::Change),
            ("move", UeventAction::Move),
            ("online", UeventAction::Online),
            ("offline", UeventAction::Offline),
            ("bind", UeventAction::Bind),
            ("unbind", UeventAction::Unbind),
        ];

        for (name, expected) in actions {
            // Bare action
            let (act, vars) = parse_synthetic(name).expect("bare action should succeed");
            assert_eq!(act, expected);
            let entries: Vec<_> = vars.iter().collect();
            assert_eq!(entries, vec![("SYNTH_UUID", "0")]);

            // With UUID (lowercase)
            let raw_lower = alloc::format!("{} 12345678-abcd-1234-abcd-123456789abc", name);
            let (act, vars) = parse_synthetic(&raw_lower).expect("action with uuid should succeed");
            assert_eq!(act, expected);
            let entries: Vec<_> = vars.iter().collect();
            assert_eq!(
                entries,
                vec![("SYNTH_UUID", "12345678-abcd-1234-abcd-123456789abc")]
            );

            // With UUID (uppercase)
            let raw_upper = alloc::format!("{} 12345678-ABCD-1234-ABCD-123456789ABC", name);
            let (act, vars) =
                parse_synthetic(&raw_upper).expect("action with upper uuid should succeed");
            assert_eq!(act, expected);
            let entries: Vec<_> = vars.iter().collect();
            assert_eq!(
                entries,
                vec![("SYNTH_UUID", "12345678-ABCD-1234-ABCD-123456789ABC")]
            );
        }

        // Ordered duplicate arguments
        let raw = "change 12345678-1234-1234-1234-123456789abc FOO=1 BAR=2 FOO=3";
        let (act, vars) = parse_synthetic(raw).expect("duplicate args should succeed");
        assert_eq!(act, UeventAction::Change);
        let entries: Vec<_> = vars.iter().collect();
        assert_eq!(
            entries,
            vec![
                ("SYNTH_UUID", "12345678-1234-1234-1234-123456789abc"),
                ("SYNTH_ARG_FOO", "1"),
                ("SYNTH_ARG_BAR", "2"),
                ("SYNTH_ARG_FOO", "3"),
            ]
        );
    }

    #[ktest]
    fn synthetic_line_endings_and_nul() {
        // Single LF accepted
        assert!(parse_synthetic("add\n").is_ok());
        // Single NUL accepted
        assert!(parse_synthetic("add\0").is_ok());
        // No line ending accepted
        assert!(parse_synthetic("add").is_ok());

        // CRLF rejected
        assert!(parse_synthetic("add\r\n").is_err());
        // Double LF rejected
        assert!(parse_synthetic("add\n\n").is_err());
        // LF + NUL rejected
        assert!(parse_synthetic("add\n\0").is_err());
        // Double NUL rejected
        assert!(parse_synthetic("add\0\0").is_err());
        // Embedded NUL rejected
        assert!(parse_synthetic("ad\0d\n").is_err());
        assert!(parse_synthetic("ad\0d").is_err());
    }

    #[ktest]
    fn synthetic_malformed_inputs() {
        let valid_uuid = "12345678-1234-1234-1234-123456789abc";

        // Invalid actions
        assert!(parse_synthetic("ADD").is_err());
        assert!(parse_synthetic("unknown").is_err());
        assert!(parse_synthetic("").is_err());

        // Leading whitespace or tabs
        assert!(parse_synthetic(" add").is_err());
        assert!(parse_synthetic("\tadd").is_err());
        assert!(parse_synthetic(&alloc::format!("add\t{}", valid_uuid)).is_err());

        // Double space after action
        assert!(parse_synthetic(&alloc::format!("add  {}", valid_uuid)).is_err());

        // UUID wrong grouping / lengths
        assert!(parse_synthetic("add 12345678-1234-1234-1234-123456789ab").is_err()); // 35 chars
        assert!(parse_synthetic("add 12345678-1234-1234-1234-123456789abcd").is_err()); // 37 chars no space
        assert!(parse_synthetic("add 1234567-81234-1234-1234-123456789abc").is_err()); // wrong dash pos
        assert!(parse_synthetic("add 12345678_1234-1234-1234-123456789abc").is_err()); // underscore dash

        // Trailing space after UUID
        assert!(parse_synthetic(&alloc::format!("add {} ", valid_uuid)).is_err());

        // Double space between args
        assert!(parse_synthetic(&alloc::format!("add {} A=1  B=2", valid_uuid)).is_err());

        // Trailing space after args
        assert!(parse_synthetic(&alloc::format!("add {} A=1 ", valid_uuid)).is_err());

        // Empty key or value
        assert!(parse_synthetic(&alloc::format!("add {} =1", valid_uuid)).is_err());
        assert!(parse_synthetic(&alloc::format!("add {} A=", valid_uuid)).is_err());
        assert!(parse_synthetic(&alloc::format!("add {} =", valid_uuid)).is_err());

        // Multiple equals
        assert!(parse_synthetic(&alloc::format!("add {} A=1=2", valid_uuid)).is_err());

        // Underscores in key or value
        assert!(parse_synthetic(&alloc::format!("add {} A_B=1", valid_uuid)).is_err());
        assert!(parse_synthetic(&alloc::format!("add {} A=1_2", valid_uuid)).is_err());

        // Non-ASCII input, including a multibyte character crossing the UUID boundary.
        assert!(parse_synthetic(&alloc::format!("add {} 键=值", valid_uuid)).is_err());
        assert!(parse_synthetic("add 12345678-1234-1234-1234-123456789abé").is_err());
    }

    #[ktest]
    fn synthetic_temporary_budget_boundaries() {
        let valid_uuid = "12345678-1234-1234-1234-123456789abc";

        // 63 arguments + 1 SYNTH_UUID = 64 items (exactly MAX_UEVENT_VARS).
        // Each arg: K00=V -> SYNTH_ARG_K00=V (14 + 1 + 1 + 1 = 17 bytes).
        // 63 * 17 = 1071 bytes. SYNTH_UUID takes 10 + 1 + 36 + 1 = 48 bytes.
        // Total bytes ~ 1119 bytes <= 2048 bytes.
        let mut synth_line = alloc::format!("change {}", valid_uuid);
        for i in 0..63 {
            synth_line.push_str(&alloc::format!(" K{:02}=1", i));
        }
        let (_, vars) = parse_synthetic(&synth_line).expect("64 items should succeed");
        assert_eq!(vars.len(), 64);

        // 64 arguments + 1 SYNTH_UUID = 65 items (exceeds MAX_UEVENT_VARS 64).
        synth_line.push_str(" K63=1");
        assert!(
            matches!(parse_synthetic(&synth_line), Err(Error::InvalidValue)),
            "65 items should fail with InvalidValue"
        );

        // Exceeding MAX_UEVENT_BYTES (2048) in temporary environment
        // UUID is 48 bytes. Remaining budget: 2000 bytes.
        // Max 63 args. If we make each arg large enough:
        // Say 20 args with value length 100 -> each SYNTH_ARG_A=... is 10 + 1 + 1 + 100 + 1 = 113 bytes.
        // 20 * 113 = 2260 bytes > 2048 bytes.
        let mut large_line = alloc::format!("change {}", valid_uuid);
        let val_100 = "a".repeat(100);
        for i in 0..20 {
            large_line.push_str(&alloc::format!(" K{:02}={}", i, val_100));
        }
        assert!(
            matches!(parse_synthetic(&large_line), Err(Error::InvalidValue)),
            "byte budget overflow in synthetic parser should fail with InvalidValue"
        );
    }

    #[ktest]
    fn final_environment_budget_and_seqnum() {
        let valid_uuid = "12345678-1234-1234-1234-123456789abc";

        // 61 args + 1 SYNTH_UUID = 62 vars.
        // In Uevent::new: 3 base fields + 62 vars + 1 SEQNUM = 66 items > 64!
        let mut synth_line = alloc::format!("change {}", valid_uuid);
        for i in 0..61 {
            synth_line.push_str(&alloc::format!(" K{:02}=1", i));
        }
        let (action, vars) = parse_synthetic(&synth_line).expect("parsing 62 vars succeeds");
        assert_eq!(vars.len(), 62);

        // Building Uevent must fail with NoMemory because final items = 62 + 4 = 66 > 64
        let res = Uevent::new(
            action,
            String::from("/devices/virtual/test"),
            String::from("virtual"),
            vars,
        );
        assert!(
            matches!(res, Err(Error::NoMemory)),
            "final items count overflow should fail with NoMemory"
        );
        let event = Uevent::new(
            UeventAction::Add,
            String::from("/devices/virtual/foo=bar"),
            String::from("virtual=devices"),
            UeventVars::new(),
        )
        .expect("equals signs are valid in uevent values");
        assert_eq!(event.devpath(), "/devices/virtual/foo=bar");
        assert_eq!(event.subsystem(), "virtual=devices");

        // Byte overflow at final stage:
        // Vars total bytes fit in 2048, but base fields + SEQNUM push it over 2048.
        let mut vars_heavy = UeventVars::new();
        // Add 19 vars of 100 bytes each -> 19 * (3 + 1 + 100 + 1) = 1995 bytes.
        let val_100 = "b".repeat(100);
        for i in 0..19 {
            vars_heavy
                .add(&alloc::format!("K{:02}", i), &val_100)
                .expect("within vars budget");
        }
        assert_eq!(vars_heavy.total_bytes(), 1995);

        // The base fields and a long device path push the final environment over 2048 bytes.
        let long_devpath = alloc::format!("/devices/virtual/{}", "c".repeat(50));
        let res = Uevent::new(
            UeventAction::Add,
            long_devpath,
            String::from("virtual"),
            vars_heavy,
        );
        assert!(
            matches!(res, Err(Error::NoMemory)),
            "final bytes overflow should fail with NoMemory"
        );
    }

    #[ktest]
    fn vars_add_failure_does_not_corrupt() {
        let mut vars = UeventVars::new();
        vars.add("KEY1", "VAL1").unwrap();
        assert_eq!(vars.len(), 1);

        // Invalid key
        assert!(vars.add("KEY=2", "VAL2").is_err());
        assert!(vars.add("", "VAL2").is_err());
        assert!(vars.add("KEY\0", "VAL2").is_err());
        assert_eq!(vars.len(), 1);

        // Valid add succeeds
        vars.add("KEY2", "VAL2").unwrap();
        assert_eq!(vars.len(), 2);
        let items: Vec<_> = vars.iter().collect();
        assert_eq!(items, vec![("KEY1", "VAL1"), ("KEY2", "VAL2")]);
    }

    #[ktest]
    fn uevent_seqnum_uniqueness() {
        // Construct multiple uevents sequentially and verify unique, increasing seqnums.
        let mut seqs = Vec::new();
        for i in 0..10 {
            let event = Uevent::new(
                UeventAction::Change,
                alloc::format!("/devices/virtual/test{}", i),
                String::from("virtual"),
                UeventVars::new(),
            )
            .expect("uevent should construct");
            seqs.push(event.seqnum());
        }

        assert_eq!(seqs.len(), 10);
        // All seqnums must be strictly positive
        for &s in &seqs {
            assert!(s > 0);
        }
        // Deduplication should retain all 10 entries
        let mut deduped = seqs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), seqs.len());
    }
}
