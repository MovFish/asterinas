// SPDX-License-Identifier: MPL-2.0

//! Wire format serialization for device uevents over Netlink.

use alloc::vec::Vec;

use aster_device::uevent::Uevent;

/// Serializes a device uevent into the exact Netlink multicast wire format:
/// `<action>@<devpath>\0ACTION=<action>\0DEVPATH=<devpath>\0SUBSYSTEM=<subsystem>\0...<var_k>=<var_v>\0...SEQNUM=<seqnum>\0`
pub(super) fn serialize_uevent(event: &Uevent) -> Vec<u8> {
    let action_str = event.action().as_str();
    let devpath = event.devpath();
    let subsystem = event.subsystem();

    // Format the sequence number without allocation.
    let mut seq_buf = [0u8; 32];
    let seq_str = format_u64(event.seqnum(), &mut seq_buf);

    // Precalculate exact capacity.
    let header_len = action_str.len() + 1 + devpath.len() + 1; // <action>@<devpath>\0
    let action_len = "ACTION".len() + 1 + action_str.len() + 1;
    let devpath_len = "DEVPATH".len() + 1 + devpath.len() + 1;
    let subsystem_len = "SUBSYSTEM".len() + 1 + subsystem.len() + 1;
    let vars_len = event.vars().total_bytes();
    let seqnum_len = "SEQNUM".len() + 1 + seq_str.len() + 1;

    let total_capacity =
        header_len + action_len + devpath_len + subsystem_len + vars_len + seqnum_len;
    let mut buf = Vec::with_capacity(total_capacity);

    // 1. Header: <action>@<devpath>\0
    buf.extend_from_slice(action_str.as_bytes());
    buf.push(b'@');
    buf.extend_from_slice(devpath.as_bytes());
    buf.push(0);

    // 2. Base fields
    buf.extend_from_slice(b"ACTION=");
    buf.extend_from_slice(action_str.as_bytes());
    buf.push(0);

    buf.extend_from_slice(b"DEVPATH=");
    buf.extend_from_slice(devpath.as_bytes());
    buf.push(0);

    buf.extend_from_slice(b"SUBSYSTEM=");
    buf.extend_from_slice(subsystem.as_bytes());
    buf.push(0);

    // 3. Extra variables (preserving insertion order)
    for (k, v) in event.vars().iter() {
        buf.extend_from_slice(k.as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(v.as_bytes());
        buf.push(0);
    }

    // 4. SEQNUM
    buf.extend_from_slice(b"SEQNUM=");
    buf.extend_from_slice(seq_str.as_bytes());
    buf.push(0);

    buf
}

fn format_u64(mut n: u64, buf: &mut [u8; 32]) -> &str {
    if n == 0 {
        return "0";
    }
    let mut idx = buf.len();
    while n > 0 {
        idx -= 1;
        buf[idx] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    core::str::from_utf8(&buf[idx..]).expect("ASCII digit bytes are valid UTF-8")
}
