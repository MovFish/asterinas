// SPDX-License-Identifier: MPL-2.0

//! Implementation of the `/sys/kernel` sysfs directory.
//!
//! This module provides the `/sys/kernel` directory in sysfs, which contains
//! kernel-specific attributes and information. Currently implemented attributes:
//!
//! - `cpu_byteorder`: The endianness of the running kernel ("little" or "big")
//! - `address_bits`: The address size of the running kernel in bits
//! - `uevent_seqnum`: The global sequence number for device uevents
//!
//! These attributes follow the Linux kernel sysfs specification:
//! - [cpu_byteorder](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-kernel-cpu_byteorder)
//! - [address_bits](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-kernel-address_bits)
//! - [uevent_seqnum](https://github.com/torvalds/linux/blob/v6.16/kernel/ksysfs.c)

use alloc::sync::Arc;

use aster_systree::{
    BranchNodeFields, Error, Result, SysAttrSetBuilder, SysBranchNode, SysNode, SysPerms, SysStr,
    inherit_sys_branch_node,
};
use aster_util::printer::VmPrinter;
use inherit_methods_macro::inherit_methods;
use ostd::mm::{VmReader, VmWriter};
use spin::Once;

/// Registers a new kernel `SysNode`.
pub(super) fn register(config_obj: Arc<dyn SysNode>) -> crate::prelude::Result<()> {
    KERNEL_SYS_NODE_ROOT.get().unwrap().add_child(config_obj)?;
    Ok(())
}

/// Unregisters a kernel `SysNode`.
pub(super) fn unregister(name: &str) -> crate::prelude::Result<()> {
    let _ = KERNEL_SYS_NODE_ROOT.get().unwrap().remove_child(name)?;
    Ok(())
}

pub(super) fn init() {
    KERNEL_SYS_NODE_ROOT.call_once(|| {
        let singleton = KernelSysNodeRoot::new();
        super::systree_singleton()
            .root()
            .add_child(singleton.clone())
            .unwrap();

        singleton
    });
}

static KERNEL_SYS_NODE_ROOT: Once<Arc<KernelSysNodeRoot>> = Once::new();

/// A systree node representing the `/sys/kernel` directory.
///
/// This node serves as the root for all kernel-related sysfs entries,
/// including kernel parameters, debugging interfaces, and various
/// kernel subsystem information. It corresponds to the `/kernel`
/// directory in the sysfs filesystem.
#[derive(Debug)]
pub(crate) struct KernelSysNodeRoot {
    fields: BranchNodeFields<dyn SysNode, Self>,
}

#[inherit_methods(from = "self.fields")]
impl KernelSysNodeRoot {
    /// Creates a new `KernelSysNodeRoot` instance.
    fn new() -> Arc<Self> {
        let name = SysStr::from("kernel");

        let mut builder = SysAttrSetBuilder::new();
        builder.add(
            SysStr::from("cpu_byteorder"),
            SysPerms::DEFAULT_RO_ATTR_PERMS,
        );
        builder.add(
            SysStr::from("address_bits"),
            SysPerms::DEFAULT_RO_ATTR_PERMS,
        );
        builder.add(
            SysStr::from("uevent_seqnum"),
            SysPerms::DEFAULT_RO_ATTR_PERMS,
        );
        // TODO: Add more kernel-specific attributes.
        let attrs = builder
            .build()
            .expect("Failed to build kernel attribute set");

        Arc::new_cyclic(|weak_self| {
            let fields = BranchNodeFields::new(name, attrs, weak_self.clone());
            KernelSysNodeRoot { fields }
        })
    }

    /// Adds a kernel `SysNode` to this node.
    fn add_child(&self, new_child: Arc<dyn SysNode>) -> Result<()>;
}

inherit_sys_branch_node!(KernelSysNodeRoot, fields, {
    fn read_attr_at(&self, name: &str, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        match name {
            "cpu_byteorder" => {
                let value = if cfg!(target_endian = "little") {
                    "little"
                } else {
                    "big"
                };
                let mut printer = VmPrinter::new_skip(writer, offset);
                writeln!(printer, "{}", value)?;
                Ok(printer.bytes_written())
            }
            "address_bits" => {
                let mut printer = VmPrinter::new_skip(writer, offset);
                writeln!(printer, "{}", usize::BITS)?;
                Ok(printer.bytes_written())
            }
            "uevent_seqnum" => {
                let seq = aster_device::uevent::current_seqnum();
                let mut printer = VmPrinter::new_skip(writer, offset);
                writeln!(printer, "{}", seq)?;
                Ok(printer.bytes_written())
            }
            // TODO: Add support for reading other attributes.
            _ => Err(Error::AttributeError),
        }
    }

    fn write_attr(&self, _name: &str, _reader: &mut VmReader) -> Result<usize> {
        // TODO: Add support for writing attributes.
        Err(Error::AttributeError)
    }

    fn perms(&self) -> SysPerms {
        SysPerms::DEFAULT_RW_PERMS
    }
});

#[cfg(ktest)]
mod test {
    use alloc::vec;

    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn uevent_seqnum_attribute() {
        let root = KernelSysNodeRoot::new();

        // Read attribute into buffer
        let mut buf = vec![0u8; 64];
        let mut writer = VmWriter::from(buf.as_mut_slice()).to_fallible();
        let bytes = root.read_attr_at("uevent_seqnum", 0, &mut writer).unwrap();
        let s = core::str::from_utf8(&buf[..bytes]).unwrap();

        // Must be decimal number followed by '\n'
        assert!(s.ends_with('\n'));
        let num_str = s.trim_end();
        let parsed: u64 = num_str.parse().expect("uevent_seqnum must be decimal u64");

        // Consecutive reads must return the exact same value (read does not allocate seq)
        let mut buf2 = vec![0u8; 64];
        let mut writer2 = VmWriter::from(buf2.as_mut_slice()).to_fallible();
        let bytes2 = root.read_attr_at("uevent_seqnum", 0, &mut writer2).unwrap();
        let s2 = core::str::from_utf8(&buf2[..bytes2]).unwrap();
        assert_eq!(s, s2);
        assert_eq!(parsed, aster_device::uevent::current_seqnum());

        // Write must fail (read-only attribute)
        let input_bytes = b"123";
        let mut reader = VmReader::from(input_bytes.as_slice()).to_fallible();
        assert!(root.write_attr("uevent_seqnum", &mut reader).is_err());

        // Partial read with offset
        if s.len() > 1 {
            let mut buf_off = vec![0u8; 64];
            let mut writer_off = VmWriter::from(buf_off.as_mut_slice()).to_fallible();
            let bytes_off = root
                .read_attr_at("uevent_seqnum", 1, &mut writer_off)
                .unwrap();
            let s_off = core::str::from_utf8(&buf_off[..bytes_off]).unwrap();
            assert_eq!(s_off, &s[1..]);
        }
    }
}
