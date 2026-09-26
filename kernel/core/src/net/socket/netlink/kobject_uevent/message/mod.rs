// SPDX-License-Identifier: MPL-2.0

use aster_device::uevent::Uevent;

use crate::{
    net::socket::netlink::{
        GroupIdSet, NetlinkSocketAddr,
        receiver::QueueableMessage,
        table::{MulticastMessage, NetlinkUeventProtocol, SupportedNetlinkProtocol},
    },
    prelude::*,
    util::MultiWrite,
};

#[cfg(ktest)]
mod test;
mod uevent;

const KOBJECT_UEVENT_GROUP_MASK: u32 = 1;

/// A uevent message for Netlink multicast distribution.
///
/// Netlink uevent messages do not include a standard Netlink message header.
/// The payload is serialized as consecutive NUL-terminated strings.
#[derive(Clone, Debug)]
pub(crate) struct UeventMessage {
    raw: Arc<Vec<u8>>,
    src_addr: NetlinkSocketAddr,
}

impl UeventMessage {
    /// Constructs a new `UeventMessage` from an existing `Uevent`.
    fn from_uevent(event: &Uevent) -> Self {
        let raw = Arc::new(uevent::serialize_uevent(event));
        Self {
            raw,
            src_addr: NetlinkSocketAddr::new(0, GroupIdSet::new(KOBJECT_UEVENT_GROUP_MASK)),
        }
    }

    /// Returns the source address of the uevent message.
    pub(super) fn src_addr(&self) -> &NetlinkSocketAddr {
        &self.src_addr
    }

    /// Writes the uevent bytes to the given `writer`.
    pub(super) fn write_to(&self, writer: &mut dyn MultiWrite) -> Result<()> {
        let _nbytes = writer.write(&mut VmReader::from(self.raw.as_slice()))?;
        Ok(())
    }
}

impl QueueableMessage for UeventMessage {
    fn total_len(&self) -> usize {
        self.raw.len()
    }
}

impl MulticastMessage for UeventMessage {}

/// Broadcasts a device uevent to multicast group 1 (mask 1) with sender port 0.
pub(crate) fn broadcast_uevent(event: &Uevent) {
    let msg = UeventMessage::from_uevent(event);
    let _ = NetlinkUeventProtocol::multicast(GroupIdSet::new(KOBJECT_UEVENT_GROUP_MASK), msg);
}
