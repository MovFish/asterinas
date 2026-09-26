// SPDX-License-Identifier: MPL-2.0

use alloc::{format, vec};

use aster_device::uevent::{Uevent, UeventAction, UeventVars};
use ostd::prelude::*;

use crate::{
    net::socket::{
        Socket,
        netlink::{GroupIdSet, NetlinkSocketAddr, NetlinkUeventSocket},
        util::{RecvFlags, SocketAddr},
    },
    prelude::*,
    util::net::SockType,
};

#[ktest]
fn multicast_device_uevent() {
    crate::net::socket::netlink::init();

    // Creates a new netlink uevent socket and joins group 1.
    let socket = NetlinkUeventSocket::new(true, SockType::SOCK_DGRAM);
    let socket_addr = SocketAddr::Netlink(NetlinkSocketAddr::new(
        100,
        GroupIdSet::new(super::KOBJECT_UEVENT_GROUP_MASK),
    ));
    socket.bind(socket_addr).unwrap();

    // Tries to receive and returns EAGAIN if no message is available.
    let mut buffer = vec![0u8; 1024];
    let mut writer = VmWriter::from(buffer.as_mut_slice()).to_fallible();
    let flags = RecvFlags::empty();
    let res = socket.try_recv(&mut writer, flags);
    assert!(res.is_err_and(|err| err.error() == Errno::EAGAIN));

    // Construct a device uevent
    let mut vars = UeventVars::new();
    vars.add("INTERFACE", "lo").unwrap();
    vars.add("IFINDEX", "1").unwrap();
    vars.add("EXTRA", "duplicate").unwrap();
    vars.add("EXTRA", "duplicate").unwrap();

    let uevent = Uevent::new(
        UeventAction::Add,
        "/devices/virtual/net/lo".to_string(),
        "net".to_string(),
        vars,
    )
    .unwrap();

    // Broadcast through the Netlink message helper
    super::broadcast_uevent(&uevent);

    let (output, _) = socket.try_recv(&mut writer, flags).unwrap();
    assert!(output.flags().is_empty());
    let s = core::str::from_utf8(&buffer[..output.len()]).unwrap();

    let expected = format!(
        "add@/devices/virtual/net/lo\0ACTION=add\0DEVPATH=/devices/virtual/net/lo\0SUBSYSTEM=net\0INTERFACE=lo\0IFINDEX=1\0EXTRA=duplicate\0EXTRA=duplicate\0SEQNUM={}\0",
        uevent.seqnum()
    );
    assert_eq!(s, expected);
}
