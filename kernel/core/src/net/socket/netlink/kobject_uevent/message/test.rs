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
    crate::time::clocks::init_for_ktest();
    crate::net::socket::netlink::init();

    let socket = NetlinkUeventSocket::new(true, SockType::SOCK_DGRAM);
    let socket_addr = SocketAddr::Netlink(NetlinkSocketAddr::new(100, GroupIdSet::new(1)));
    socket.bind(socket_addr).unwrap();

    let mut buffer = vec![0u8; 1024];
    let mut writer = VmWriter::from(buffer.as_mut_slice()).to_fallible();
    let flags = RecvFlags::empty();
    let result = socket.try_recv(&mut writer, flags);
    assert!(result.is_err_and(|err| err.error() == Errno::EAGAIN));

    let mut vars = UeventVars::new();
    vars.add("INTERFACE", "lo").unwrap();
    vars.add("IFINDEX", "1").unwrap();
    let event = Uevent::new(
        UeventAction::Add,
        "/devices/virtual/net/lo".to_string(),
        "net".to_string(),
        vars,
    )
    .unwrap();
    crate::net::socket::netlink::broadcast_uevent(&event);

    let (output, source) = socket.try_recv(&mut writer, flags).unwrap();
    assert!(output.flags().is_empty());
    assert_eq!(
        source,
        SocketAddr::Netlink(NetlinkSocketAddr::new(0, GroupIdSet::new(1)))
    );
    let payload = core::str::from_utf8(&buffer[..output.len()]).unwrap();
    assert_eq!(
        payload,
        format!(
            "add@/devices/virtual/net/lo\0ACTION=add\0DEVPATH=/devices/virtual/net/lo\0SUBSYSTEM=net\0INTERFACE=lo\0IFINDEX=1\0SEQNUM={}\0",
            event.seqnum()
        )
    );

    // Delivery keeps the existing queue overflow semantics for userspace.
    let message_len = output.len();
    for _ in 0..=crate::net::socket::netlink::NETLINK_DEFAULT_BUF_SIZE / message_len {
        crate::net::socket::netlink::broadcast_uevent(&event);
    }
    let mut writer = VmWriter::from(buffer.as_mut_slice()).to_fallible();
    assert!(
        socket
            .try_recv(&mut writer, flags)
            .is_err_and(|err| err.error() == Errno::ENOBUFS)
    );
}
