// SPDX-License-Identifier: MPL-2.0

pub(super) use bound::BoundNetlink;
use ostd::sync::{PreemptDisabled, RwLockWriteGuard};
use unbound::UnboundNetlink;

use super::{
    GroupIdSet, NetlinkSocketAddr,
    options::{NetlinkOptionSet, StrictCheck},
};
use crate::{
    events::IoEvents,
    fs::file::FileCommon,
    net::socket::{
        Socket,
        netlink::{AddMembership, DropMembership, table::SupportedNetlinkProtocol},
        new_socket_common,
        options::{
            Error as SocketError, SocketOption,
            macros::{sock_option_mut, sock_option_ref},
        },
        private::SocketPrivate,
        util::{
            MessageHeader, RecvFlags, RecvOutput, SendFlags, SocketAddr,
            datagram_common::{Bound, Inner, select_remote_and_bind},
            options::{
                GetSocketLevelOption, SetSocketLevelOption, SocketOptionSet, SocketTimeouts,
            },
        },
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    util::{MultiRead, MultiWrite, net::SockType},
};

mod bound;
mod unbound;

pub(crate) struct NetlinkSocket<P: SupportedNetlinkProtocol> {
    inner: RwMutex<Inner<UnboundNetlink<P>, BoundNetlink<P::Message>>>,
    options: RwLock<OptionSet>,
    socket_type: SockType,
    timeouts: SocketTimeouts,

    pollee: Pollee,
    common: FileCommon,
}

#[derive(Clone, Debug)]
struct OptionSet {
    socket: SocketOptionSet,
    netlink: NetlinkOptionSet,
}

impl OptionSet {
    pub(self) fn new() -> Self {
        Self {
            socket: SocketOptionSet::new_netlink(),
            netlink: NetlinkOptionSet::new(),
        }
    }
}

impl<P: SupportedNetlinkProtocol> NetlinkSocket<P>
where
    BoundNetlink<P::Message>: Bound<Endpoint = NetlinkSocketAddr, SendOptions = NetlinkOptionSet>,
{
    pub(crate) fn new(is_nonblocking: bool, socket_type: SockType) -> Arc<Self> {
        debug_assert!(socket_type == SockType::SOCK_RAW || socket_type == SockType::SOCK_DGRAM);

        let options = OptionSet::new();
        let unbound = UnboundNetlink::new(options.socket.recv_buf() as usize);
        Arc::new(Self {
            inner: RwMutex::new(Inner::Unbound(unbound)),
            options: RwLock::new(options),
            socket_type,
            timeouts: SocketTimeouts::new(),
            pollee: Pollee::new(),
            common: new_socket_common(is_nonblocking),
        })
    }

    fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        remote: Option<&NetlinkSocketAddr>,
        flags: SendFlags,
    ) -> Result<usize> {
        let options = self.options.read().netlink;
        let sent_bytes = select_remote_and_bind(
            &self.inner,
            remote,
            || {
                self.inner
                    .write()
                    .bind_ephemeral(&NetlinkSocketAddr::new_unspecified(), &self.pollee)
            },
            |bound, remote_endpoint| bound.try_send(reader, remote_endpoint, flags, options),
        )?;
        self.pollee.invalidate();

        Ok(sent_bytes)
    }

    // FIXME: This method is marked as `pub(super)` because it's invoked during kernel mode testing.
    pub(super) fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, SocketAddr)> {
        let result = self
            .inner
            .read()
            .try_recv(writer, flags)
            .map(|(output, remote_endpoint)| (output, remote_endpoint.into()))?;
        self.pollee.invalidate();

        Ok(result)
    }
}

impl<P: SupportedNetlinkProtocol> Socket for NetlinkSocket<P>
where
    BoundNetlink<P::Message>: Bound<Endpoint = NetlinkSocketAddr, SendOptions = NetlinkOptionSet>,
{
    fn bind(&self, socket_addr: SocketAddr) -> Result<()> {
        let endpoint = socket_addr.try_into()?;

        self.inner.write().bind(&endpoint, &self.pollee, ())
    }

    fn connect(&self, socket_addr: SocketAddr) -> Result<()> {
        let endpoint = socket_addr.try_into()?;

        self.inner.write().connect(&endpoint, &self.pollee)
    }

    fn addr(&self) -> Result<SocketAddr> {
        let endpoint = match &*self.inner.read() {
            Inner::Unbound(unbound) => unbound.addr(),
            Inner::Bound(bound) => bound.local_endpoint(),
        };

        Ok(endpoint.into())
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        let endpoint = self
            .inner
            .read()
            .peer_addr()
            .cloned()
            .unwrap_or(NetlinkSocketAddr::new_unspecified());

        Ok(endpoint.into())
    }

    fn sendmsg(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendFlags,
    ) -> Result<usize> {
        let MessageHeader {
            addr,
            control_messages,
        } = message_header;

        let remote = match addr {
            None => None,
            Some(addr) => Some(addr.try_into()?),
        };

        if !control_messages.is_empty() {
            // TODO: Support sending control message
            warn!("sending control message is not supported");
        }

        if reader.is_empty() {
            // Based on how Linux behaves, zero-sized messages are not allowed for netlink sockets.
            return_errno_with_message!(Errno::ENODATA, "there are no data to send");
        }

        // TODO: Make sure our blocking behavior matches that of Linux
        self.try_send(reader, remote.as_ref(), flags)
    }

    fn recvmsg(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, MessageHeader)> {
        let (output, addr) = self.block_on(IoEvents::IN, self.timeouts.recv_timeout(), || {
            self.try_recv(writer, flags)
        })?;

        // TODO: Receive control message

        let message_header = MessageHeader::new(Some(addr), Vec::new());

        Ok((output, message_header))
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option {
            socket_errors @ SocketError => {
                // TODO: Support socket errors for netlink sockets
                socket_errors.set(None);
                return Ok(());
            }
            _ => (),
        });

        let inner = self.inner.read();
        let options = self.options.read();

        // Deal with socket-level options
        match options
            .socket
            .get_option(option, &(&*inner, self.socket_type, &self.timeouts))
        {
            Err(err) if err.error() == Errno::ENOPROTOOPT => (),
            res => return res,
        }

        // Deal with netlink-level options
        options.netlink.get_option(option)
    }

    fn set_option(&self, option: &dyn SocketOption) -> Result<()> {
        let mut inner = self.inner.write();

        // Deal with socket-level options
        let mut options = self.options.write();
        let old_recv_buf = options.socket.recv_buf();
        let res = options
            .socket
            .set_option(option, &(&*inner, &self.timeouts));
        match res {
            Ok(_) => {
                let recv_buf = options.socket.recv_buf();
                // Release the spinlock before taking the queue mutex.
                drop(options);
                if recv_buf != old_recv_buf {
                    inner.set_recv_buf(recv_buf as usize);
                }
                return Ok(());
            }
            Err(err) if err.error() == Errno::ENOPROTOOPT => (),
            Err(err) => return Err(err),
        }

        // Deal with netlink-level options
        do_netlink_setsockopt(option, options, &mut inner)
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }
}

impl<P: SupportedNetlinkProtocol> SocketPrivate for NetlinkSocket<P>
where
    BoundNetlink<P::Message>: Bound<Endpoint = NetlinkSocketAddr, SendOptions = NetlinkOptionSet>,
{
    fn is_nonblocking(&self) -> bool {
        self.common.is_nonblocking()
    }
}

impl<P: SupportedNetlinkProtocol> Pollable for NetlinkSocket<P>
where
    BoundNetlink<P::Message>: Bound<Endpoint = NetlinkSocketAddr, SendOptions = NetlinkOptionSet>,
{
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.inner.read().check_io_events())
    }
}

impl<P: SupportedNetlinkProtocol> GetSocketLevelOption
    for (
        &Inner<UnboundNetlink<P>, BoundNetlink<P::Message>>,
        SockType,
        &SocketTimeouts,
    )
{
    fn socket_type(&self) -> SockType {
        self.1
    }

    fn is_listening(&self) -> bool {
        false
    }

    fn socket_timeouts(&self) -> Option<&SocketTimeouts> {
        Some(self.2)
    }
}

impl<P: SupportedNetlinkProtocol> SetSocketLevelOption
    for (
        &Inner<UnboundNetlink<P>, BoundNetlink<P::Message>>,
        &SocketTimeouts,
    )
{
    fn socket_timeouts(&self) -> Option<&SocketTimeouts> {
        Some(self.1)
    }
}

impl<P: SupportedNetlinkProtocol> Inner<UnboundNetlink<P>, BoundNetlink<P::Message>> {
    fn add_groups(&mut self, groups: GroupIdSet) {
        match self {
            Inner::Unbound(unbound_socket) => unbound_socket.add_groups(groups),
            Inner::Bound(bound_socket) => bound_socket.add_groups(groups),
        }
    }

    fn drop_groups(&mut self, groups: GroupIdSet) {
        match self {
            Inner::Unbound(unbound_socket) => unbound_socket.drop_groups(groups),
            Inner::Bound(bound_socket) => bound_socket.drop_groups(groups),
        }
    }

    fn set_recv_buf(&mut self, recv_buf: usize) {
        match self {
            Inner::Unbound(unbound_socket) => unbound_socket.set_recv_buf(recv_buf),
            Inner::Bound(bound_socket) => bound_socket.set_recv_buf(recv_buf),
        }
    }
}

fn do_netlink_setsockopt<P: SupportedNetlinkProtocol>(
    option: &dyn SocketOption,
    mut options: RwLockWriteGuard<'_, OptionSet, PreemptDisabled>,
    inner: &mut Inner<UnboundNetlink<P>, BoundNetlink<P::Message>>,
) -> Result<()> {
    sock_option_ref!(match option {
        add_membership @ AddMembership => {
            // Membership updates may sleep,
            // so release the options lock first.
            drop(options);

            let group_id = add_membership.get().unwrap();
            inner.add_groups(GroupIdSet::from_group_id(*group_id)?);
        }
        drop_membership @ DropMembership => {
            // Membership updates may sleep,
            // so release the options lock first.
            drop(options);

            let group_id = drop_membership.get().unwrap();
            inner.drop_groups(GroupIdSet::from_group_id(*group_id)?);
        }
        strict @ StrictCheck => {
            options.netlink.set_strict_check(*strict.get().unwrap());
        }
        _ =>
            return_errno_with_message!(Errno::ENOPROTOOPT, "the socket option to be set is unknown"),
    });

    Ok(())
}
