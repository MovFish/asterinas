// SPDX-License-Identifier: MPL-2.0

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "netlink_sockoption.h"

static const int protocols[] = { NETLINK_ROUTE, NETLINK_KOBJECT_UEVENT };

#define FN_TEST_FOREACH_PROTO(name, sock_fd)                              \
	FN_TEST(name)                                                     \
	{                                                                 \
		for (size_t p = 0;                                        \
		     p < sizeof(protocols) / sizeof(protocols[0]); ++p) { \
			int sock_fd = TEST_SUCC(                          \
				socket(AF_NETLINK, SOCK_RAW, protocols[p]));

#define END_TEST_FOREACH_PROTO(sock_fd) \
	TEST_SUCC(close(sock_fd));      \
	}                               \
	}                               \
	END_TEST()

#define TEST_NL_GROUPS(fd, expected_nl_groups)                             \
	do {                                                               \
		struct sockaddr_nl _addr;                                  \
		socklen_t _addr_len = sizeof(_addr);                       \
		TEST_RES(getsockname(fd, (struct sockaddr *)&_addr,        \
				     &_addr_len),                          \
			 _addr_len == sizeof(_addr) &&                     \
				 _addr.nl_groups == (expected_nl_groups)); \
	} while (0)

FN_TEST_FOREACH_PROTO(membership_group_ids, sock_fd)
{
	TEST_SETSOCKOPT_INT(sock_fd, NETLINK_ADD_MEMBERSHIP, 1);
	TEST_NL_GROUPS(sock_fd, 1);

	for (int bound = 0; bound < 2; ++bound) {
		if (bound) {
			struct sockaddr_nl bind_addr = {
				.nl_family = AF_NETLINK,
				.nl_groups = 1,
			};
			TEST_SUCC(bind(sock_fd, (struct sockaddr *)&bind_addr,
				       sizeof(bind_addr)));
		}

		const uint32_t group_ids[] = { 5, 32 };
		for (size_t i = 0; i < sizeof(group_ids) / sizeof(group_ids[0]);
		     ++i) {
			uint32_t group = group_ids[i];
			uint32_t mask = UINT32_C(1) << (group - 1);

			TEST_SETSOCKOPT_INT(sock_fd, NETLINK_ADD_MEMBERSHIP,
					    group);
			TEST_NL_GROUPS(sock_fd, 1 | mask);

			TEST_SETSOCKOPT_INT(sock_fd, NETLINK_DROP_MEMBERSHIP,
					    1);
			TEST_NL_GROUPS(sock_fd, mask);

			TEST_SETSOCKOPT_INT(sock_fd, NETLINK_DROP_MEMBERSHIP,
					    group);
			TEST_NL_GROUPS(sock_fd, 0);

			TEST_SETSOCKOPT_INT(sock_fd, NETLINK_ADD_MEMBERSHIP, 1);
		}
	}
}
END_TEST_FOREACH_PROTO(sock_fd)

FN_TEST_FOREACH_PROTO(invalid_membership, sock_fd)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK, .nl_groups = 1 };
	TEST_SUCC(bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)));

	const int options[] = { NETLINK_ADD_MEMBERSHIP,
				NETLINK_DROP_MEMBERSHIP };
	for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
		uint32_t group = 5;
		for (socklen_t len = 0; len < sizeof(group); ++len) {
			// Setting truncated membership options fails with EINVAL.
			TEST_ERRNO(setsockopt(sock_fd, SOL_NETLINK, options[i],
					      &group, len),
				   EINVAL);
			TEST_ERRNO(setsockopt(sock_fd, SOL_NETLINK, options[i],
					      NULL, len),
				   EINVAL);

			TEST_NL_GROUPS(sock_fd, 1);
		}
		// Setting membership options with a NULL pointer fails with EFAULT.
		TEST_ERRNO(setsockopt(sock_fd, SOL_NETLINK, options[i], NULL,
				      sizeof(group)),
			   EFAULT);

		const uint32_t invalid_groups[] = { 0, UINT32_MAX,
						    UINT32_C(1) << 31 };
		for (size_t j = 0;
		     j < sizeof(invalid_groups) / sizeof(invalid_groups[0]);
		     ++j) {
			// Setting invalid membership options fails with EINVAL.
			TEST_ERRNO(setsockopt(sock_fd, SOL_NETLINK, options[i],
					      &invalid_groups[j],
					      sizeof(group)),
				   EINVAL);

			TEST_NL_GROUPS(sock_fd, 1);
		}

		for (socklen_t len = 0; len <= sizeof(group); ++len) {
			// Getting membership options fails with ENOPROTOOPT.
			TEST_ERRNO(getsockopt(sock_fd, SOL_NETLINK, options[i],
					      &group, &len),
				   ENOPROTOOPT);
		}
	}
}
END_TEST_FOREACH_PROTO(sock_fd)

FN_TEST_FOREACH_PROTO(strict_check_socket_option, sock_fd)
{
	TEST_GETSOCKOPT_INT(sock_fd, NETLINK_GET_STRICT_CHK, _opt == 0);

	TEST_SETSOCKOPT_INT(sock_fd, NETLINK_GET_STRICT_CHK, 1);
	TEST_GETSOCKOPT_INT(sock_fd, NETLINK_GET_STRICT_CHK, _opt == 1);
	TEST_SETSOCKOPT_INT(sock_fd, NETLINK_GET_STRICT_CHK, 0);
	TEST_GETSOCKOPT_INT(sock_fd, NETLINK_GET_STRICT_CHK, _opt == 0);

	int strict = -1;
	socklen_t option_len = sizeof(strict);
	TEST_ERRNO(getsockopt(sock_fd, SOL_NETLINK, 9999, &strict, &option_len),
		   ENOPROTOOPT);

	for (socklen_t len = 0; len < sizeof(int); ++len) {
		uint32_t input = UINT32_MAX;

		TEST_SETSOCKOPT_INT(sock_fd, NETLINK_GET_STRICT_CHK, 1);
		TEST_SUCC(setsockopt(sock_fd, SOL_NETLINK,
				     NETLINK_GET_STRICT_CHK, &input, len));
		TEST_GETSOCKOPT_INT(sock_fd, NETLINK_GET_STRICT_CHK, _opt == 0);

		// Short inputs must not access even a NULL buffer.
		TEST_SETSOCKOPT_INT(sock_fd, NETLINK_GET_STRICT_CHK, 1);
		TEST_SUCC(setsockopt(sock_fd, SOL_NETLINK,
				     NETLINK_GET_STRICT_CHK, NULL, len));
		TEST_GETSOCKOPT_INT(sock_fd, NETLINK_GET_STRICT_CHK, _opt == 0);

		uint32_t sentinel = 0xa5a5a5a5;
		uint32_t output = sentinel;
		socklen_t value_len = len;
		TEST_ERRNO(getsockopt(sock_fd, SOL_NETLINK,
				      NETLINK_GET_STRICT_CHK, &output,
				      &value_len),
			   EINVAL);
		TEST_RES(memcmp(&output, &sentinel, sizeof(output)),
			 _ret == 0 && value_len == len);
		TEST_ERRNO(getsockopt(sock_fd, SOL_NETLINK,
				      NETLINK_GET_STRICT_CHK, NULL, &value_len),
			   EINVAL);
	}

	// Ignore extra input bytes and only overwrite one integer on output.
	int input[2] = { -1, 0 };
	TEST_SUCC(setsockopt(sock_fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
			     input, sizeof(input)));
	TEST_ERRNO(setsockopt(sock_fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
			      NULL, sizeof(int)),
		   EFAULT);
	int output[2] = { -1, -1 };
	socklen_t output_len = sizeof(output);
	TEST_RES(getsockopt(sock_fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
			    output, &output_len),
		 output[0] == 1 && output[1] == -1 &&
			 output_len == sizeof(int));
}
END_TEST_FOREACH_PROTO(sock_fd)

// Regression for https://github.com/asterinas/asterinas/issues/4187.
// Invalid link queries generate error replies without changing any links.
static void queue_link_errors(int fd, unsigned int count)
{
	struct {
		struct nlmsghdr header;
		struct ifinfomsg link;
	} request = {
		.header = {
			.nlmsg_len = sizeof(request),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.link = { .ifi_index = INT32_MAX },
	};
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };

	for (unsigned int i = 0; i < count; ++i) {
		CHECK(sendto(fd, &request, sizeof(request), 0,
			     (struct sockaddr *)&kernel, sizeof(kernel)));
	}
}

static unsigned int drain_link_errors(int fd)
{
	unsigned int count = 0;
	struct {
		struct nlmsghdr header;
		struct nlmsgerr error;
		char payload[256];
	} reply;

	for (;;) {
		ssize_t len = recv(fd, &reply, sizeof(reply), MSG_DONTWAIT);
		if (len < 0) {
			if (errno == ENOBUFS)
				continue;
			int error = errno;
			CHECK_WITH(error, _ret == EAGAIN);
			return count;
		}
		CHECK_WITH(
			len,
			len >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)) &&
				reply.header.nlmsg_type == NLMSG_ERROR &&
				reply.error.error == -ENODEV);
		++count;
	}
}

FN_TEST(receive_buffer_queue_capacity)
{
	const int options[] = { SO_RCVBUF, SO_RCVBUFFORCE };
	const unsigned int count = 128;
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };

	for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
		// Exercise explicit and implicit binding, and resizing after binding.
		for (int bound = 0; bound < 3; ++bound) {
			int fd = TEST_SUCC(socket(AF_NETLINK,
						  SOCK_RAW | SOCK_NONBLOCK,
						  NETLINK_ROUTE));
			if (bound == 2)
				TEST_SUCC(bind(fd, (struct sockaddr *)&addr,
					       sizeof(addr)));

			int size = 0;
			TEST_SUCC(setsockopt(fd, SOL_SOCKET, options[i], &size,
					     sizeof(size)));
			if (bound == 1)
				TEST_SUCC(bind(fd, (struct sockaddr *)&addr,
					       sizeof(addr)));

			queue_link_errors(fd, count);
			TEST_RES(drain_link_errors(fd),
				 _ret > 0 && _ret < count);

			size = 65536;
			TEST_SUCC(setsockopt(fd, SOL_SOCKET, options[i], &size,
					     sizeof(size)));
			queue_link_errors(fd, count);
			TEST_RES(drain_link_errors(fd), _ret == count);

			// Shrinking a nonempty queue must not discard queued replies.
			queue_link_errors(fd, count);
			size = 0;
			TEST_SUCC(setsockopt(fd, SOL_SOCKET, options[i], &size,
					     sizeof(size)));
			queue_link_errors(fd, 1);
			TEST_ERRNO(recv(fd, &size, sizeof(size), MSG_DONTWAIT),
				   ENOBUFS);
			TEST_RES(drain_link_errors(fd), _ret == count);

			// Receiving frees space for subsequent messages.
			queue_link_errors(fd, 1);
			TEST_RES(drain_link_errors(fd), _ret == 1);
			TEST_SUCC(close(fd));
		}
	}
}
END_TEST()

FN_TEST(enlarged_receive_buffer)
{
	int fd = TEST_SUCC(
		socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE));
	// Allow for Linux's per-message memory overhead, not just payload bytes.
	int size = 8 * 1024 * 1024;
	TEST_SUCC(setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size,
			     sizeof(size)));

	// Even header-only error replies exceed 64 KiB in aggregate.
	const unsigned int count = 4096;
	queue_link_errors(fd, count);
	TEST_RES(drain_link_errors(fd), _ret == count);
	TEST_SUCC(close(fd));
}
END_TEST()
