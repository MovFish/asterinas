// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/netlink.h>

#include "../common/test.h"

#define MAX_FIELDS 128
#define RECV_BUF_SIZE 4096

struct uevent_field {
	char key[64];
	char val[256];
};

struct parsed_uevent {
	char header_action[32];
	char header_devpath[256];
	char action[32];
	char devpath[256];
	char subsystem[64];
	uint64_t seqnum;
	bool has_seqnum;
	struct uevent_field fields[MAX_FIELDS];
	size_t num_fields;
};

struct target_filter {
	const char *action;
	const char *devpath;
	const char *synth_uuid;
};
enum recv_result {
	RECV_ERROR = -1,
	RECV_FOUND,
	RECV_TIMEOUT,
};

static int open_uevent_socket(uint32_t group_mask)
{
	int fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK,
			NETLINK_KOBJECT_UEVENT);
	if (fd < 0)
		return -1;
	struct sockaddr_nl addr;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = group_mask;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int parse_uevent_message(const char *buf, size_t len,
				struct parsed_uevent *ev)
{
	if (len == 0 || buf[len - 1] != '\0')
		return -1;

	memset(ev, 0, sizeof(*ev));

	// First segment: <action>@<devpath>\0
	size_t first_len = strlen(buf);
	if (first_len >= len)
		return -1;

	const char *at = strchr(buf, '@');
	if (!at || at == buf || *(at + 1) == '\0')
		return -1;

	size_t act_len = at - buf;
	if (act_len >= sizeof(ev->header_action))
		return -1;
	memcpy(ev->header_action, buf, act_len);
	ev->header_action[act_len] = '\0';

	size_t path_len = first_len - act_len - 1;
	if (path_len >= sizeof(ev->header_devpath))
		return -1;
	memcpy(ev->header_devpath, at + 1, path_len);
	ev->header_devpath[path_len] = '\0';

	// Subsequent segments: KEY=VALUE\0
	size_t offset = first_len + 1;
	bool seen_action = false;
	bool seen_devpath = false;
	bool seen_subsystem = false;
	bool seen_seqnum = false;

	while (offset < len) {
		const char *token = buf + offset;
		size_t token_len = strlen(token);
		if (offset + token_len >= len)
			return -1;

		const char *eq = strchr(token, '=');
		if (!eq || eq == token)
			return -1;

		size_t klen = eq - token;
		const char *val = eq + 1;

		if (klen == 6 && strncmp(token, "ACTION", 6) == 0) {
			if (seen_action)
				return -1; // duplicate base field rejected
			seen_action = true;
			snprintf(ev->action, sizeof(ev->action), "%s", val);
		} else if (klen == 7 && strncmp(token, "DEVPATH", 7) == 0) {
			if (seen_devpath)
				return -1; // duplicate base field rejected
			seen_devpath = true;
			snprintf(ev->devpath, sizeof(ev->devpath), "%s", val);
		} else if (klen == 9 && strncmp(token, "SUBSYSTEM", 9) == 0) {
			if (seen_subsystem)
				return -1; // duplicate base field rejected
			seen_subsystem = true;
			snprintf(ev->subsystem, sizeof(ev->subsystem), "%s",
				 val);
		} else if (klen == 6 && strncmp(token, "SEQNUM", 6) == 0) {
			if (seen_seqnum)
				return -1; // duplicate base field rejected
			seen_seqnum = true;
			ev->seqnum = strtoull(val, NULL, 10);
			ev->has_seqnum = true;
		} else {
			if (ev->num_fields < MAX_FIELDS) {
				snprintf(ev->fields[ev->num_fields].key,
					 sizeof(ev->fields[ev->num_fields].key),
					 "%.*s", (int)klen, token);
				snprintf(ev->fields[ev->num_fields].val,
					 sizeof(ev->fields[ev->num_fields].val),
					 "%s", val);
				ev->num_fields++;
			}
		}

		offset += token_len + 1;
	}

	if (!seen_action || !seen_devpath || !seen_subsystem || !seen_seqnum)
		return -1;

	// Wire header action and devpath must match the fields
	if (strcmp(ev->header_action, ev->action) != 0)
		return -1;
	if (strcmp(ev->header_devpath, ev->devpath) != 0)
		return -1;

	return 0;
}

static bool matches_target(const struct parsed_uevent *ev,
			   const struct target_filter *tf)
{
	if (tf->action && strcmp(ev->action, tf->action) != 0)
		return false;
	if (tf->devpath && strcmp(ev->devpath, tf->devpath) != 0)
		return false;
	if (tf->synth_uuid) {
		bool found = false;
		for (size_t i = 0; i < ev->num_fields; i++) {
			if (strcmp(ev->fields[i].key, "SYNTH_UUID") == 0 &&
			    strcmp(ev->fields[i].val, tf->synth_uuid) == 0) {
				found = true;
				break;
			}
		}
		if (!found)
			return false;
	}
	return true;
}

static int recv_target_uevent(int fd, const struct target_filter *tf,
			      struct parsed_uevent *out, int timeout_ms)
{
	struct timespec now, deadline;
	clock_gettime(CLOCK_MONOTONIC, &now);
	deadline.tv_sec = now.tv_sec + (timeout_ms / 1000);
	deadline.tv_nsec = now.tv_nsec + ((timeout_ms % 1000) * 1000000L);
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec += 1;
		deadline.tv_nsec -= 1000000000L;
	}

	char buf[RECV_BUF_SIZE];
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		long rem_sec = deadline.tv_sec - now.tv_sec;
		long rem_nsec = deadline.tv_nsec - now.tv_nsec;
		long rem_ms = rem_sec * 1000L + rem_nsec / 1000000L;
		if (rem_ms <= 0)
			return RECV_TIMEOUT;

		int ret = poll(&pfd, 1, (int)rem_ms);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return RECV_ERROR;
		}
		if (ret == 0)
			return RECV_TIMEOUT;

		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			return RECV_ERROR;

		if (pfd.revents & POLLIN) {
			ssize_t n = recv(fd, buf, sizeof(buf), 0);
			if (n < 0) {
				if (errno == EINTR || errno == EAGAIN)
					continue;
				return RECV_ERROR;
			}

			struct parsed_uevent ev;
			if (parse_uevent_message(buf, (size_t)n, &ev) == 0) {
				if (matches_target(&ev, tf)) {
					if (out)
						*out = ev;
					return RECV_FOUND;
				}
			}
			// Unrelated event drained; continue until deadline.
		}
	}

	return RECV_TIMEOUT;
}

static int assert_no_target_uevent(int fd, const struct target_filter *tf,
				   int timeout_ms)
{
	struct parsed_uevent ev;
	int ret = recv_target_uevent(fd, tf, &ev, timeout_ms);
	if (ret == RECV_ERROR)
		return -1;
	return ret == RECV_TIMEOUT ? 0 : -1;
}

static int read_uevent_seqnum(uint64_t *seq)
{
	int fd = open("/sys/kernel/uevent_seqnum", O_RDONLY);
	if (fd < 0)
		return -1;
	char buf[64];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	if (buf[n - 1] != '\n')
		return -1;
	*seq = strtoull(buf, NULL, 10);
	return 0;
}

static int write_dev_uevent(const char *devpath, const void *data, size_t len)
{
	char path[256];
	snprintf(path, sizeof(path), "/sys%s/uevent", devpath);
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	ssize_t n = write(fd, data, len);
	int saved_errno = errno;
	close(fd);
	if (n < 0) {
		errno = saved_errno;
		return -1;
	}
	return (int)n;
}

FN_TEST(show_device_uevent)
{
	const char *devs[] = { "/devices/virtual/mem/null",
			       "/devices/virtual/mem/zero",
			       "/devices/virtual/mem/full",
			       "/devices/virtual/mem/random",
			       "/devices/virtual/mem/urandom" };

	for (size_t i = 0; i < sizeof(devs) / sizeof(devs[0]); i++) {
		char path[256];
		snprintf(path, sizeof(path), "/sys%s/uevent", devs[i]);
		int fd = open(path, O_RDONLY);
		CHECK_WITH(fd, fd >= 0);

		char buf[1024];
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		CHECK_WITH(n, n > 0);
		buf[n] = '\0';

		// Must contain MAJOR=, MINOR=, DEVNAME=
		TEST_RES(strstr(buf, "MAJOR=") != NULL, _ret);
		TEST_RES(strstr(buf, "MINOR=") != NULL, _ret);
		TEST_RES(strstr(buf, "DEVNAME=") != NULL, _ret);

		// Must NOT contain header fields, SEQNUM, or SYNTH_UUID
		TEST_RES(strstr(buf, "ACTION=") == NULL, _ret);
		TEST_RES(strstr(buf, "DEVPATH=") == NULL, _ret);
		TEST_RES(strstr(buf, "SUBSYSTEM=") == NULL, _ret);
		TEST_RES(strstr(buf, "SEQNUM=") == NULL, _ret);
		TEST_RES(strstr(buf, "SYNTH_UUID=") == NULL, _ret);

		// Check corresponding /dev node stat
		const char *devname = strrchr(devs[i], '/') + 1;
		char nodepath[64];
		snprintf(nodepath, sizeof(nodepath), "/dev/%s", devname);
		struct stat st;
		if (stat(nodepath, &st) == 0) {
			char expected_major[32];
			snprintf(expected_major, sizeof(expected_major),
				 "MAJOR=%u", major(st.st_rdev));
			TEST_RES(strstr(buf, expected_major) != NULL, _ret);
		}
	}
}
END_TEST()

FN_TEST(synthetic_actions)
{
	int fd = open_uevent_socket(1);
	CHECK_WITH(fd, fd >= 0);

	const char *actions[] = { "add",    "remove",  "change", "move",
				  "online", "offline", "bind",	 "unbind" };

	for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) {
		char uuid[64];
		snprintf(uuid, sizeof(uuid), "11111111-2222-3333-4444-%012zu",
			 i);
		char cmd[256];
		int cmd_len =
			snprintf(cmd, sizeof(cmd), "%s %s\n", actions[i], uuid);

		int w = write_dev_uevent("/devices/virtual/mem/null", cmd,
					 (size_t)cmd_len);
		CHECK_WITH(w, w == cmd_len);

		struct target_filter tf = {
			.action = actions[i],
			.devpath = "/devices/virtual/mem/null",
			.synth_uuid = uuid,
		};
		struct parsed_uevent ev = { 0 };
		int r = recv_target_uevent(fd, &tf, &ev, 1000);
		TEST_RES(r, _ret == 0);
		TEST_RES(strcmp(ev.action, actions[i]), _ret == 0);
		TEST_RES(strcmp(ev.devpath, "/devices/virtual/mem/null"),
			 _ret == 0);
		TEST_RES(strcmp(ev.subsystem, "mem"), _ret == 0);
		TEST_RES(ev.has_seqnum, _ret);
	}

	// Verify /dev/null still functions normally (synthetic actions don't alter state)
	int null_fd = open("/dev/null", O_RDWR);
	CHECK_WITH(null_fd, null_fd >= 0);
	char c = 'x';
	TEST_RES(write(null_fd, &c, 1), _ret == 1);
	close(null_fd);

	close(fd);
}
END_TEST()

FN_TEST(synthetic_uuids_and_ordered_args)
{
	int fd = open_uevent_socket(1);
	CHECK_WITH(fd, fd >= 0);

	// Case 1: Uppercase & lowercase mixed UUID + ordered duplicate args
	const char *uuid = "12345678-ABCD-1234-abcd-123456789ABC";
	char cmd[256];
	int cmd_len = snprintf(cmd, sizeof(cmd),
			       "change %s FOO=1 BAR=2 FOO=3\n", uuid);
	int w = write_dev_uevent("/devices/virtual/mem/zero", cmd,
				 (size_t)cmd_len);
	CHECK_WITH(w, w == cmd_len);

	struct target_filter tf = {
		.action = "change",
		.devpath = "/devices/virtual/mem/zero",
		.synth_uuid = uuid,
	};
	struct parsed_uevent ev = { 0 };
	int r = recv_target_uevent(fd, &tf, &ev, 1000);
	TEST_RES(r, _ret == 0);

	// Verify SYNTH_UUID preserved case exactly
	bool found_uuid = false;
	int foo_order = 0;
	bool bar_seen = false;
	for (size_t i = 0; i < ev.num_fields; i++) {
		if (strcmp(ev.fields[i].key, "SYNTH_UUID") == 0) {
			if (strcmp(ev.fields[i].val, uuid) == 0)
				found_uuid = true;
		} else if (strcmp(ev.fields[i].key, "SYNTH_ARG_FOO") == 0) {
			if (foo_order == 0 &&
			    strcmp(ev.fields[i].val, "1") == 0)
				foo_order = 1;
			else if (foo_order == 1 && bar_seen &&
				 strcmp(ev.fields[i].val, "3") == 0)
				foo_order = 2;
		} else if (strcmp(ev.fields[i].key, "SYNTH_ARG_BAR") == 0) {
			if (foo_order == 1 &&
			    strcmp(ev.fields[i].val, "2") == 0)
				bar_seen = true;
		}
	}
	TEST_RES(found_uuid, _ret);
	TEST_RES(foo_order, _ret == 2);

	// Case 2: No UUID -> SYNTH_UUID=0
	const char *uuid_zero = "0";
	const char *bare_cmd = "change\n";
	w = write_dev_uevent("/devices/virtual/mem/zero", bare_cmd,
			     strlen(bare_cmd));
	CHECK_WITH(w, w == (int)strlen(bare_cmd));

	struct target_filter tf_zero = {
		.action = "change",
		.devpath = "/devices/virtual/mem/zero",
		.synth_uuid = uuid_zero,
	};
	r = recv_target_uevent(fd, &tf_zero, &ev, 1000);
	TEST_RES(r, _ret == 0);

	close(fd);
}
END_TEST()

FN_TEST(malformed_synthetic_inputs)
{
	int fd = open_uevent_socket(1);
	CHECK_WITH(fd, fd >= 0);

	uint64_t seq_before = 0;
	CHECK(read_uevent_seqnum(&seq_before));

// Test array of bad inputs: all lengths use sizeof(literal) - 1
#define BAD_ENTRY(lit)               \
	{                            \
		lit, sizeof(lit) - 1 \
	}
	struct {
		const char *data;
		size_t len;
	} bad_inputs[] = {
		BAD_ENTRY(""), // empty
		BAD_ENTRY("ADD\n"), // uppercase action
		BAD_ENTRY("invalid\n"), // unknown action
		BAD_ENTRY("add\r\n"), // CRLF rejected
		BAD_ENTRY("add\n\n"), // double LF rejected
		BAD_ENTRY("add\n\0"), // LF + NUL rejected
		BAD_ENTRY("add\0\0"), // double NUL rejected
		BAD_ENTRY("ad\0d\n"), // embedded NUL rejected
		BAD_ENTRY(" add\n"), // leading whitespace
		BAD_ENTRY("\tadd\n"), // tab
		BAD_ENTRY(
			"add  12345678-1234-1234-1234-123456789abc\n"), // double space
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789ab\n"), // UUID 35 bytes
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789abcd\n"), // UUID 37 bytes
		BAD_ENTRY(
			"add 1234567-81234-1234-1234-123456789abc\n"), // wrong dash pos
		BAD_ENTRY(
			"add 12345678_1234-1234-1234-123456789abc\n"), // underscore in UUID
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789abc \n"), // trailing space after UUID
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789abc A=1  B=2\n"), // double space
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789abc A=1 \n"), // trailing space
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789abc =1\n"), // empty key
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789abc A=\n"), // empty val
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789abc A=1=2\n"), // multiple equals
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789abc A_B=1\n"), // underscore key
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789abc A=1_2\n"), // underscore val
		BAD_ENTRY(
			"add 12345678-1234-1234-1234-123456789abc \xe4\xb8\xad=1\n"), // non-ASCII
	};
#undef BAD_ENTRY

	for (size_t i = 0; i < sizeof(bad_inputs) / sizeof(bad_inputs[0]);
	     i++) {
		int ret = write_dev_uevent("/devices/virtual/mem/null",
					   bad_inputs[i].data,
					   bad_inputs[i].len);
		int saved_errno = errno;
		TEST_RES(ret, _ret == -1);
		TEST_RES(saved_errno, _ret == EINVAL);
	}

	// Negative assertion: no events were broadcast
	struct target_filter tf = {
		.devpath = "/devices/virtual/mem/null",
	};
	TEST_RES(assert_no_target_uevent(fd, &tf, 100), _ret == 0);

	uint64_t seq_after = 0;
	CHECK(read_uevent_seqnum(&seq_after));
	TEST_RES(seq_after, _ret == seq_before);

	close(fd);
}
END_TEST()

FN_TEST(buffer_overflow_budgets)
{
	int fd = open_uevent_socket(1);
	CHECK_WITH(fd, fd >= 0);

	const char *uuid = "12345678-1234-1234-1234-123456789abc";

	// 1. Temporary budget overflow: 64 args + 1 SYNTH_UUID = 65 items (> 64 MAX_UEVENT_VARS).
	// Must fail with EINVAL during synthetic parsing.
	char line_65[2048];
	int offset = snprintf(line_65, sizeof(line_65), "change %s", uuid);
	for (int i = 0; i < 64; i++) {
		offset += snprintf(line_65 + offset, sizeof(line_65) - offset,
				   " K%02d=1", i);
	}
	offset += snprintf(line_65 + offset, sizeof(line_65) - offset, "\n");

	int ret = write_dev_uevent("/devices/virtual/mem/null", line_65,
				   (size_t)offset);
	int saved_errno = errno;
	TEST_RES(ret, _ret == -1);
	TEST_RES(saved_errno, _ret == EINVAL);

	// 2. Final environment budget overflow:
	// 61 args + 1 SYNTH_UUID = 62 vars.
	// 62 vars <= 64, so temporary synthetic parsing succeeds!
	// But final environment has 3 base fields + 62 vars + 1 SEQNUM = 66 items > 64!
	// Must fail with ENOMEM!
	char line_62[2048];
	offset = snprintf(line_62, sizeof(line_62), "change %s", uuid);
	for (int i = 0; i < 61; i++) {
		offset += snprintf(line_62 + offset, sizeof(line_62) - offset,
				   " K%02d=1", i);
	}
	offset += snprintf(line_62 + offset, sizeof(line_62) - offset, "\n");

	ret = write_dev_uevent("/devices/virtual/mem/null", line_62,
			       (size_t)offset);
	saved_errno = errno;
	TEST_RES(ret, _ret == -1);
	TEST_RES(saved_errno, _ret == ENOMEM);

	// Verify no events were broadcast
	struct target_filter tf = {
		.devpath = "/devices/virtual/mem/null",
	};
	TEST_RES(assert_no_target_uevent(fd, &tf, 100), _ret == 0);

	close(fd);
}
END_TEST()

FN_TEST(multicast_groups)
{
	// Socket 1: joined group 1
	int fd1 = open_uevent_socket(1);
	CHECK_WITH(fd1, fd1 >= 0);

	// Socket 2: also joined group 1
	int fd2 = open_uevent_socket(1);
	CHECK_WITH(fd2, fd2 >= 0);

	// Socket 3: joined group 0 (mask 0)
	int fd0 = open_uevent_socket(0);
	CHECK_WITH(fd0, fd0 >= 0);

	// Socket 4: joined group 2 (mask 2)
	int fd_other = open_uevent_socket(2);
	CHECK_WITH(fd_other, fd_other >= 0);

	const char *uuid = "88888888-4444-4444-4444-123456789abc";
	char cmd[128];
	int cmd_len = snprintf(cmd, sizeof(cmd), "change %s\n", uuid);
	int w = write_dev_uevent("/devices/virtual/mem/null", cmd,
				 (size_t)cmd_len);
	CHECK_WITH(w, w == cmd_len);

	struct target_filter tf = {
		.synth_uuid = uuid,
	};

	struct parsed_uevent ev1 = { 0 }, ev2 = { 0 };
	int r1 = recv_target_uevent(fd1, &tf, &ev1, 1000);
	int r2 = recv_target_uevent(fd2, &tf, &ev2, 1000);
	TEST_RES(r1, _ret == 0);
	TEST_RES(r2, _ret == 0);

	// Both subscribers in group 1 received the exact same seqnum
	TEST_RES(ev1.seqnum, _ret == ev2.seqnum);

	// Subscribers in group 0 or group 2 must NOT receive the event
	TEST_RES(assert_no_target_uevent(fd0, &tf, 100), _ret == 0);
	TEST_RES(assert_no_target_uevent(fd_other, &tf, 100), _ret == 0);

	close(fd1);
	close(fd2);
	close(fd0);
	close(fd_other);
}
END_TEST()

FN_TEST(uevent_seqnum_sysfs)
{
	int fd = open_uevent_socket(1);
	CHECK_WITH(fd, fd >= 0);

	uint64_t seq1 = 0, seq2 = 0;
	CHECK(read_uevent_seqnum(&seq1));
	CHECK(read_uevent_seqnum(&seq2));
	// Reading does not increment sequence
	TEST_RES(seq1, _ret == seq2);

	// Writing /sys/kernel/uevent_seqnum must be rejected. The rejection may
	// happen while opening the read-only attribute or when writing to it.
	int kfd = open("/sys/kernel/uevent_seqnum", O_WRONLY);
	ssize_t write_ret = -1;
	int saved_errno = errno;
	if (kfd >= 0) {
		write_ret = write(kfd, "1", 1);
		saved_errno = errno;
		close(kfd);
	}
	TEST_RES(write_ret, _ret == -1);
	TEST_RES(saved_errno, _ret == EACCES || _ret == EPERM || _ret == EIO);

	// Trigger a single serial synthetic event
	const char *uuid = "99999999-5555-5555-5555-123456789abc";
	char cmd[128];
	int cmd_len = snprintf(cmd, sizeof(cmd), "change %s\n", uuid);
	int w = write_dev_uevent("/devices/virtual/mem/null", cmd,
				 (size_t)cmd_len);
	CHECK_WITH(w, w == cmd_len);

	struct target_filter tf = {
		.synth_uuid = uuid,
	};
	struct parsed_uevent ev = { 0 };
	int r = recv_target_uevent(fd, &tf, &ev, 1000);
	TEST_RES(r, _ret == 0);

	uint64_t seq_after = 0;
	CHECK(read_uevent_seqnum(&seq_after));
	// In serial controlled environment, uevent_seqnum equals the event's seqnum
	TEST_RES(seq_after, _ret == ev.seqnum);

	close(fd);
}
END_TEST()

FN_TEST(coldplug_discovery)
{
	int fd = open_uevent_socket(1);
	CHECK_WITH(fd, fd >= 0);

	const char *devices[] = { "/devices/virtual/mem/null",
				  "/devices/virtual/mem/zero",
				  "/devices/virtual/mem/full",
				  "/devices/virtual/mem/random",
				  "/devices/virtual/mem/urandom" };
	size_t num_devices = sizeof(devices) / sizeof(devices[0]);

	// Write "add\n" to each device to trigger coldplug
	for (size_t i = 0; i < num_devices; i++) {
		int w = write_dev_uevent(devices[i], "add\n", 4);
		CHECK_WITH(w, w == 4);
	}

	// Collect the five target events under one absolute deadline.
	bool found[5] = { false };
	size_t found_count = 0;
	struct timespec deadline;
	struct parsed_uevent ev = { 0 };
	CHECK(clock_gettime(CLOCK_MONOTONIC, &deadline));
	deadline.tv_sec += 1;
	while (found_count < num_devices) {
		struct timespec now;
		CHECK(clock_gettime(CLOCK_MONOTONIC, &now));
		long rem_sec = deadline.tv_sec - now.tv_sec;
		long rem_nsec = deadline.tv_nsec - now.tv_nsec;
		long rem_ms = rem_sec * 1000L + rem_nsec / 1000000L;
		int r = rem_ms > 0 ? recv_target_uevent(fd,
							&(struct target_filter){
								.action = "add",
							},
							&ev, (int)rem_ms) :
				     RECV_TIMEOUT;
		TEST_RES(r, _ret == 0);
		if (r != 0)
			break;
		for (size_t i = 0; i < num_devices; i++) {
			if (!found[i] && strcmp(ev.devpath, devices[i]) == 0) {
				found[i] = true;
				found_count++;
				break;
			}
		}
	}

	for (size_t i = 0; i < num_devices; i++) {
		TEST_RES(found[i], _ret);
	}

	close(fd);
}
END_TEST()

struct writer_arg {
	char uuid[64];
};

static void *concurrent_writer(void *arg)
{
	struct writer_arg *warg = (struct writer_arg *)arg;
	char cmd[256];
	int cmd_len = snprintf(cmd, sizeof(cmd), "change %s\n", warg->uuid);
	write_dev_uevent("/devices/virtual/mem/null", cmd, (size_t)cmd_len);
	return NULL;
}

FN_TEST(concurrent_synthetic_writers)
{
	int fd = open_uevent_socket(1);
	CHECK_WITH(fd, fd >= 0);

#define NUM_WRITERS 8
	pthread_t threads[NUM_WRITERS];
	struct writer_arg args[NUM_WRITERS];

	for (int i = 0; i < NUM_WRITERS; i++) {
		snprintf(args[i].uuid, sizeof(args[i].uuid),
			 "77777777-6666-5555-4444-%012d", i);
	}

	for (int i = 0; i < NUM_WRITERS; i++) {
		CHECK_WITH(pthread_create(&threads[i], NULL, concurrent_writer,
					  &args[i]),
			   _ret == 0);
	}

	for (int i = 0; i < NUM_WRITERS; i++) {
		CHECK_WITH(pthread_join(threads[i], NULL), _ret == 0);
	}

	// Collect events and verify unique UUIDs and unique seqnums
	uint64_t seqs[NUM_WRITERS];
	bool found_uuid[NUM_WRITERS] = { false };

	for (int i = 0; i < NUM_WRITERS; i++) {
		struct target_filter tf = {
			.action = "change",
			.devpath = "/devices/virtual/mem/null",
		};
		struct parsed_uevent ev = { 0 };
		int r = recv_target_uevent(fd, &tf, &ev, 1000);
		TEST_RES(r, _ret == 0);
		seqs[i] = ev.seqnum;

		for (size_t j = 0; j < ev.num_fields; j++) {
			if (strcmp(ev.fields[j].key, "SYNTH_UUID") == 0) {
				for (int k = 0; k < NUM_WRITERS; k++) {
					if (strcmp(ev.fields[j].val,
						   args[k].uuid) == 0) {
						found_uuid[k] = true;
					}
				}
			}
		}
	}

	for (int i = 0; i < NUM_WRITERS; i++) {
		TEST_RES(found_uuid[i], _ret);
	}

	// Verify all seqnums are unique
	for (int i = 0; i < NUM_WRITERS; i++) {
		for (int j = i + 1; j < NUM_WRITERS; j++) {
			TEST_RES(seqs[i] != seqs[j], _ret);
		}
	}

	close(fd);
#undef NUM_WRITERS
}
END_TEST()

FN_TEST(queue_pressure_and_recovery)
{
	// 1. Write without any listeners -> must succeed without error
	for (int i = 0; i < 20; i++) {
		int w = write_dev_uevent("/devices/virtual/mem/null",
					 "change\n", 7);
		CHECK_WITH(w, w == 7);
	}

	// 2. Open a listener now
	int fd = open_uevent_socket(1);
	CHECK_WITH(fd, fd >= 0);

	// 3. Write a new event with target UUID
	const char *target_uuid = "44444444-3333-2222-1111-123456789abc";
	char cmd[128];
	int cmd_len = snprintf(cmd, sizeof(cmd), "change %s\n", target_uuid);
	int w = write_dev_uevent("/devices/virtual/mem/null", cmd,
				 (size_t)cmd_len);
	CHECK_WITH(w, w == cmd_len);

	struct target_filter tf = {
		.synth_uuid = target_uuid,
	};
	struct parsed_uevent ev = { 0 };
	int r = recv_target_uevent(fd, &tf, &ev, 1000);
	TEST_RES(r, _ret == 0);

	close(fd);
}
END_TEST()
