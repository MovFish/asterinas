// SPDX-License-Identifier: MPL-2.0

/* Exercise basic Linux loop device I/O, status ABI, loop-control,
 * LOOP_CONFIGURE, capacity updates, and change uevents. */
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/netlink.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <unistd.h>

#include "../common/test.h"

#define BACKING_SIZE 8192
#define SECTOR_SIZE 512
#define DATA_OFFSET 1024
#define DATA_SIZE 2048

static int control_fd = -1, loop_fd = -1, backing_fd = -1, readonly_fd = -1;
static int loop_number, extra_number = -1;
static bool attached;
static char device_path[64];

static void release_resources(void)
{
	if (attached) {
		ioctl(loop_fd, LOOP_CLR_FD, 0);
		attached = false;
	}
	if (extra_number >= 0 && control_fd >= 0) {
		ioctl(control_fd, LOOP_CTL_REMOVE, extra_number);
		extra_number = -1;
	}
	if (loop_fd >= 0) {
		close(loop_fd);
		loop_fd = -1;
	}
	if (readonly_fd >= 0) {
		close(readonly_fd);
		readonly_fd = -1;
	}
	if (backing_fd >= 0) {
		close(backing_fd);
		backing_fd = -1;
	}
	if (control_fd >= 0) {
		close(control_fd);
		control_fd = -1;
	}
}

static long long read_loop_attr(int number, const char *attr)
{
	char path[128], buffer[32];
	snprintf(path, sizeof(path), "/sys/class/block/loop%d/%s", number,
		 attr);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
	int saved_errno = errno;
	close(fd);
	if (n <= 0) {
		errno = n < 0 ? saved_errno : EIO;
		return -1;
	}
	buffer[n] = '\0';
	errno = 0;
	return strtoll(buffer, NULL, 10);
}

static bool uevent_has(const char *buffer, ssize_t len, const char *field)
{
	size_t field_len = strlen(field);
	for (ssize_t i = 0; i + (ssize_t)field_len <= len; i++) {
		if ((i == 0 || buffer[i - 1] == '\0') &&
		    !memcmp(buffer + i, field, field_len) &&
		    (i + (ssize_t)field_len == len ||
		     buffer[i + field_len] == '\0'))
			return true;
	}
	return false;
}

static unsigned long long uevent_seqnum(const char *buffer, ssize_t len)
{
	const char prefix[] = "SEQNUM=";
	const ssize_t prefix_len = sizeof(prefix) - 1;
	for (ssize_t i = 0; i + prefix_len <= len; i++) {
		if ((i == 0 || buffer[i - 1] == '\0') &&
		    !memcmp(buffer + i, prefix, prefix_len))
			return strtoull(buffer + i + prefix_len, NULL, 10);
	}
	return 0;
}

static unsigned long long read_uevent_seqnum(void)
{
	char buffer[32];
	int fd = open("/sys/kernel/uevent_seqnum", O_RDONLY);
	if (fd < 0)
		return 0;
	ssize_t len = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (len <= 0)
		return 0;
	buffer[len] = '\0';
	return strtoull(buffer, NULL, 10);
}

static int open_uevent_socket(void)
{
	int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (fd < 0)
		return -1;
	struct sockaddr_nl address = {
		.nl_family = AF_NETLINK,
		.nl_groups = 1,
	};
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		close(fd);
		return -1;
	}
	struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) <
	    0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int drain_uevents(int fd)
{
	char buffer[4096];
	while (recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT) > 0)
		;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return 0;
	return -1;
}

static int wait_for_change(int fd, const char *devname,
			   unsigned long long min_seqnum)
{
	char expected[64];
	snprintf(expected, sizeof(expected), "DEVNAME=%s", devname);
	char buffer[4096];
	for (;;) {
		ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
		if (len < 0 && errno == EINTR)
			continue;
		if (len <= 0)
			return -1;
		if (uevent_has(buffer, len, "ACTION=change") &&
		    uevent_has(buffer, len, expected) &&
		    uevent_seqnum(buffer, len) > min_seqnum)
			return 0;
	}
}

FN_SETUP(prepare)
{
	CHECK(atexit(release_resources));
	control_fd = CHECK(open("/dev/loop-control", O_RDWR));
	loop_number = CHECK(ioctl(control_fd, LOOP_CTL_GET_FREE));
	CHECK_WITH(snprintf(device_path, sizeof(device_path), "/dev/loop%d",
			    loop_number),
		   _ret > 0 && (size_t)_ret < sizeof(device_path));
	loop_fd = CHECK(open(device_path, O_RDWR));

	char path[] = "/tmp/loop-regression-XXXXXX";
	backing_fd = CHECK(mkstemp(path));
	readonly_fd = open(path, O_RDONLY);
	CHECK(unlink(path));
	CHECK(readonly_fd);
	CHECK(ftruncate(backing_fd, BACKING_SIZE));
}
END_SETUP()

FN_TEST(detached_and_invalid_state)
{
	struct stat metadata;
	TEST_RES(fstat(control_fd, &metadata),
		 S_ISCHR(metadata.st_mode) &&
			 metadata.st_rdev == makedev(10, 237));
	TEST_RES(fstat(loop_fd, &metadata),
		 S_ISBLK(metadata.st_mode) &&
			 metadata.st_rdev == makedev(7, loop_number));
	TEST_RES(read_loop_attr(loop_number, "size"), _ret == 0);

	char sys_block[64];
	CHECK_WITH(snprintf(sys_block, sizeof(sys_block), "/sys/block/loop%d",
			    loop_number),
		   _ret > 0 && (size_t)_ret < sizeof(sys_block));
	TEST_RES(lstat(sys_block, &metadata), S_ISLNK(metadata.st_mode));

	char byte = 0;
	TEST_RES(pread(loop_fd, &byte, sizeof(byte), 0), _ret == 0);
	TEST_ERRNO(pwrite(loop_fd, &byte, sizeof(byte), 0), ENOSPC);

	struct loop_info64 status = { 0 };
	TEST_ERRNO(ioctl(loop_fd, LOOP_GET_STATUS64, &status), ENXIO);
	TEST_ERRNO(ioctl(loop_fd, LOOP_CLR_FD, 0), ENXIO);
	TEST_ERRNO(ioctl(loop_fd, LOOP_SET_FD, -1), EBADF);
	int dir_fd = CHECK(open("/tmp", O_RDONLY | O_DIRECTORY));
	TEST_ERRNO(ioctl(loop_fd, LOOP_SET_FD, dir_fd), EINVAL);
	CHECK(close(dir_fd));
}
END_TEST()

FN_TEST(attach_status_and_windowed_io)
{
	int uevent_fd = CHECK(open_uevent_socket());
	CHECK_WITH(drain_uevents(uevent_fd), _ret == 0);
	unsigned long long seqnum = read_uevent_seqnum();

	CHECK(ioctl(loop_fd, LOOP_SET_FD, backing_fd));
	attached = true;
	char device_name[16];
	CHECK_WITH(snprintf(device_name, sizeof(device_name), "loop%d",
			    loop_number),
		   _ret > 0);
	TEST_RES(wait_for_change(uevent_fd, device_name, seqnum), _ret == 0);
	CHECK(close(uevent_fd));

	TEST_ERRNO(ioctl(loop_fd, LOOP_SET_FD, backing_fd), EBUSY);

	struct loop_info legacy = { .lo_offset = SECTOR_SIZE };
	strcpy(legacy.lo_name, "loop-regression-legacy");
	CHECK(ioctl(loop_fd, LOOP_SET_STATUS, &legacy));
	struct loop_info64 status = { 0 };
	TEST_RES(ioctl(loop_fd, LOOP_GET_STATUS64, &status),
		 status.lo_offset == SECTOR_SIZE &&
			 !strcmp((char *)status.lo_file_name, legacy.lo_name));

	struct loop_info64 window = {
		.lo_offset = DATA_OFFSET,
		.lo_sizelimit = DATA_SIZE,
	};
	strcpy((char *)window.lo_file_name, "loop-regression-window");
	CHECK(ioctl(loop_fd, LOOP_SET_STATUS64, &window));
	TEST_RES(ioctl(loop_fd, LOOP_GET_STATUS, &legacy),
		 legacy.lo_offset == DATA_OFFSET &&
			 !strcmp(legacy.lo_name, (char *)window.lo_file_name));
	unsigned long long capacity = 0;
	TEST_RES(ioctl(loop_fd, BLKGETSIZE64, &capacity),
		 capacity == DATA_SIZE);
	TEST_RES(read_loop_attr(loop_number, "size"),
		 _ret == DATA_SIZE / SECTOR_SIZE);

	char written[SECTOR_SIZE], readback[SECTOR_SIZE];
	memset(written, 0x5a, sizeof(written));
	CHECK_WITH(pwrite(backing_fd, written, sizeof(written), DATA_OFFSET),
		   _ret == sizeof(written));
	TEST_RES(pread(loop_fd, readback, sizeof(readback), 0),
		 _ret == sizeof(readback) &&
			 !memcmp(readback, written, sizeof(readback)));

	memset(written, 0xa5, sizeof(written));
	TEST_RES(pwrite(loop_fd, written, sizeof(written), SECTOR_SIZE),
		 _ret == sizeof(written));
	TEST_RES(pread(backing_fd, readback, sizeof(readback),
		       DATA_OFFSET + SECTOR_SIZE),
		 _ret == sizeof(readback) &&
			 !memcmp(readback, written, sizeof(readback)));
	TEST_RES(pread(loop_fd, readback, sizeof(readback),
		       DATA_SIZE - SECTOR_SIZE / 2),
		 _ret == SECTOR_SIZE / 2);
	TEST_RES(pwrite(loop_fd, written, sizeof(written),
			DATA_SIZE - SECTOR_SIZE / 2),
		 _ret == SECTOR_SIZE / 2);
	TEST_ERRNO(pwrite(loop_fd, written, sizeof(written), DATA_SIZE),
		   ENOSPC);

	memset(readback, 1, sizeof(readback));
	TEST_RES(pread(backing_fd, readback, sizeof(readback),
		       DATA_OFFSET + DATA_SIZE),
		 _ret == sizeof(readback) && readback[0] == 0 &&
			 !memcmp(readback, readback + 1, sizeof(readback) - 1));

#ifdef __asterinas__
	/* Kernel workers carry no user credentials, so loop writes clear set-ID bits. */
	CHECK(fchmod(backing_fd, 04755));
	TEST_RES(pwrite(loop_fd, written, sizeof(written), 0),
		 _ret == sizeof(written));
	struct stat metadata;
	TEST_RES(fstat(backing_fd, &metadata),
		 (metadata.st_mode & S_ISUID) == 0);
	CHECK(fchmod(backing_fd, 0600));
#endif

	CHECK(ioctl(loop_fd, LOOP_CLR_FD, 0));
	attached = false;
	TEST_RES(read_loop_attr(loop_number, "size"), _ret == 0);
}
END_TEST()

FN_TEST(detach_readonly_and_control_add_remove)
{
	char pattern[SECTOR_SIZE];
	memset(pattern, 0x5a, sizeof(pattern));
	CHECK_WITH(pwrite(backing_fd, pattern, sizeof(pattern), DATA_OFFSET),
		   _ret == sizeof(pattern));

	CHECK(ioctl(loop_fd, LOOP_SET_FD, backing_fd));
	attached = true;

	int extra_fd = CHECK(open(device_path, O_RDONLY));
	TEST_ERRNO(ioctl(loop_fd, LOOP_CLR_FD, 0), EBUSY);
	CHECK(close(extra_fd));

	TEST_ERRNO(ioctl(control_fd, LOOP_CTL_REMOVE, loop_number), EBUSY);

	CHECK(ioctl(loop_fd, LOOP_CLR_FD, 0));
	attached = false;
	TEST_RES(read_loop_attr(loop_number, "size"), _ret == 0);

	CHECK(ioctl(loop_fd, LOOP_SET_FD, readonly_fd));
	attached = true;
	struct loop_info64 status = { 0 };
	TEST_RES(ioctl(loop_fd, LOOP_GET_STATUS64, &status),
		 (status.lo_flags & LO_FLAGS_READ_ONLY) != 0);
	char byte = 0;
	TEST_RES(pread(loop_fd, &byte, 1, DATA_OFFSET),
		 _ret == 1 && (unsigned char)byte == 0x5a);
	TEST_RES(pwrite(loop_fd, &byte, 0, 0), _ret == 0);
	TEST_ERRNO(pwrite(loop_fd, &byte, 1, 0), EPERM);
	CHECK(ioctl(loop_fd, LOOP_CLR_FD, 0));
	attached = false;

	char dev_path[64], sys_class[128];
	struct stat metadata;
	int candidate = -1;
	for (int i = 8; i < 256; i++) {
		CHECK_WITH(snprintf(dev_path, sizeof(dev_path), "/dev/loop%d",
				    i),
			   _ret > 0 && (size_t)_ret < sizeof(dev_path));
		if (stat(dev_path, &metadata) < 0 && errno == ENOENT) {
			candidate = i;
			break;
		}
	}
	CHECK_WITH(candidate, _ret >= 8);
	CHECK_WITH(snprintf(sys_class, sizeof(sys_class),
			    "/sys/class/block/loop%d", candidate),
		   _ret > 0 && (size_t)_ret < sizeof(sys_class));

	TEST_RES(ioctl(control_fd, LOOP_CTL_ADD, candidate), _ret == candidate);
	extra_number = candidate;
	TEST_ERRNO(ioctl(control_fd, LOOP_CTL_ADD, candidate), EEXIST);
	TEST_RES(stat(dev_path, &metadata),
		 S_ISBLK(metadata.st_mode) &&
			 metadata.st_rdev == makedev(7, candidate));
	TEST_RES(read_loop_attr(candidate, "size"), _ret == 0);

	TEST_SUCC(ioctl(control_fd, LOOP_CTL_REMOVE, candidate));
	extra_number = -1;
	TEST_ERRNO(ioctl(control_fd, LOOP_CTL_REMOVE, candidate), ENODEV);
	TEST_ERRNO(stat(dev_path, &metadata), ENOENT);
	TEST_ERRNO(stat(sys_class, &metadata), ENOENT);

	int dynamic = CHECK(ioctl(control_fd, LOOP_CTL_ADD, -1));
	extra_number = dynamic;
	TEST_SUCC(ioctl(control_fd, LOOP_CTL_REMOVE, dynamic));
	extra_number = -1;
}
END_TEST()

FN_TEST(configure_and_legacy_encoding)
{
	struct loop_config configure = {
		.fd = backing_fd,
		.info = {
			.lo_offset = DATA_OFFSET,
			.lo_sizelimit = DATA_SIZE,
		},
	};
	strcpy((char *)configure.info.lo_file_name,
	       "loop-regression-configure");

	struct loop_config invalid = configure;
	invalid.__reserved[0] = 1;
	TEST_ERRNO(ioctl(loop_fd, LOOP_CONFIGURE, &invalid), EINVAL);
#ifdef __asterinas__
	invalid = configure;
	invalid.block_size = 1024;
	TEST_ERRNO(ioctl(loop_fd, LOOP_CONFIGURE, &invalid), EINVAL);
	invalid = configure;
	invalid.info.lo_flags = LO_FLAGS_PARTSCAN;
	TEST_ERRNO(ioctl(loop_fd, LOOP_CONFIGURE, &invalid), EINVAL);
#endif

	configure.block_size = SECTOR_SIZE;
	configure.info.lo_flags = LO_FLAGS_READ_ONLY;
	CHECK(ioctl(loop_fd, LOOP_CONFIGURE, &configure));
	attached = true;

	struct loop_info64 status = { 0 };
	TEST_RES(ioctl(loop_fd, LOOP_GET_STATUS64, &status),
		 status.lo_offset == DATA_OFFSET &&
			 status.lo_sizelimit == DATA_SIZE &&
			 (status.lo_flags & LO_FLAGS_READ_ONLY) != 0 &&
			 !strcmp((char *)status.lo_file_name,
				 "loop-regression-configure"));
	TEST_ERRNO(ioctl(loop_fd, LOOP_CONFIGURE, &configure), EBUSY);

	struct stat metadata;
	CHECK(fstat(backing_fd, &metadata));
	unsigned major_number = major(metadata.st_dev);
	unsigned minor_number = minor(metadata.st_dev);
	struct loop_info legacy = { 0 };
	if (major_number <= 0xff && minor_number <= 0xff) {
		TEST_RES(ioctl(loop_fd, LOOP_GET_STATUS, &legacy),
			 legacy.lo_device ==
				 (unsigned long)((major_number << 8) |
						 minor_number));
	} else {
		TEST_ERRNO(ioctl(loop_fd, LOOP_GET_STATUS, &legacy), EOVERFLOW);
	}

	struct loop_info negative = { .lo_offset = -1 };
	TEST_ERRNO(ioctl(loop_fd, LOOP_SET_STATUS, &negative), EOVERFLOW);

	CHECK(ioctl(loop_fd, LOOP_CLR_FD, 0));
	attached = false;
}
END_TEST()

FN_TEST(truncated_backing_and_set_capacity)
{
	CHECK(ioctl(loop_fd, LOOP_SET_FD, backing_fd));
	attached = true;
	struct loop_info64 window = {
		.lo_offset = DATA_OFFSET,
		.lo_sizelimit = DATA_SIZE,
	};
	CHECK(ioctl(loop_fd, LOOP_SET_STATUS64, &window));

	CHECK(ftruncate(backing_fd, DATA_OFFSET + SECTOR_SIZE));

	char buffer[SECTOR_SIZE];
	memset(buffer, 0xff, sizeof(buffer));
	TEST_RES(pread(loop_fd, buffer, sizeof(buffer),
		       DATA_SIZE - SECTOR_SIZE),
		 _ret == sizeof(buffer) && !buffer[0] &&
			 !buffer[sizeof(buffer) - 1]);

	CHECK(ioctl(loop_fd, LOOP_SET_CAPACITY, 0));
	TEST_RES(read_loop_attr(loop_number, "size"), _ret == 1);

	CHECK(ioctl(loop_fd, LOOP_CLR_FD, 0));
	attached = false;
	CHECK(ftruncate(backing_fd, BACKING_SIZE));
}
END_TEST()

FN_SETUP(cleanup)
{
	release_resources();
}
END_SETUP()
