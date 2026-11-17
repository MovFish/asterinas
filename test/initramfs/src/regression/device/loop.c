// SPDX-License-Identifier: MPL-2.0

/* Exercise loop device I/O, status ABI, sysfs attributes, and loop-control. */
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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
	TEST_RES(read_loop_attr(loop_number, "ro"), _ret == 0);
	TEST_RES(read_loop_attr(loop_number, "removable"), _ret == 0);

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
	CHECK(ioctl(loop_fd, LOOP_SET_FD, backing_fd));
	attached = true;
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
}
END_TEST()

FN_TEST(detach_readonly_and_control_add_remove)
{
	CHECK(ioctl(loop_fd, LOOP_CLR_FD, 0));
	attached = false;
	TEST_RES(read_loop_attr(loop_number, "size"), _ret == 0);
	TEST_RES(read_loop_attr(loop_number, "ro"), _ret == 0);

	CHECK(ioctl(loop_fd, LOOP_SET_FD, readonly_fd));
	attached = true;
	TEST_RES(read_loop_attr(loop_number, "ro"), _ret == 1);
	struct loop_info64 status = { 0 };
	TEST_RES(ioctl(loop_fd, LOOP_GET_STATUS64, &status),
		 (status.lo_flags & LO_FLAGS_READ_ONLY) != 0);
	char byte = 0;
	TEST_RES(pread(loop_fd, &byte, 1, DATA_OFFSET),
		 _ret == 1 && (unsigned char)byte == 0x5a);
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
	TEST_RES(stat(dev_path, &metadata),
		 S_ISBLK(metadata.st_mode) &&
			 metadata.st_rdev == makedev(7, candidate));
	TEST_RES(read_loop_attr(candidate, "size"), _ret == 0);

	TEST_SUCC(ioctl(control_fd, LOOP_CTL_REMOVE, candidate));
	extra_number = -1;
	TEST_ERRNO(stat(dev_path, &metadata), ENOENT);
	TEST_ERRNO(stat(sys_class, &metadata), ENOENT);
}
END_TEST()

FN_SETUP(cleanup)
{
	release_resources();
}
END_SETUP()
