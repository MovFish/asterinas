#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

# Run in an isolated guest without udev/coldplug writers: sequence checks are exact.
cd "$(dirname "$0")"
exec ./uevent
