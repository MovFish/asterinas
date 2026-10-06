#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

# Requires a running daemon; never owns or removes its runtime/database.
set -eu
UDEVADM=${UDEVADM:-udevadm}
TEST_DIR=$(mktemp -d /run/asterinas-udev-processed-test.XXXXXX)
MONITOR_PID=

finish()
{
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ -n "$MONITOR_PID" ]; then
        kill -TERM "$MONITOR_PID" 2>/dev/null
        wait "$MONITOR_PID"
    fi
    if [ "$status" -ne 0 ]; then
        for diagnostic in "$TEST_DIR"/*; do
            [ -f "$diagnostic" ] || continue
            echo "--- $diagnostic ---" >&2
            cat "$diagnostic" >&2
        done
    fi
    rm -rf "$TEST_DIR" || status=1
    if [ "$status" -eq 0 ]; then
        echo "All five mem processed-event tests passed."
    fi
    exit "$status"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

command -v stdbuf >/dev/null
timeout 15 "$UDEVADM" control --ping --timeout=10
# Match records by UUID below; do not require optional socket BPF filtering.
"$UDEVADM" monitor --udev --property >"$TEST_DIR/monitor" 2>&1 &
MONITOR_PID=$!
remaining=5
while ! grep -F -q 'UDEV - the event which udev sends out after rule processing' "$TEST_DIR/monitor"; do
    if ! kill -0 "$MONITOR_PID" 2>/dev/null || [ "$remaining" -eq 0 ]; then
        echo "processed monitor did not become ready" >&2
        break
    fi
    sleep 1
    remaining=$((remaining - 1))
done

# Exercise every device even when an earlier processed-event round trip fails.
failed=0
for device in null:3 zero:5 full:7 random:8 urandom:9; do
    name=${device%:*}
    minor=${device#*:}
    # Preserve the UUID even if the processed-event wait is killed by timeout.
    if timeout 5 stdbuf -oL "$UDEVADM" trigger --uuid --settle --type=devices \
        --action=change --subsystem-match=mem --sysname-match="$name" \
        "/sys/devices/virtual/mem/$name" >"$TEST_DIR/uuid-$name" 2>&1; then
        trigger_status=0
    else
        trigger_status=$?
    fi
    if [ "$trigger_status" -ne 0 ]; then
        echo "processed trigger: $name exit=$trigger_status" >&2
        failed=1
    fi
    if ! uuid=$(awk -v status="$trigger_status" '
        NR == 1 { uuid = $0 }
        NR == 2 { if ($0 != "settle " uuid) bad = 1 }
        END {
            if (status == 0 ? NR != 2 || bad : NR != 1) exit 1
            print uuid
        }
    ' "$TEST_DIR/uuid-$name") ||
        ! printf '%s\n' "$uuid" | grep -E -x -q \
            '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'; then
        echo "processed trigger: $name has no valid UUID" >&2
        failed=1
        continue
    fi
    # Queue completion alone cannot satisfy this assertion: require the same
    # UUID in one complete, authenticated libudev group-2 record.
    record_status=1
    remaining=3
    while [ "$remaining" -gt 0 ]; do
        if awk -v uuid="$uuid" -v name="$name" -v minor="$minor" '
            BEGIN { RS = ""; FS = "\n" }
            {
                delete fields; delete counts
                for (i = 1; i <= NF; i++) {
                    equals = index($i, "=")
                    if (!equals) continue
                    key = substr($i, 1, equals - 1)
                    fields[key] = substr($i, equals + 1)
                    counts[key]++
                }
                if (fields["SYNTH_UUID"] != uuid) next
                matches++
                header_line = $1
                # udevadm pads UDEV to six columns, unlike KERNEL.
                sub(/^UDEV[[:space:]]+\[/, "UDEV[", header_line)
                split(header_line, header, /[[:space:]]+/)
                if (header[1] !~ /^UDEV\[[0-9]+\.[0-9]+\]$/ ||
                    header[2] != "change" ||
                    header[3] != "/devices/virtual/mem/" name || header[4] != "(mem)") bad = 1
                required[1] = "ACTION"; required[2] = "DEVPATH"
                required[3] = "SUBSYSTEM"; required[4] = "MAJOR"
                required[5] = "MINOR"; required[6] = "DEVNAME"
                required[7] = "SYNTH_UUID"; required[8] = "SEQNUM"
                for (i = 1; i <= 8; i++) if (counts[required[i]] != 1) bad = 1
                if (fields["ACTION"] != "change" ||
                    fields["DEVPATH"] != "/devices/virtual/mem/" name ||
                    fields["SUBSYSTEM"] != "mem" || fields["MAJOR"] != "1" ||
                    fields["MINOR"] != minor || fields["DEVNAME"] != "/dev/" name ||
                    fields["SEQNUM"] !~ /^[0-9]+$/) bad = 1
            }
            END { exit(matches == 1 && !bad ? 0 : 1) }
        ' "$TEST_DIR/monitor"; then
            record_status=0
            break
        fi
        sleep 1
        remaining=$((remaining - 1))
    done
    if [ "$record_status" -ne 0 ]; then
        echo "processed record: $name missing, duplicate or invalid (uuid=$uuid)" >&2
        failed=1
    else
        echo "processed record: $name uuid=$uuid"
    fi
done
[ "$failed" -eq 0 ]
