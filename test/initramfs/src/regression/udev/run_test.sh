#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

MODE=standalone
case $# in
    0) ;;
    1) [ "$1" = --managed ] || { echo "usage: $0 [--managed]" >&2; exit 2; }
       MODE=managed ;;
    *) echo "usage: $0 [--managed]" >&2; exit 2 ;;
esac

UDEVADM=${UDEVADM:-udevadm}
UDEVD=${UDEVD:-}
DEVICES="null:3 zero:5 full:7 random:8 urandom:9"
RUNTIME_DIR=/run/udev
RULE_DIR=$RUNTIME_DIR/rules.d
TEST_DIR=
RULE_FILE=
OWNERSHIP_MARKER=$RUNTIME_DIR/.asterinas-udev-mem-test-owned
UDEVD_PID=
MONITOR_PID=
OWNS_RUNTIME_DIR=0
OWNS_RULE_DIR=0
OWNS_RULE_FILE=0
OWNS_LINK_NAMESPACE=0
DATABASE_DIRTY=0
LAST_SEQNUM=0
EVENT_NUMBER=0
PHASE=

fail()
{
    echo "mem udev regression failed: $*" >&2
    return 1
}

select_device()
{
    NAME=${1%:*}
    MINOR=${1#*:}
    DEVICE_PATH=/sys/devices/virtual/mem/$NAME
    DEVICE_DEVPATH=/devices/virtual/mem/$NAME
    DEVLINK=/dev/$LINK_PREFIX-$NAME
    INFO=$TEST_DIR/info-$NAME.log
}

process_is_active()
{
    kill -0 "$1" 2>/dev/null || return 1
    if [ -r "/proc/$1/stat" ]; then
        process_state=$(awk '{ print $3 }' "/proc/$1/stat" 2>/dev/null || true)
        [ "$process_state" != Z ] && [ "$process_state" != X ] || return 1
    fi
}

wait_for_exit()
{
    exit_remaining=5
    while process_is_active "$1"; do
        [ "$exit_remaining" -gt 0 ] || return 1
        sleep 1
        exit_remaining=$((exit_remaining - 1))
    done
}

has_field()
{
    # Check both the value and its uniqueness; fields from separate records
    # must never accidentally satisfy one assertion.
    awk -v key="$2" -v value="$3" '
        index($0, key "=") == 1 {
            count++
            if ($0 != key "=" value) bad = 1
        }
        END { exit(count == 1 && !bad ? 0 : 1) }
    ' "$1"
}

has_devlink()
{
    awk -v link="$2" '
        /^DEVLINKS=/ {
            sub(/^DEVLINKS=/, "")
            for (i = 1; i <= NF; i++) if ($i == link) found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "$1"
}

check_info_identity()
{
    has_field "$1" DEVPATH "$DEVICE_DEVPATH" &&
        has_field "$1" SUBSYSTEM mem &&
        has_field "$1" DEVNAME "/dev/$NAME" &&
        has_field "$1" MAJOR 1 &&
        has_field "$1" MINOR "$MINOR" &&
        has_field "$1" DEVMODE 0666 ||
        fail "udevadm info identity differs for $NAME ($1)"
}

check_device_identity()
{
    [ -d "$DEVICE_PATH" ] || fail "$DEVICE_PATH is missing"
    [ -w "$DEVICE_PATH/uevent" ] || fail "$DEVICE_PATH/uevent is not writable"
    [ -L "/sys/class/mem/$NAME" ] &&
        [ "$(readlink -f "/sys/class/mem/$NAME")" = "$DEVICE_PATH" ] ||
        fail "class index differs for $NAME"
    [ -L "/sys/dev/char/1:$MINOR" ] &&
        [ "$(readlink -f "/sys/dev/char/1:$MINOR")" = "$DEVICE_PATH" ] ||
        fail "character-device index differs for $NAME"
    [ "$(readlink -f "$DEVICE_PATH/subsystem")" = /sys/class/mem ] ||
        fail "subsystem link differs for $NAME"
    [ "$(cat "$DEVICE_PATH/dev")" = "1:$MINOR" ] ||
        fail "dev attribute differs for $NAME"
    cat "$DEVICE_PATH/uevent" >"$TEST_DIR/sysfs-$NAME.log"
    has_field "$TEST_DIR/sysfs-$NAME.log" MAJOR 1 &&
        has_field "$TEST_DIR/sysfs-$NAME.log" MINOR "$MINOR" &&
        has_field "$TEST_DIR/sysfs-$NAME.log" DEVNAME "$NAME" &&
        has_field "$TEST_DIR/sysfs-$NAME.log" DEVMODE 0666 ||
        fail "sysfs uevent fields differ for $NAME"
    [ -c "/dev/$NAME" ] &&
        [ "$(stat -c '%t:%T' "/dev/$NAME")" = "1:$MINOR" ] ||
        fail "/dev/$NAME is not character device 1:$MINOR"
    [ "$("$UDEVADM" info --query=path --name="/dev/$NAME")" = "$DEVICE_DEVPATH" ] ||
        fail "udevadm devnode lookup differs for $NAME"
    "$UDEVADM" info --query=property --path="$DEVICE_PATH" >"$INFO"
    check_info_identity "$INFO"
    "$UDEVADM" info --query=property --name="/dev/$NAME" >"$TEST_DIR/node-$NAME.log"
    check_info_identity "$TEST_DIR/node-$NAME.log"
}

reload_rules()
{
    echo "+ $UDEVADM control --reload --timeout=10"
    timeout 15 "$UDEVADM" control --reload --timeout=10 &&
        timeout 15 "$UDEVADM" control --ping --timeout=10 ||
        fail "daemon did not acknowledge rule reload"
}

write_rules()
{
    PHASE=$1
    NULL_PRIORITY=$2
    OWNS_RULE_FILE=1
    : >"$RULE_FILE"
    for rule_device in $DEVICES; do
        select_device "$rule_device"
        for rule_action in add change; do
            printf 'ACTION=="%s", SUBSYSTEM=="mem", KERNEL=="%s", ATTR{dev}=="1:%s", ENV{%s}="%s-%s-%s", OWNER:="1", GROUP:="1", MODE:="0640", SYMLINK+="%s-%s"\n' \
                "$rule_action" "$NAME" "$MINOR" "$TEST_PROPERTY" \
                "$PHASE" "$NAME" "$rule_action" "$LINK_PREFIX" "$NAME" >>"$RULE_FILE"
        done
    done
    if [ "$NULL_PRIORITY" != none ]; then
        printf 'ACTION=="add|change", SUBSYSTEM=="mem", KERNEL=="null", OPTIONS+="link_priority=%s", SYMLINK+="%s-shared"\n' \
            "$NULL_PRIORITY" "$LINK_PREFIX" >>"$RULE_FILE"
    fi
    printf 'ACTION=="add|change", SUBSYSTEM=="mem", KERNEL=="zero", OPTIONS+="link_priority=20", SYMLINK+="%s-shared"\n' \
        "$LINK_PREFIX" >>"$RULE_FILE"
    cat "$RULE_FILE" >"$TEST_DIR/rules-$PHASE.log"
    DATABASE_DIRTY=1
    reload_rules
}

capture_kernel_record()
{
    # udevadm normalizes DEVNAME to /dev/<name>. Match a complete kernel
    # record by its synthetic UUID, not independent grep hits in the log.
    awk -v uuid="$TRIGGER_UUID" -v action="$TRIGGER_ACTION" \
        -v path="$DEVICE_DEVPATH" -v name="$NAME" -v minor="$MINOR" \
        -v before="$SEQNUM_BEFORE" -v after="$SEQNUM_AFTER" '
        BEGIN { RS = ""; FS = "\n" }
        {
            delete fields
            delete counts
            for (i = 1; i <= NF; i++) {
                equals = index($i, "=")
                if (!equals) continue
                key = substr($i, 1, equals - 1)
                fields[key] = substr($i, equals + 1)
                counts[key]++
            }
            if (fields["SYNTH_UUID"] != uuid) next
            matches++
            split($1, header, /[[:space:]]+/)
            if (header[1] !~ /^KERNEL\[[0-9]+\.[0-9]+\]$/ ||
                header[2] != action || header[3] != path || header[4] != "(mem)")
                bad = 1
            required[1] = "ACTION"; required[2] = "DEVPATH"
            required[3] = "SUBSYSTEM"; required[4] = "MAJOR"
            required[5] = "MINOR"; required[6] = "DEVNAME"
            required[7] = "DEVMODE"; required[8] = "SEQNUM"
            required[9] = "SYNTH_UUID"
            for (i = 1; i <= 9; i++)
                if (counts[required[i]] != 1) bad = 1
            if (fields["ACTION"] != action || fields["DEVPATH"] != path ||
                fields["SUBSYSTEM"] != "mem" || fields["MAJOR"] != "1" ||
                fields["MINOR"] != minor || fields["DEVNAME"] != "/dev/" name ||
                fields["DEVMODE"] != "0666" || fields["SEQNUM"] !~ /^[0-9]+$/ ||
                fields["SEQNUM"] + 0 <= before + 0 ||
                fields["SEQNUM"] + 0 > after + 0)
                bad = 1
            sequence = fields["SEQNUM"]
        }
        END {
            if (matches != 1 || bad) exit 1
            print sequence
        }
    ' "$MONITOR_LOG" >"$EVENT_BASE.seqnum"
}

trigger_device()
{
    TRIGGER_ACTION=$1
    EVENT_NUMBER=$((EVENT_NUMBER + 1))
    EVENT_BASE=$TEST_DIR/event-$EVENT_NUMBER-$NAME-$TRIGGER_ACTION
    SEQNUM_BEFORE=$(cat /sys/kernel/uevent_seqnum)
    echo "+ $UDEVADM trigger --uuid --type=devices --action=$TRIGGER_ACTION $DEVICE_PATH"
    timeout 15 "$UDEVADM" trigger --uuid --type=devices --action="$TRIGGER_ACTION" \
        --subsystem-match=mem --sysname-match="$NAME" "$DEVICE_PATH" \
        >"$EVENT_BASE.trigger" || fail "targeted $TRIGGER_ACTION trigger failed for $NAME"
    SEQNUM_AFTER=$(cat /sys/kernel/uevent_seqnum)
    printf 'before=%s\nafter=%s\n' "$SEQNUM_BEFORE" "$SEQNUM_AFTER" >"$EVENT_BASE.snapshot"
    TRIGGER_UUID=$(cat "$EVENT_BASE.trigger")
    awk 'END { exit(NR == 1 ? 0 : 1) }' "$EVENT_BASE.trigger" &&
        printf '%s\n' "$TRIGGER_UUID" | grep -E -x -q \
            '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' ||
        fail "targeted trigger did not return exactly one UUID for $NAME"
    case "$SEQNUM_BEFORE:$SEQNUM_AFTER" in
        *[!0-9:]*|:*|*:) fail "invalid uevent sequence snapshots for $NAME" ;;
    esac
    record_remaining=10
    until capture_kernel_record; do
        process_is_active "$MONITOR_PID" || fail "kernel monitor exited during $NAME trigger"
        [ "$record_remaining" -gt 0 ] ||
            fail "missing, duplicate or invalid complete $NAME $TRIGGER_ACTION kernel record ($TRIGGER_UUID)"
        sleep 1
        record_remaining=$((record_remaining - 1))
    done
    RECORD_SEQNUM=$(cat "$EVENT_BASE.seqnum")
    [ "$RECORD_SEQNUM" -gt "$LAST_SEQNUM" ] ||
        fail "serially triggered records are not in sequence order"
    LAST_SEQNUM=$RECORD_SEQNUM
    printf '%s %s %s %s %s %s %s\n' "$NAME:$MINOR" "$TRIGGER_ACTION" \
        "$TRIGGER_UUID" "$SEQNUM_BEFORE" "$SEQNUM_AFTER" "$RECORD_SEQNUM" \
        "$EVENT_NUMBER" >>"$TEST_DIR/events"
    # Ordinary settle checks the queue. It is not the UUID/processed-event
    # round trip tested by trigger --settle; actual rule effects are checked below.
    timeout 15 "$UDEVADM" settle --timeout=10 ||
        fail "udev queue did not settle after $NAME $TRIGGER_ACTION"
    echo "kernel record: $NAME $TRIGGER_ACTION seq=$RECORD_SEQNUM uuid=$TRIGGER_UUID"
}

check_record_manifest()
{
    # Check again on the completed monitor log, including any duplicate
    # record that arrived after the first successful bounded wait.
    while read -r manifest_device TRIGGER_ACTION TRIGGER_UUID SEQNUM_BEFORE \
        SEQNUM_AFTER manifest_sequence manifest_number; do
        select_device "$manifest_device"
        EVENT_BASE=$TEST_DIR/event-$manifest_number-$NAME-$TRIGGER_ACTION
        if ! capture_kernel_record ||
            [ "$(cat "$EVENT_BASE.seqnum")" != "$manifest_sequence" ]; then
            fail "completed monitor log has invalid/duplicate $NAME $TRIGGER_ACTION records"
            return 1
        fi
    done <"$TEST_DIR/events"
}

rule_state_matches()
{
    "$UDEVADM" info --query=property --path="$DEVICE_PATH" >"$INFO" 2>&1 || return 1
    has_field "$INFO" "$TEST_PROPERTY" "$PHASE-$NAME-$TRIGGER_ACTION" &&
        has_devlink "$INFO" "$DEVLINK" &&
        [ -L "$DEVLINK" ] &&
        [ "$(readlink -f "$DEVLINK")" = "/dev/$NAME" ] &&
        [ "$(stat -c '%u:%g:%a' "/dev/$NAME")" = 1:1:640 ]
}

wait_for_rule_state()
{
    rule_remaining=10
    until rule_state_matches; do
        [ "$rule_remaining" -gt 0 ] ||
            fail "rule property, devlink or permissions did not take effect for $NAME ($INFO)"
        sleep 1
        rule_remaining=$((rule_remaining - 1))
    done
    check_device_identity
    has_field "$TEST_DIR/node-$NAME.log" "$TEST_PROPERTY" "$PHASE-$NAME-$TRIGGER_ACTION" &&
        has_devlink "$TEST_DIR/node-$NAME.log" "$DEVLINK" ||
        fail "sysfs and devnode udev queries disagree for $NAME"
}

check_shared_link()
{
    [ -L "$SHARED_LINK" ] &&
        [ "$(readlink -f "$SHARED_LINK")" = "/dev/$1" ] ||
        fail "shared devlink does not resolve to the expected /dev/$1"
}

clean_state_matches()
{
    "$UDEVADM" info --query=property --path="$DEVICE_PATH" >"$INFO" 2>&1 || return 1
    ! grep -q "^$TEST_PROPERTY=" "$INFO" &&
        ! grep -F -q "$LINK_PREFIX" "$INFO" &&
        [ ! -e "$DEVLINK" ] && [ ! -L "$DEVLINK" ]
}

wait_for_clean_state()
{
    clean_remaining=10
    until clean_state_matches; do
        [ "$clean_remaining" -gt 0 ] || return 1
        sleep 1
        clean_remaining=$((clean_remaining - 1))
    done
}

remove_rules()
{
    if [ "$OWNS_RULE_FILE" -eq 1 ]; then
        rm -f "$RULE_FILE" || return 1
        OWNS_RULE_FILE=0
    fi
    if [ "$DATABASE_DIRTY" -eq 1 ]; then
        reload_rules || return 1
    fi
}

restore_permissions()
{
    permissions_status=0
    for permission_device in $DEVICES; do
        select_device "$permission_device"
        [ -f "$TEST_DIR/original-mode-$NAME" ] &&
            [ -f "$TEST_DIR/original-owner-$NAME" ] || continue
        original_mode=$(cat "$TEST_DIR/original-mode-$NAME")
        original_owner=$(cat "$TEST_DIR/original-owner-$NAME")
        if ! chown "$original_owner" "/dev/$NAME" ||
            ! chmod "$original_mode" "/dev/$NAME" ||
            [ "$(stat -c '%u:%g:%a' "/dev/$NAME")" != "$original_owner:$original_mode" ]; then
            echo "could not restore /dev/$NAME permissions to $original_owner:$original_mode" >&2
            permissions_status=1
        fi
    done
    return "$permissions_status"
}

cleanup_rule_effects()
{
    effects_status=0
    remove_rules || effects_status=1
    if [ "$DATABASE_DIRTY" -eq 1 ]; then
        # Recompute production rules instead of deleting shared database files.
        # Never synthesize remove: these five devices remain registered.
        for cleanup_device in $DEVICES; do
            select_device "$cleanup_device"
            timeout 15 "$UDEVADM" trigger --type=devices --action=add \
                --subsystem-match=mem --sysname-match="$NAME" "$DEVICE_PATH" ||
                effects_status=1
        done
        timeout 15 "$UDEVADM" settle --timeout=10 || effects_status=1
        for cleanup_device in $DEVICES; do
            select_device "$cleanup_device"
            if ! wait_for_clean_state; then
                echo "test database/link effects remain for $NAME ($INFO)" >&2
                effects_status=1
            fi
        done
        [ ! -e "$SHARED_LINK" ] && [ ! -L "$SHARED_LINK" ] || effects_status=1
        [ "$effects_status" -ne 0 ] || DATABASE_DIRTY=0
    fi
    return "$effects_status"
}

remove_owned_links()
{
    [ "$OWNS_LINK_NAMESPACE" -eq 1 ] || return 0
    links_status=0
    for link_device in $DEVICES; do
        select_device "$link_device"
        if [ -L "$DEVLINK" ] && [ "$(readlink -f "$DEVLINK")" = "/dev/$NAME" ]; then
            rm -f "$DEVLINK" || links_status=1
        elif [ -e "$DEVLINK" ] || [ -L "$DEVLINK" ]; then
            echo "refusing to remove unexpected object at $DEVLINK" >&2
            links_status=1
        fi
    done
    if [ -L "$SHARED_LINK" ]; then
        case "$(readlink -f "$SHARED_LINK")" in
            /dev/null|/dev/zero) rm -f "$SHARED_LINK" || links_status=1 ;;
            *) echo "refusing to remove unexpected shared link $SHARED_LINK" >&2
               links_status=1 ;;
        esac
    elif [ -e "$SHARED_LINK" ]; then
        echo "refusing to remove unexpected object at $SHARED_LINK" >&2
        links_status=1
    fi
    return "$links_status"
}

stop_monitor()
{
    [ -n "$MONITOR_PID" ] || return 0
    monitor_requested=0
    if process_is_active "$MONITOR_PID"; then
        kill -TERM "$MONITOR_PID" 2>/dev/null && monitor_requested=1
        wait_for_exit "$MONITOR_PID" || kill -KILL "$MONITOR_PID" 2>/dev/null
    fi
    if wait "$MONITOR_PID"; then monitor_status=0; else monitor_status=$?; fi
    MONITOR_PID=
    [ "$monitor_requested" -eq 1 ] &&
        { [ "$monitor_status" -eq 0 ] || [ "$monitor_status" -eq 143 ]; }
}

stop_daemon()
{
    # Only the standalone mode ever owns a daemon PID.
    [ -n "$UDEVD_PID" ] || return 0
    daemon_requested=0
    if process_is_active "$UDEVD_PID"; then
        if timeout 10 "$UDEVADM" control --exit --timeout=5; then
            daemon_requested=1
        else
            kill -TERM "$UDEVD_PID" 2>/dev/null
        fi
        wait_for_exit "$UDEVD_PID" || kill -KILL "$UDEVD_PID" 2>/dev/null
    fi
    if wait "$UDEVD_PID"; then daemon_status=0; else daemon_status=$?; fi
    UDEVD_PID=
    [ "$daemon_requested" -eq 1 ] && [ "$daemon_status" -eq 0 ]
}

finish()
{
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ -n "$TEST_DIR" ]; then
        cleanup_rule_effects || status=1
    fi
    stop_monitor || { echo "kernel monitor exited unexpectedly" >&2; status=1; }
    stop_daemon || { echo "standalone daemon exited unexpectedly" >&2; status=1; }
    if [ "$status" -eq 0 ]; then
        check_record_manifest || status=1
    fi
    remove_owned_links || status=1
    if [ -n "$TEST_DIR" ]; then
        restore_permissions || status=1
    fi
    if [ "$status" -ne 0 ] && [ -n "$TEST_DIR" ]; then
        echo "--- mem udev failure diagnostics ---" >&2
        for diagnostic in "$TEST_DIR"/*.log "$TEST_DIR"/*.trigger "$TEST_DIR"/*.snapshot; do
            [ -f "$diagnostic" ] || continue
            echo "--- $diagnostic ---" >&2
            cat "$diagnostic" >&2
        done
        echo "--- last kernel messages ---" >&2
        dmesg | tail -n 100 >&2
    fi
    if [ "$OWNS_RUNTIME_DIR" -eq 1 ]; then
        if [ -f "$OWNERSHIP_MARKER" ] &&
            [ "$(cat "$OWNERSHIP_MARKER")" = "$RUN_ID" ]; then
            rm -rf "$RUNTIME_DIR" || status=1
        else
            echo "runtime ownership marker differs; refusing to delete /run/udev" >&2
            status=1
        fi
    elif [ "$OWNS_RULE_DIR" -eq 1 ]; then
        # If another user has populated the directory, it is now shared.
        rmdir "$RULE_DIR" 2>/dev/null || true
    fi
    if [ -n "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR" || status=1
    fi
    if [ "$status" -eq 0 ]; then
        echo "cleanup: owned rules, properties, links and permissions restored"
        echo "All five mem udev tests passed."
        if [ "$MODE" = standalone ]; then
            echo "Real udev coldplug regression passed."
        fi
    fi
    exit "$status"
}

trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

command -v "$UDEVADM" >/dev/null || fail "$UDEVADM is not executable"
for prerequisite in awk cat grep readlink stat chown chmod mkdir rm rmdir mktemp sleep timeout id; do
    command -v "$prerequisite" >/dev/null || fail "$prerequisite is required"
done
[ "$(id -u)" -eq 0 ] || fail "root privileges are required"
[ -w /run ] || fail "/run is not writable"
[ -r /sys/kernel/uevent_seqnum ] || fail "/sys/kernel/uevent_seqnum is missing"
if [ "$MODE" = standalone ]; then
    [ ! -e "$RUNTIME_DIR" ] && [ ! -L "$RUNTIME_DIR" ] ||
        fail "/run/udev already exists; use --managed for an existing daemon"
    if [ -z "$UDEVD" ]; then
        if [ -x /usr/lib/systemd/systemd-udevd ]; then
            UDEVD=/usr/lib/systemd/systemd-udevd
        else
            UDEVD=systemd-udevd
        fi
    fi
    command -v "$UDEVD" >/dev/null || fail "$UDEVD is not executable"
    grep -q ' /run tmpfs ' /proc/mounts || fail "standalone /run is not a tmpfs mount"
else
    [ -d "$RUNTIME_DIR" ] || fail "--managed requires the existing /run/udev"
fi

TEST_DIR=$(mktemp -d /run/asterinas-udev-mem-test.XXXXXX)
RUN_ID=${TEST_DIR##*/}
LINK_PREFIX=$RUN_ID
TEST_PROPERTY=ASTERINAS_UDEV_MEM_TEST_${RUN_ID##*.}
RULE_FILE=$RULE_DIR/99-zz-$RUN_ID.rules
DAEMON_LOG=$TEST_DIR/systemd-udevd.log
MONITOR_LOG=$TEST_DIR/udevadm-monitor.log
SHARED_LINK=/dev/$LINK_PREFIX-shared
[ ! -e "$SHARED_LINK" ] && [ ! -L "$SHARED_LINK" ] ||
    fail "$SHARED_LINK already exists"
for device in $DEVICES; do
    select_device "$device"
    [ ! -e "$DEVLINK" ] && [ ! -L "$DEVLINK" ] || fail "$DEVLINK already exists"
    check_device_identity
    stat -c '%a' "/dev/$NAME" >"$TEST_DIR/original-mode-$NAME"
    stat -c '%u:%g' "/dev/$NAME" >"$TEST_DIR/original-owner-$NAME"
    # The kernel's DEVMODE is checked in both modes. Save the actual node
    # permissions as well, since installed udev rules may impose local policy.
    ! grep -q "^$TEST_PROPERTY=" "$INFO" || fail "test property already exists for $NAME"
done
OWNS_LINK_NAMESPACE=1

if [ "$MODE" = standalone ]; then
    # mkdir is exclusive: only an initially absent runtime tree can be owned.
    mkdir "$RUNTIME_DIR"
    OWNS_RUNTIME_DIR=1
    printf '%s\n' "$RUN_ID" >"$OWNERSHIP_MARKER"
fi
if [ ! -d "$RULE_DIR" ]; then
    mkdir "$RULE_DIR"
    OWNS_RULE_DIR=1
fi
[ ! -e "$RULE_FILE" ] && [ ! -L "$RULE_FILE" ] || fail "$RULE_FILE already exists"

echo "mode: $MODE"
echo "udevadm version: $("$UDEVADM" --version)"
echo "coverage: kernel records and rule effects; processed-event/worker-route ABI and trigger --settle are separate probes"
if [ "$MODE" = standalone ]; then
    echo "systemd-udevd version: $("$UDEVD" --version)"
    SYSTEMD_LOG_TARGET=console SYSTEMD_LOG_COLOR=0 \
        "$UDEVD" --debug --children-max=1 --event-timeout=10 --resolve-names=never \
        >"$DAEMON_LOG" 2>&1 &
    UDEVD_PID=$!
    control_remaining=10
    while [ ! -S "$RUNTIME_DIR/control" ]; do
        process_is_active "$UDEVD_PID" || fail "standalone daemon exited before readiness"
        [ "$control_remaining" -gt 0 ] || fail "standalone control socket did not appear"
        sleep 1
        control_remaining=$((control_remaining - 1))
    done
fi
timeout 15 "$UDEVADM" control --ping --timeout=10 || fail "daemon control channel is not ready"
if [ -n "$UDEVD_PID" ]; then
    process_is_active "$UDEVD_PID" || fail "standalone daemon exited after control ping"
fi

"$UDEVADM" monitor --kernel --property --subsystem-match=mem >"$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!
subscription_remaining=10
# systemd v260 prints this only after sd_device_monitor_start() succeeds.
while ! grep -F -q 'KERNEL - the kernel uevent' "$MONITOR_LOG"; do
    process_is_active "$MONITOR_PID" || fail "kernel monitor exited before subscription"
    [ "$subscription_remaining" -gt 0 ] || fail "kernel monitor subscription did not become ready"
    sleep 1
    subscription_remaining=$((subscription_remaining - 1))
done
process_is_active "$MONITOR_PID" || fail "kernel monitor exited after subscription"

echo "scenario: all five sysfs/devnode identities and add/change rule effects"
write_rules first 10
# Process the higher-priority claimant first, then prove that a later lower
# priority event cannot steal the shared link.
for action in add change; do
    for device in zero:5 null:3 full:7 random:8 urandom:9; do
        select_device "$device"
        trigger_device "$action"
        wait_for_rule_state
        check_shared_link zero
    done
done

echo "scenario: priority promotion after reload and selected change"
write_rules promoted 30
select_device null:3
trigger_device change
wait_for_rule_state
check_shared_link null
has_devlink "$INFO" "$SHARED_LINK" || fail "null's shared claim is absent from udev info"
select_device zero:5
"$UDEVADM" info --query=property --path="$DEVICE_PATH" >"$INFO"
has_field "$INFO" "$TEST_PROPERTY" first-zero-change &&
    has_devlink "$INFO" "$SHARED_LINK" ||
    fail "selected null retrigger unexpectedly altered zero's property or claim"

echo "scenario: withdrawing one claim falls back without unregistering devices"
write_rules fallback none
select_device null:3
trigger_device change
wait_for_rule_state
! has_devlink "$INFO" "$SHARED_LINK" || fail "withdrawn null shared claim remains in the database"
check_shared_link zero
select_device zero:5
"$UDEVADM" info --query=property --path="$DEVICE_PATH" >"$INFO"
has_field "$INFO" "$TEST_PROPERTY" first-zero-change &&
    has_devlink "$INFO" "$SHARED_LINK" ||
    fail "fallback required an unintended retrigger of zero"

echo "scenario: repeated targeted add/change remains consistent for all five"
for action in add change; do
    for device in $DEVICES; do
        select_device "$device"
        trigger_device "$action"
        wait_for_rule_state
        check_shared_link zero
    done
done

echo "scenario: removing rules clears only test properties and links"
remove_rules
for device in $DEVICES; do
    select_device "$device"
    trigger_device add
    wait_for_clean_state || fail "test property or per-device link remains for $NAME"
    check_device_identity
    ! grep -q "^$TEST_PROPERTY=" "$TEST_DIR/node-$NAME.log" &&
        ! grep -F -q "$LINK_PREFIX" "$TEST_DIR/node-$NAME.log" ||
        fail "devnode query retains test database effects for $NAME"
done
[ ! -e "$SHARED_LINK" ] && [ ! -L "$SHARED_LINK" ] || fail "shared test link remains"
DATABASE_DIRTY=0
# EXIT performs the remaining cleanup before either success marker is emitted.
