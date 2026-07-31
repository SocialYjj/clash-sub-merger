#!/bin/sh
set -eu
umask 077

data_dir="${DATA_DIR:-/app/data}"

case "$data_dir" in
    ""|"/")
        echo "DATA_DIR must point to a dedicated application directory" >&2
        exit 1
        ;;
esac

mkdir -p \
    "$data_dir/uploads" \
    "$data_dir/logs" \
    "$data_dir/backups" \
    "$data_dir/refresh_locks"

if [ "$(id -u)" = "0" ]; then
    # A fresh bind mount is commonly created as root and hides the ownership
    # prepared in the image. Repair the mounted tree before dropping privileges.
    if ! chown -R appuser:appuser "$data_dir"; then
        echo "Could not change DATA_DIR ownership; checking effective appuser access" >&2
    fi

    # Configuration, subscriptions, and backups contain credentials. Tighten
    # existing migrated files as well as files created under the umask above.
    if ! find "$data_dir" -type d -exec chmod 700 {} + \
        || ! find "$data_dir" -type f -exec chmod 600 {} +; then
        echo "Could not tighten all DATA_DIR permissions on this filesystem" >&2
    fi

    for writable_dir in \
        "$data_dir" \
        "$data_dir/uploads" \
        "$data_dir/logs" \
        "$data_dir/backups" \
        "$data_dir/refresh_locks"
    do
        write_probe="$writable_dir/.submerger-write-test.$$"
        if ! gosu appuser touch "$write_probe"; then
            echo "DATA_DIR is not writable by appuser: $writable_dir" >&2
            exit 1
        fi
        gosu appuser rm -f "$write_probe"
    done

    exec gosu appuser "$@"
fi

for writable_dir in \
    "$data_dir" \
    "$data_dir/uploads" \
    "$data_dir/logs" \
    "$data_dir/backups" \
    "$data_dir/refresh_locks"
do
    write_probe="$writable_dir/.submerger-write-test.$$"
    if ! (touch "$write_probe" && rm -f "$write_probe"); then
        echo "DATA_DIR is not writable by uid $(id -u): $writable_dir" >&2
        exit 1
    fi
done

exec "$@"
