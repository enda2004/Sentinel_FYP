#!/usr/bin/env bash
# Put a wireless adapter into (or out of) monitor mode.
#
#   sudo ./scripts/monitor-mode.sh up   wlan1
#   sudo ./scripts/monitor-mode.sh down wlan1
#   sudo ./scripts/monitor-mode.sh status
#
# Deliberately does not use `airmon-ng check kill`: that stops NetworkManager
# and wpa_supplicant, which on a Raspberry Pi kills the connection you are
# almost certainly logged in over. Instead only the capture interface is
# taken over, and everything else is left running.

set -euo pipefail

ACTION="${1:-status}"
IFACE="${2:-wlan1}"

die() { echo "error: $*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "run this with sudo"; }

have_iface() { [[ -d "/sys/class/net/$IFACE" ]]; }

iface_type() {
    # 803 = ARPHRD_IEEE80211_RADIOTAP (monitor), 1 = ARPHRD_ETHER (managed)
    cat "/sys/class/net/$1/type" 2>/dev/null || echo "?"
}

case "$ACTION" in
up)
    need_root
    have_iface || die "no interface called $IFACE (try: iw dev)"

    if [[ "$(iface_type "$IFACE")" == "803" ]]; then
        echo "$IFACE is already in monitor mode"
        exit 0
    fi

    # Stop NetworkManager from reassociating the interface while it is in use.
    if command -v nmcli >/dev/null 2>&1; then
        nmcli device set "$IFACE" managed no 2>/dev/null || true
        sleep 1
    fi

    ip link set "$IFACE" down
    iw dev "$IFACE" set type monitor
    ip link set "$IFACE" up

    [[ "$(iface_type "$IFACE")" == "803" ]] || die "$IFACE did not enter monitor mode"
    echo "$IFACE is in monitor mode"
    iw dev "$IFACE" info | sed 's/^/  /'
    ;;

down)
    need_root
    have_iface || die "no interface called $IFACE"

    ip link set "$IFACE" down
    iw dev "$IFACE" set type managed
    ip link set "$IFACE" up
    if command -v nmcli >/dev/null 2>&1; then
        nmcli device set "$IFACE" managed yes 2>/dev/null || true
    fi
    echo "$IFACE returned to managed mode"
    ;;

status)
    printf '%-10s %-10s %s\n' INTERFACE MODE DRIVER
    for path in /sys/class/net/*; do
        dev="$(basename "$path")"
        [[ -d "$path/wireless" || -d "$path/phy80211" ]] || continue
        case "$(iface_type "$dev")" in
            803) mode=monitor ;;
            1)   mode=managed ;;
            *)   mode=unknown ;;
        esac
        driver="$(basename "$(readlink -f "$path/device/driver" 2>/dev/null || echo unknown)")"
        printf '%-10s %-10s %s\n' "$dev" "$mode" "$driver"
    done
    ;;

*)
    die "usage: $0 {up|down|status} [interface]"
    ;;
esac
