#!/bin/bash
# Title: AirTrace - passive recon (AP + clients + GPS)
# Description: Passively records 802.11 frames to a pcap plus a GPS log.
#              Classification and geotagging are done on the PC (pc/airtrace.py).
# Author: (you)
# Version: 0.4
#
# Transmits nothing. Only a monitor-mode capture and a GPS log.
#
# Pager helpers used: LOG, GPS_GET, WIFI_PCAP_START, WIFI_PCAP_STOP.
# WIFI_PCAP_START takes no arguments: pineapd picks the file and the command
# prints its name. We move that file into the session folder on stop.

LOOT_ROOT="${LOOT_ROOT:-/root/loot}"   # Pager runs payloads without $HOME
SESSION="airtrace-$(date -u +%Y%m%dT%H%M%SZ)"
LOOT="$LOOT_ROOT/$SESSION"
PCAP="$LOOT/capture.pcap"        # final location after stop
PCAP_SRC=""                      # file pineapd is writing while recording
GPSLOG="$LOOT/gps.log"           # "<pager epoch> <lat> <lon> <alt> <speed>"

mkdir -p "$LOOT"
: >> "$GPSLOG"

# GPS: pineapd owns the receiver (gpsd is off), so read it through GPS_GET,
# which prints "lat lon alt speed" (0.0 0.0 ... without a fix). Timestamps
# come from the Pager clock, the same clock pineapd uses for the pcap.
gps_poll() {
    while true; do
        GPS_GET 2>/dev/null | awk -v t="$(date -u +%s)" \
            'NF >= 2 && ($1 + 0 != 0 || $2 + 0 != 0) { print t, $1, $2, $3, $4 }' >> "$GPSLOG"
        sleep 1
    done
}

GPS_PID=""
STOPPING=""
cleanup() {
    [ -n "$STOPPING" ] && return
    STOPPING=1
    LOG "Stopping capture..."
    if [ -n "$GPS_PID" ]; then
        kill "$GPS_PID" 2>/dev/null
    fi
    WIFI_PCAP_STOP
    sync
    if [ -n "$PCAP_SRC" ] && [ -f "$PCAP_SRC" ]; then
        case "$PCAP_SRC" in
            *.pcapng) PCAP="${PCAP%.pcap}.pcapng" ;;
        esac
        mv "$PCAP_SRC" "$PCAP" && sync
    else
        LOG "WARNING: pcap file not found: ${PCAP_SRC:-<none>}"
    fi
    LOG "Session saved: $LOOT"
    exit 0
}
trap cleanup INT TERM

# --- GPS ---------------------------------------------------------------
gps_poll &
GPS_PID=$!
LOG "GPS: $(GPS_GET 2>/dev/null || echo 'GPS_GET failed')"

# --- Capture --------------------------------------------------------------
# WIFI_PCAP_START prints the capture file name (path may be relative).
PCAP_SRC=$(WIFI_PCAP_START 2>&1 | tail -n1)
if [ -n "$PCAP_SRC" ] && [ "${PCAP_SRC#/}" = "$PCAP_SRC" ] && [ ! -f "$PCAP_SRC" ]; then
    FOUND=$(find /root/loot /mmc/root/loot /tmp -name "$(basename "$PCAP_SRC")" 2>/dev/null | head -n1)
    [ -n "$FOUND" ] && PCAP_SRC="$FOUND"
fi
echo "$PCAP_SRC" > "$LOOT/pcap_source.txt"
LOG "Recording: $SESSION"
LOG "pcap: ${PCAP_SRC:-<WIFI_PCAP_START failed>}"

# Keep the payload alive until the user stops it. Pager stops it with INT.
# "sleep & wait" lets the trap fire immediately instead of after the sleep.
while true; do
    sleep 5 &
    wait $!
    FIXES=$(wc -l < "$GPSLOG")
    SIZE=$(du -h "$PCAP_SRC" 2>/dev/null | cut -f1)
    LOG "Recording ${SIZE:-0} pcap, GPS fixes: $FIXES"
done
