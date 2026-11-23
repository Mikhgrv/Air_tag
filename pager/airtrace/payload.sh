#!/bin/bash
# Title: AirTrace - passive recon (AP + clients + GPS)
# Description: Passively records 802.11 frames to a pcap and raw GPS NMEA.
#              Classification and geotagging are done on the PC (pc/airtrace.py).
# Author: (you)
# Version: 0.3
#
# Transmits nothing. Only a monitor-mode capture and a GPS log.
#
# Pager helpers used: LOG, WIFI_PCAP_START, WIFI_PCAP_STOP.
# WIFI_PCAP_START takes no arguments: pineapd picks the file and the command
# prints its name. We move that file into the session folder on stop.

LOOT_ROOT="${LOOT_ROOT:-/root/loot}"   # Pager runs payloads without $HOME
SESSION="airtrace-$(date -u +%Y%m%dT%H%M%SZ)"
LOOT="$LOOT_ROOT/$SESSION"
PCAP="$LOOT/capture.pcap"        # final location after stop
PCAP_SRC=""                      # file pineapd is writing while recording
NMEA="$LOOT/gps.nmea"
GPS_BAUD="${GPS_BAUD:-9600}"     # u-blox default; some modules use 4800/38400

mkdir -p "$LOOT"
: >> "$NMEA"

# Each RMC line is stored as "<pager epoch> $GPRMC,...". The PC side uses the
# difference to the GPS time to fix pcap timestamps if the Pager clock is off
# (no RTC / no NTP in the field). Pure shell: BusyBox grep may lack
# --line-buffered, and this way nothing is buffered.
gps_log() {
    while IFS= read -r line; do
        case "$line" in
            '$GPRMC'*|'$GNRMC'*) printf '%s %s\n' "$(date -u +%s)" "$line" >> "$NMEA" ;;
        esac
    done
}

GPS_PID=""
STOPPING=""
cleanup() {
    [ -n "$STOPPING" ] && return
    STOPPING=1
    LOG "Stopping capture..."
    if [ -n "$GPS_PID" ]; then
        pkill -P "$GPS_PID" 2>/dev/null   # gpspipe / reader inside the subshell
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

# --- GPS source: gpsd if running, otherwise serial port -------------------
GPS_SRC="none"
if pgrep -x gpsd >/dev/null 2>&1 && command -v gpspipe >/dev/null 2>&1; then
    GPS_SRC="gpsd"
    ( gpspipe -r | gps_log ) &
    GPS_PID=$!
else
    TTY=$(ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null | head -n1)
    if [ -n "$TTY" ]; then
        GPS_SRC="$TTY"
        stty -F "$TTY" "$GPS_BAUD" raw -echo 2>/dev/null
        ( gps_log < "$TTY" ) &
        GPS_PID=$!
    fi
fi
LOG "GPS source: $GPS_SRC"

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
    FIXES=$(wc -l < "$NMEA")
    SIZE=$(du -h "$PCAP_SRC" 2>/dev/null | cut -f1)
    LOG "Recording ${SIZE:-0} pcap, GPS: $GPS_SRC ($FIXES fixes)"
done
