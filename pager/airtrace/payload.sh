#!/bin/bash
# Title: AirTrace - passive recon (AP + clients + GPS)
# Description: Passively records 802.11 frames to a pcap and raw GPS NMEA.
#              Classification and geotagging are done on the PC (pc/airtrace.py).
# Author: (you)
# Version: 0.2
#
# Transmits nothing. Only a monitor-mode capture and a GPS log.
#
# NOTE: the DuckyScript-style helpers (LOG, WIFI_PCAP_START, WIFI_PCAP_STOP)
# are used as named in the spec. Check their argument syntax on your Pager
# firmware before the first field run and adjust the three marked lines.

LOOT_ROOT="${LOOT_ROOT:-/root/loot}"   # Pager runs payloads without $HOME
SESSION="airtrace-$(date -u +%Y%m%dT%H%M%SZ)"
LOOT="$LOOT_ROOT/$SESSION"
PCAP="$LOOT/capture.pcap"
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
    WIFI_PCAP_STOP                                   # (1) stop capture
    sync
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
# (2) start monitor-mode capture to $PCAP. Argument form per spec; verify.
WIFI_PCAP_START "$PCAP"
LOG "Recording: $SESSION"

# Keep the payload alive until the user stops it. Pager stops it with INT.
# "sleep & wait" lets the trap fire immediately instead of after the sleep.
while true; do
    sleep 5 &
    wait $!
    # (3) optional status line for the Pager screen
    FIXES=$(wc -l < "$NMEA")
    LOG "Recording $(du -h "$PCAP" 2>/dev/null | cut -f1) pcap, GPS: $GPS_SRC ($FIXES fixes)"
done
