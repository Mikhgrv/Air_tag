#!/bin/bash
# Title: GPS Check
# Description: Shows GPS_GET output every 2 s until stopped. Records nothing.
# Author: (you)
# Version: 1.0
#
# "0 0 0 0" = no fix yet (go outdoors, wait 2-5 min).
# "lat lon alt speed" with real numbers = GPS works.

trap 'exit 0' INT TERM

LOG "GPS check: waiting for a fix..."
FIRST_FIX=""
START=$(date +%s)
while true; do
    POS=$(GPS_GET 2>/dev/null)
    ELAPSED=$(( $(date +%s) - START ))
    if echo "$POS" | awk 'NF >= 2 && ($1 + 0 != 0 || $2 + 0 != 0) { ok = 1 } END { exit !ok }'; then
        if [ -z "$FIRST_FIX" ]; then
            FIRST_FIX=1
            LOG "FIX after ${ELAPSED}s"
            VIBRATE 2>/dev/null
        fi
        LOG "FIX: $POS"
    else
        LOG "no fix (${ELAPSED}s): ${POS:-GPS_GET failed}"
    fi
    sleep 2 &
    wait $!
done
