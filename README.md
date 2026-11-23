# AirTrace

Passive Wi-Fi recon with GPS for the Pager: the device only **listens**, and the PC
works out who was where.

```
Pager (pager/airtrace/payload.sh)   PC (pc/airtrace.py)
  monitor-mode capture  ──► capture.pcap ─┐
  GPS RMC sentences     ──► gps.nmea ─────┴─► devices-<date>.csv
                                              devices-<date>.kml  (Google Earth / QGIS)
                                              track-<date>.csv
```

Nothing is transmitted: no deauth, no probes, no association.

## Repository layout

| File | Where it runs | What it does |
|---|---|---|
| `pager/airtrace/payload.sh` | Pager | Writes a pcap and a GPS log into `/root/loot/airtrace-<UTC time>/` |
| `pc/airtrace.py` | PC | Classifies MACs, geotags them, builds the CSV / KML |
| `pc/requirements.txt` | PC | `scapy` |

## Pager side

1. Copy the `pager/airtrace/` folder to the Pager's payload directory, e.g.
   `payloads/user/recon/airtrace/payload.sh`.
2. Before the first field run, check the argument syntax of `LOG`,
   `WIFI_PCAP_START` and `WIFI_PCAP_STOP` on your firmware (lines marked (1), (2), (3)).
3. GPS: `gpsd` is used if it is running, otherwise the first `/dev/ttyACM*` / `/dev/ttyUSB*`.
   Serial baud rate comes from `GPS_BAUD` (default 9600).
4. Stop the payload from the Pager menu (it sends INT); the capture is closed cleanly.

Each GPS line is saved as `<Pager epoch> $GPRMC,...`. If the Pager clock is
wrong (no RTC, no NTP in the field), `airtrace.py` sees the offset against GPS
time and shifts the pcap timestamps.

## PC side

```bash
pip install -r pc/requirements.txt
./pc/airtrace.py path/to/loot/airtrace-20261120T120000Z
```

No build step: it is a plain Python 3 script. On Linux you only need
`python3` and Scapy (`pip install scapy`, or `sudo apt install python3-scapy`
on Debian/Ubuntu).

Options: `--no-clock-fix` turns off the Pager clock correction.

### Classification (per MAC, highest rank wins)

| Type | Source | MAC |
|---|---|---|
| `AP` | beacon / probe response | BSSID (addr3) |
| `ASSOCIATED` | data frames, (re)association request | client |
| `PROBING` | probe request only | addr2 |

Broadcast and multicast addresses are ignored. `RandomMAC=yes` means the
locally-administered bit is set (a randomized MAC on phones).

### Coordinates

A device's point is the GPS fix (within ±10 s) at the moment of its
**strongest own** frame. RSSI is taken only from frames the device itself
transmitted, so a client is never placed by its AP's signal.

### CSV columns

`MAC, Type, RandomMAC, SSID/Probed, ConnectedBSSID, FirstSeenUTC, LastSeenUTC,
Packets, BestRSSI, Lat, Lon`

## Legal

Even passive capture of other people's traffic and MAC addresses is regulated
(privacy and personal-data laws) in many countries. Use it on your own networks
or with permission. Field data (`loot/`, `*.pcap`, `*.nmea`, results) is
excluded from git by `.gitignore`.
