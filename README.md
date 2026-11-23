# AirTrace

Passive Wi-Fi recon with GPS for the Pager: the device only **listens**, and the PC
works out who was where.

```
Pager (pager/airtrace/payload.sh)   PC (pc/airtrace.py)
  monitor-mode capture  ──► capture.pcap ─┐
  GPS_GET every second  ──► gps.log ──────┴─► devices-<date>.csv
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
2. GPS: the payload reads the receiver through the Pager's own `GPS_GET`
   (pineapd owns the serial port, so the port cannot be read directly).
   Select the GPS once with `GPS_LIST` / `GPS_CONFIGURE PINEAP <device>`.
3. The capture is started with `WIFI_PCAP_START` (pineapd chooses the file);
   on stop the file is moved into the session folder as `capture.pcap`.
4. Stop the payload from the Pager menu (it sends INT); the capture is closed cleanly.

Session folder: `capture.pcap`, `gps.log` (`<epoch> <lat> <lon> <alt> <speed>`,
only samples with a fix), `pcap_source.txt` (where pineapd wrote the pcap).
GPS and pcap timestamps both come from the Pager clock, so they always line up.

## PC side

```bash
pip install -r pc/requirements.txt
./pc/airtrace.py path/to/loot/airtrace-20261120T120000Z
```

No build step: it is a plain Python 3 script. On Linux you only need
`python3` and Scapy (`pip install scapy`, or `sudo apt install python3-scapy`
on Debian/Ubuntu).

Older sessions with `gps.nmea` are still supported (`--no-clock-fix` turns off
the Pager-vs-GPS clock correction for them).

### Classification (per MAC, highest rank wins)

| Type | Source | MAC |
|---|---|---|
| `AP` | beacon / probe response | BSSID (addr3) |
| `ASSOCIATED` | data frames, (re)association request | client |
| `PROBING` | probe request only | addr2 |

Broadcast and multicast addresses are ignored. `RandomMAC=yes` means the
locally-administered bit is set (a randomized MAC on phones).

### Coordinates

A device's point is the GPS sample (within ±10 s) at the moment of its
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
