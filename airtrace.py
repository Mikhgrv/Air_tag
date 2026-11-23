#!/usr/bin/env python3
"""
AirTrace - classify 802.11 devices from a Pager capture and geotag them.

Input  (one session folder written by payload/payload.sh):
    capture.pcap   raw monitor-mode capture (radiotap); .pcapng also works
    gps.nmea       RMC sentences from the Pager's GPS, optionally prefixed
                   with the Pager's system time: "<epoch> $GPRMC,..."

Output (written into the same folder):
    devices-<date>.csv   one row per MAC
    devices-<date>.kml   three layers (AP / ASSOCIATED / PROBING)
    track-<date>.csv     GPS track, one point per second

Requires: Python 3 and Scapy (pip install scapy).

Classification per MAC, highest rank wins:
    AP          beacon / probe response, MAC = BSSID (addr3)
    ASSOCIATED  data frame or (re)association request, client MAC
    PROBING     probe request only, MAC = addr2
Broadcast and multicast addresses are ignored.

Location of a device = GPS fix at the moment of its strongest frame that
the device itself transmitted (RSSI of a frame belongs to its sender only).
"""

import argparse
import bisect
import csv
import glob
import html
import os
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import reduce

from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap
from scapy.utils import PcapReader

MAX_FIX_DELTA_S = 10          # packet is matched to the nearest fix within this
TRACK_INTERVAL_S = 1.0        # track resolution
CLOCK_SKEW_MIN_S = 2          # apply Pager-clock correction above this skew

RANK = {"PROBING": 1, "ASSOCIATED": 2, "AP": 3}
KML_COLOR = {                 # KML uses aabbggrr
    "AP": "ff0000ff",         # red
    "ASSOCIATED": "ff00ff00", # green
    "PROBING": "ffff8000",    # blue-ish
}
CSV_HEADER = [
    "MAC", "Type", "RandomMAC", "SSID/Probed", "ConnectedBSSID",
    "FirstSeenUTC", "LastSeenUTC", "Packets", "BestRSSI", "Lat", "Lon",
]


# ----------------------------------------------------------------- helpers --

def utc_str(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def is_group_address(mac):
    """Broadcast/multicast: LSB of the first octet is set."""
    return int(mac.split(":")[0], 16) & 0x01 == 1


def is_random_mac(mac):
    """Locally administered bit (0x02) set in the first octet."""
    return int(mac.split(":")[0], 16) & 0x02 == 2


def ssid_of(pkt):
    """
    Return the SSID tagged parameter (element ID 0), or None if absent.
    A hidden SSID (empty or all NUL bytes) is returned as "".
    """
    layer = pkt.getlayer(Dot11Elt)
    while isinstance(layer, Dot11Elt):
        if layer.ID == 0:
            raw = bytes(layer.info or b"")
            if not raw.strip(b"\x00"):
                return ""
            return raw.decode("utf-8", errors="replace")
        layer = layer.payload
    return None


def rssi_of(pkt):
    rt = pkt.getlayer(RadioTap)
    if rt is None:
        return None
    value = getattr(rt, "dBm_AntSignal", None)
    return int(value) if value is not None else None


# ------------------------------------------------------------------- GPS --

def nmea_checksum_ok(sentence):
    """sentence = '$...*hh'. Verify the XOR checksum."""
    body, _, given = sentence[1:].partition("*")
    try:
        want = int(given[:2], 16)
    except ValueError:
        return False
    return reduce(lambda acc, ch: acc ^ ord(ch), body, 0) == want


def parse_rmc(line):
    """
    Return (gps_epoch, lat, lon, speed_kn, sys_epoch) for a valid RMC fix,
    else None. sys_epoch is the Pager's clock when the line was logged, or
    None if the line has no prefix.
    """
    line = line.strip()
    sys_epoch = None
    if not line.startswith("$"):                     # "<epoch> $GPRMC,..."
        prefix, _, line = line.partition(" ")
        try:
            sys_epoch = float(prefix)
        except ValueError:
            return None
        line = line.strip()
    if not line.startswith("$") or "*" not in line or not nmea_checksum_ok(line):
        return None
    # fields: 0 GPRMC, 1 time, 2 status, 3 lat, 4 N/S, 5 lon, 6 E/W,
    #         7 speed(kn), 8 course, 9 date ddmmyy
    fields = line[1:line.index("*")].split(",")
    if len(fields) < 10 or not fields[0].endswith("RMC") or fields[2] != "A":
        return None
    try:
        t, d = fields[1], fields[9]
        stamp = datetime.strptime(d + t.split(".")[0], "%d%m%y%H%M%S")
        epoch = stamp.replace(tzinfo=timezone.utc).timestamp()

        lat = float(fields[3][:2]) + float(fields[3][2:]) / 60.0
        if fields[4] == "S":
            lat = -lat
        lon = float(fields[5][:3]) + float(fields[5][3:]) / 60.0
        if fields[6] == "W":
            lon = -lon
        speed = float(fields[7]) if fields[7] else 0.0
        return epoch, lat, lon, speed, sys_epoch
    except (ValueError, IndexError):
        return None


def load_track(nmea_path):
    """
    Parse the NMEA log and thin it to one point per second.
    Returns (track, clock_offset_s). clock_offset_s = GPS time - Pager time
    (median), or 0.0 if the log has no system-time prefix.
    """
    points, offsets = [], []
    if not os.path.exists(nmea_path):
        return points, 0.0
    with open(nmea_path, errors="replace") as fh:
        for line in fh:
            fix = parse_rmc(line)
            if fix:
                points.append(fix[:4])
                if fix[4] is not None:
                    offsets.append(fix[0] - fix[4])
    points.sort(key=lambda p: p[0])
    thinned, last = [], None
    for p in points:
        if last is None or p[0] - last >= TRACK_INTERVAL_S:
            thinned.append(p)
            last = p[0]
    offset = statistics.median(offsets) if offsets else 0.0
    return thinned, offset


class Geo:
    def __init__(self, track):
        self.track = track
        self.times = [p[0] for p in track]

    def fix_for(self, epoch):
        """Nearest GPS point within MAX_FIX_DELTA_S, or None."""
        if not self.times:
            return None
        i = bisect.bisect_left(self.times, epoch)
        best = None
        for j in (i - 1, i):
            if 0 <= j < len(self.times):
                if best is None or abs(self.times[j] - epoch) < abs(self.times[best] - epoch):
                    best = j
        if best is not None and abs(self.times[best] - epoch) <= MAX_FIX_DELTA_S:
            return self.track[best][1], self.track[best][2]
        return None


# --------------------------------------------------------- classification --

def candidates(pkt):
    """
    Yield (mac, kind, extra, is_tx) tuples for one frame.
    extra: SSID for AP/PROBING, BSSID for ASSOCIATED.
    is_tx: True if `mac` transmitted this frame (so the RSSI is its signal).
    """
    d11 = pkt[Dot11]
    ftype, subtype = d11.type, d11.subtype
    fc = int(d11.FCfield)
    to_ds, from_ds = fc & 0x01, fc & 0x02

    if ftype == 0:                                   # management
        if subtype in (8, 5):                        # beacon, probe response
            ssid = ssid_of(pkt)
            yield d11.addr3, "AP", ssid or "", d11.addr2 == d11.addr3
        elif subtype == 4:                           # probe request
            ssid = ssid_of(pkt)
            yield d11.addr2, "PROBING", ssid if ssid else "(wildcard)", True
        elif subtype in (0, 2):                      # (re)association request
            yield d11.addr2, "ASSOCIATED", d11.addr3, True

    elif ftype == 2:                                 # data
        if to_ds and not from_ds:                    # client -> AP
            yield d11.addr2, "ASSOCIATED", d11.addr1, True
        elif from_ds and not to_ds:                  # AP -> client
            yield d11.addr1, "ASSOCIATED", d11.addr2, False


class Device:
    __slots__ = ("kinds", "ssids", "probed", "bssids", "packets",
                 "first", "last", "best_rssi", "geo_rssi", "best_coord")

    def __init__(self):
        self.kinds = Counter()
        self.ssids = Counter()
        self.probed = set()
        self.bssids = Counter()
        self.packets = 0
        self.first = None
        self.last = None
        self.best_rssi = None     # strongest own frame, reported in CSV
        self.geo_rssi = None      # strongest own frame that had a GPS fix
        self.best_coord = None

    def rank_kind(self):
        return max(self.kinds, key=lambda k: RANK[k])


def scan(pcap_path, geo, clock_offset=0.0):
    devices = defaultdict(Device)
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(Dot11):
                continue
            epoch = float(pkt.time) + clock_offset
            rssi = rssi_of(pkt)
            fix = None
            fix_looked_up = False
            for mac, kind, extra, is_tx in candidates(pkt):
                if not mac or is_group_address(mac):
                    continue
                dev = devices[mac]
                dev.kinds[kind] += 1
                dev.packets += 1
                dev.first = epoch if dev.first is None else min(dev.first, epoch)
                dev.last = epoch if dev.last is None else max(dev.last, epoch)

                if kind == "AP":
                    if extra:
                        dev.ssids[extra] += 1
                elif kind == "PROBING":
                    dev.probed.add(extra)
                elif kind == "ASSOCIATED":
                    if extra and not is_group_address(extra):
                        dev.bssids[extra] += 1

                if not is_tx or rssi is None:
                    continue
                if dev.best_rssi is None or rssi > dev.best_rssi:
                    dev.best_rssi = rssi
                if not fix_looked_up:
                    fix, fix_looked_up = geo.fix_for(epoch), True
                if fix and (dev.geo_rssi is None or rssi > dev.geo_rssi):
                    dev.geo_rssi = rssi
                    dev.best_coord = fix          # coord at strongest moment
    return devices


# ----------------------------------------------------------------- output --

def row_for(mac, dev):
    kind = dev.rank_kind()
    ssid_or_probed = ""
    connected = ""
    if kind == "AP":
        ssid_or_probed = dev.ssids.most_common(1)[0][0] if dev.ssids else "(hidden)"
    elif kind == "PROBING":
        ssid_or_probed = "; ".join(sorted(dev.probed))
    elif kind == "ASSOCIATED":
        connected = dev.bssids.most_common(1)[0][0] if dev.bssids else ""

    lat = lon = ""
    if dev.best_coord:
        lat, lon = f"{dev.best_coord[0]:.6f}", f"{dev.best_coord[1]:.6f}"

    return {
        "MAC": mac,
        "Type": kind,
        "RandomMAC": "yes" if is_random_mac(mac) else "no",
        "SSID/Probed": ssid_or_probed,
        "ConnectedBSSID": connected,
        "FirstSeenUTC": utc_str(dev.first),
        "LastSeenUTC": utc_str(dev.last),
        "Packets": dev.packets,
        "BestRSSI": dev.best_rssi if dev.best_rssi is not None else "",
        "Lat": lat,
        "Lon": lon,
    }


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_HEADER)
        w.writeheader()
        w.writerows(rows)


def write_track_csv(path, track):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["time_utc", "lat", "lon", "speed_kn"])
        for epoch, lat, lon, speed in track:
            w.writerow([utc_str(epoch), f"{lat:.6f}", f"{lon:.6f}", f"{speed:.2f}"])


def write_kml(path, rows, title):
    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>',
        f"<name>{html.escape(title)}</name>",
    ]
    for kind in ("AP", "ASSOCIATED", "PROBING"):
        out.append(f"<Style id='{kind}'><IconStyle><color>{KML_COLOR[kind]}</color>"
                   f"<scale>0.7</scale></IconStyle></Style>")
    for kind in ("AP", "ASSOCIATED", "PROBING"):
        layer = [r for r in rows if r["Type"] == kind and r["Lat"] and r["Lon"]]
        out.append(f"<Folder><name>{kind} ({len(layer)})</name>")
        for r in layer:
            desc = "<br/>".join(f"{k}: {html.escape(str(v))}" for k, v in r.items()
                                if k not in ("Lat", "Lon"))
            out.append(
                "<Placemark>"
                f"<name>{html.escape(r['MAC'])}</name>"
                f"<description><![CDATA[{desc}]]></description>"
                f"<styleUrl>#{kind}</styleUrl>"
                f"<Point><coordinates>{r['Lon']},{r['Lat']},0</coordinates></Point>"
                "</Placemark>"
            )
        out.append("</Folder>")
    out.append("</Document></kml>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))


# ------------------------------------------------------------------- main --

def main():
    ap = argparse.ArgumentParser(prog="airtrace", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("session", help="session folder from the Pager (loot/<name>)")
    ap.add_argument("--no-clock-fix", action="store_true",
                    help="do not correct pcap timestamps by the Pager-vs-GPS clock offset")
    args = ap.parse_args()

    session = os.path.abspath(args.session)
    pcaps = sorted(glob.glob(os.path.join(session, "*.pcap")) +
                   glob.glob(os.path.join(session, "*.pcapng")))
    if not pcaps:
        sys.exit(f"no .pcap/.pcapng in {session}")
    if len(pcaps) > 1:
        print(f"warning: several captures found, using {os.path.basename(pcaps[0])}",
              file=sys.stderr)
    pcap = pcaps[0]
    nmea = os.path.join(session, "gps.nmea")

    track, offset = load_track(nmea)
    if not track:
        print("warning: no valid GPS fixes; coordinates will be empty", file=sys.stderr)
    if args.no_clock_fix or abs(offset) < CLOCK_SKEW_MIN_S:
        offset = 0.0
    else:
        print(f"Pager clock is off by {offset:+.0f} s vs GPS; correcting pcap timestamps")
    geo = Geo(track)

    print(f"scanning {os.path.basename(pcap)} ...")
    devices = scan(pcap, geo, offset)

    rows = [row_for(mac, dev) for mac, dev in devices.items()]
    rows.sort(key=lambda r: (RANK[r["Type"]] * -1, r["MAC"]))

    stamp = (utc_str(track[0][0])[:10] if track
             else datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    base = os.path.join(session, f"devices-{stamp}")
    write_csv(base + ".csv", rows)
    write_kml(base + ".kml", rows, f"AirTrace {stamp}")
    if track:
        write_track_csv(os.path.join(session, f"track-{stamp}.csv"), track)

    counts = Counter(r["Type"] for r in rows)
    located = sum(1 for r in rows if r["Lat"])
    print(f"devices: {len(rows)}  AP={counts['AP']}  "
          f"ASSOCIATED={counts['ASSOCIATED']}  PROBING={counts['PROBING']}  "
          f"geotagged={located}")
    print(f"wrote: {base}.csv, {base}.kml" + (f", track-{stamp}.csv" if track else ""))


if __name__ == "__main__":
    main()
