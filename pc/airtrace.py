#!/usr/bin/env python3
"""
AirTrace - classify 802.11 devices from a Pager capture and geotag them.

Input  (one session folder written by pager/airtrace/payload.sh):
    capture.pcap   raw monitor-mode capture (radiotap); .pcapng also works
    gps.log        GPS_GET samples: "<pager epoch> <lat> <lon> <alt> <speed>"
                   (older sessions: gps.nmea with RMC sentences, optionally
                   prefixed with the Pager's time: "<epoch> $GPRMC,...")

Output (written into the same folder):
    devices-<date>.csv   one row per MAC
    devices-<date>.html  interactive map: click an AP to see its clients,
                         probing devices grouped into counted clusters
    devices-<date>.kml   three layers (AP / ASSOCIATED / PROBING)
    track-<date>.csv     GPS track, one point per second

Requires: Python 3 and Scapy (pip install scapy).

Classification per MAC, highest rank wins:
    AP          beacon / probe response, MAC = BSSID (addr3)
    ASSOCIATED  data frame or (re)association request, client MAC
    PROBING     probe request only, MAC = addr2
Broadcast and multicast addresses are ignored.

Location of a device = RSSI-weighted average of the GPS points where its own
frames were strongest (within LOC_WINDOW_DB of its best signal). Only frames
the device transmitted count: RSSI of a frame belongs to its sender.

Vendor names come from Scapy's OUI database (falls back to Wireshark's manuf
or /usr/share/ieee-data/oui.txt). Randomized MACs have no vendor.
"""

import argparse
import bisect
import csv
import glob
import html
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import reduce

from scapy.config import conf
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap
from scapy.utils import PcapReader

MAX_FIX_DELTA_S = 10          # packet is matched to the nearest fix within this
TRACK_INTERVAL_S = 1.0        # track resolution
CLOCK_SKEW_MIN_S = 2          # apply Pager-clock correction above this skew
LOC_WINDOW_DB = 10            # GPS points within this many dB of the best one
                              # are averaged into the device location

RANK = {"PROBING": 1, "ASSOCIATED": 2, "AP": 3}
KML_COLOR = {                 # KML uses aabbggrr
    "AP": "ff0000ff",         # red
    "ASSOCIATED": "ff00ff00", # green
    "PROBING": "ffff8000",    # blue-ish
}
CSV_HEADER = [
    "MAC", "Type", "Vendor", "RandomMAC", "SSID/Probed", "Security", "Channel", "Band",
    "ConnectedBSSID", "FirstSeenUTC", "LastSeenUTC", "Packets", "BestRSSI",
    "Lat", "Lon", "LocPoints",
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


_OUI = None


def _load_oui_files():
    """Fallback vendor table from Wireshark / ieee-data, {'AABBCC': vendor}."""
    table = {}
    for path in ("/usr/share/wireshark/manuf", "/usr/share/ieee-data/oui.txt"):
        if not os.path.exists(path):
            continue
        with open(path, errors="replace") as fh:
            for line in fh:
                if path.endswith("manuf"):
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) >= 2 and len(parts[0]) == 8:
                        table[parts[0].replace(":", "").upper()] = parts[-1].strip()
                elif "(hex)" in line:
                    prefix, _, name = line.partition("(hex)")
                    table[prefix.strip().replace("-", "").upper()] = name.strip()
        if table:
            break
    return table


_VENDOR_NOISE = re.compile(
    r"\b(technologies|technology|corporation|corporate|corp|company|co|ltd|limited|inc|"
    r"incorporated|llc|gmbh|ag|sa|srl|bv|plc|electronics|trading|foundation|"
    r"international|communication|communications|telecom|mobile)\b\.?", re.I)


def short_vendor(name):
    """'Tp-Link Technologies Co.,Ltd.' -> 'Tp-Link'."""
    short = _VENDOR_NOISE.sub("", name.split(",")[0])
    short = re.sub(r"[\s.,]+$", "", re.sub(r"\s{2,}", " ", short)).strip()
    return short or name


def vendor_of(mac):
    """Manufacturer for a globally assigned MAC, '' if unknown or randomized."""
    global _OUI
    if is_random_mac(mac):
        return ""
    try:
        name = conf.manufdb._get_manuf(mac)
        if name and name.lower() != mac.lower():
            return short_vendor(name)
    except Exception:
        pass
    if _OUI is None:
        _OUI = _load_oui_files()
    return short_vendor(_OUI.get(mac.replace(":", "")[:6].upper(), "")) if _OUI else ""


def security_label(crypto):
    """Scapy network_stats() crypto set -> 'Open', 'WEP', 'WPA2', 'WPA3', ..."""
    s = " ".join(sorted(crypto or ()))
    if not s:
        return ""
    if "OWE" in s:
        return "OWE"
    if "WPA3-transition" in s or ("SAE" in s and "PSK" in s):
        base = "WPA2/WPA3"
    elif "WPA3" in s or "SAE" in s:
        base = "WPA3"
    elif "WPA2" in s and "WPA/" in s:
        base = "WPA/WPA2"
    elif "WPA2" in s:
        base = "WPA2"
    elif s.startswith("WPA"):
        base = "WPA"
    elif "WEP" in s:
        return "WEP"
    elif "OPN" in s:
        return "Open"
    else:
        return s
    return base + ("-Enterprise" if "802.1X" in s else "")


def band_channel(freq, channel):
    """(band, channel) from radiotap frequency (MHz) and/or DS channel."""
    band = ""
    if freq:
        if 2400 <= freq <= 2500:
            band, ch = "2.4", (14 if freq == 2484 else (freq - 2407) // 5)
        elif 4900 <= freq < 5925:
            band, ch = "5", (freq - 5000) // 5
        elif 5925 <= freq <= 7125:
            band, ch = "6", (freq - 5950) // 5
        else:
            ch = None
        if band == "6" or not channel:
            channel = ch
    if not band and channel:
        band = "2.4" if channel <= 14 else "5"
    return band, channel


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


def parse_gpslog(line):
    """'<epoch> <lat> <lon> [alt] [speed]' -> (epoch, lat, lon, speed), or None."""
    parts = line.split()
    if len(parts) < 3:
        return None
    try:
        epoch, lat, lon = float(parts[0]), float(parts[1]), float(parts[2])
        speed = float(parts[4]) if len(parts) > 4 else 0.0
    except ValueError:
        return None
    if (lat == 0 and lon == 0) or not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return epoch, lat, lon, speed


def load_gpslog(path):
    """Track from gps.log. Times are Pager clock = pcap clock, so no offset."""
    points = []
    with open(path, errors="replace") as fh:
        for line in fh:
            fix = parse_gpslog(line)
            if fix:
                points.append(fix)
    return thin_track(points)


def thin_track(points):
    points.sort(key=lambda p: p[0])
    thinned, last = [], None
    for p in points:
        if last is None or p[0] - last >= TRACK_INTERVAL_S:
            thinned.append(p)
            last = p[0]
    return thinned


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
    offset = statistics.median(offsets) if offsets else 0.0
    return thin_track(points), offset


class Geo:
    def __init__(self, track):
        self.track = track
        self.times = [p[0] for p in track]

    def fix_for(self, epoch):
        """Nearest GPS point (lat, lon) within MAX_FIX_DELTA_S, or None."""
        i = self.index_for(epoch)
        return None if i is None else (self.track[i][1], self.track[i][2])

    def index_for(self, epoch):
        """Index of the nearest track point within MAX_FIX_DELTA_S, or None."""
        if not self.times:
            return None
        i = bisect.bisect_left(self.times, epoch)
        best = None
        for j in (i - 1, i):
            if 0 <= j < len(self.times):
                if best is None or abs(self.times[j] - epoch) < abs(self.times[best] - epoch):
                    best = j
        if best is not None and abs(self.times[best] - epoch) <= MAX_FIX_DELTA_S:
            return best
        return None

    def locate(self, samples):
        """
        samples: {track index: best RSSI there}. RSSI-weighted average of the
        points within LOC_WINDOW_DB of the best one. Returns (lat, lon, n).
        """
        if not samples:
            return None
        best = max(samples.values())
        lat = lon = wsum = 0.0
        n = 0
        for i, r in samples.items():
            if r < best - LOC_WINDOW_DB:
                continue
            w = 10 ** ((r - best) / 10.0)        # linear power, best point = 1
            lat += w * self.track[i][1]
            lon += w * self.track[i][2]
            wsum += w
            n += 1
        return lat / wsum, lon / wsum, n


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
    __slots__ = ("kinds", "ssids", "probed", "bssids", "packets", "first", "last",
                 "best_rssi", "samples", "coord", "security", "channel", "band")

    def __init__(self):
        self.kinds = Counter()
        self.ssids = Counter()
        self.probed = set()
        self.bssids = Counter()
        self.packets = 0
        self.first = None
        self.last = None
        self.best_rssi = None     # strongest own frame, reported in CSV
        self.samples = {}         # track index -> strongest own RSSI there
        self.coord = None         # (lat, lon, points used), set after the scan
        self.security = None      # APs: from the first beacon / probe response
        self.channel = None
        self.band = ""

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
            fix_idx = None
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
                    if dev.security is None and is_tx:
                        ap_details(pkt, dev)
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
                    fix_idx, fix_looked_up = geo.index_for(epoch), True
                if fix_idx is not None and rssi > dev.samples.get(fix_idx, -999):
                    dev.samples[fix_idx] = rssi
    for dev in devices.values():
        dev.coord = geo.locate(dev.samples)
        dev.samples = None                        # free memory
    return devices


def ap_details(pkt, dev):
    """Security, channel and band from a beacon / probe response."""
    layer = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
    if layer is None:
        return
    try:
        stats = layer.network_stats()
    except Exception:
        stats = {}
    dev.security = security_label(stats.get("crypto"))
    rt = pkt.getlayer(RadioTap)
    freq = getattr(rt, "ChannelFrequency", None) if rt is not None else None
    dev.band, dev.channel = band_channel(freq, stats.get("channel"))


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
    points = ""
    if dev.coord:
        lat, lon, points = f"{dev.coord[0]:.6f}", f"{dev.coord[1]:.6f}", dev.coord[2]

    is_ap = kind == "AP"
    return {
        "MAC": mac,
        "Type": kind,
        "Vendor": vendor_of(mac),
        "RandomMAC": "yes" if is_random_mac(mac) else "no",
        "SSID/Probed": ssid_or_probed,
        "Security": (dev.security or "") if is_ap else "",
        "Channel": (dev.channel or "") if is_ap else "",
        "Band": dev.band if is_ap else "",
        "ConnectedBSSID": connected,
        "FirstSeenUTC": utc_str(dev.first),
        "LastSeenUTC": utc_str(dev.last),
        "Packets": dev.packets,
        "BestRSSI": dev.best_rssi if dev.best_rssi is not None else "",
        "Lat": lat,
        "Lon": lon,
        "LocPoints": points,
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
                   f"<scale>0.7</scale></IconStyle>"
                   f"<LabelStyle><scale>0</scale></LabelStyle></Style>")   # no MAC labels
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


MAP_TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "map_template.html")
MAX_TRACK_POINTS = 5000


def write_html(path, rows, track, title):
    """Interactive Leaflet map (needs internet for map tiles and Leaflet)."""
    devices = []
    for r in rows:
        kind = r["Type"]
        devices.append({
            "mac": r["MAC"],
            "type": kind,
            "vendor": r["Vendor"],
            "rnd": r["RandomMAC"] == "yes",
            "sec": r["Security"],
            "ch": r["Channel"],
            "band": r["Band"],
            "locn": r["LocPoints"] or 0,
            "ssid": r["SSID/Probed"] if kind == "AP" else "",
            "probed": r["SSID/Probed"].split("; ") if kind == "PROBING" and r["SSID/Probed"] else [],
            "bssid": r["ConnectedBSSID"],
            "first": r["FirstSeenUTC"],
            "last": r["LastSeenUTC"],
            "pkts": r["Packets"],
            "rssi": r["BestRSSI"] if r["BestRSSI"] != "" else None,
            "lat": float(r["Lat"]) if r["Lat"] else None,
            "lon": float(r["Lon"]) if r["Lon"] else None,
        })
    step = max(1, len(track) // MAX_TRACK_POINTS)
    pts = [[round(p[1], 6), round(p[2], 6)] for p in track[::step]]
    data = json.dumps({"title": title, "devices": devices, "track": pts},
                      ensure_ascii=False, separators=(",", ":"))
    data = data.replace("</", "<\\/")          # keep </script> inside SSIDs harmless
    with open(MAP_TEMPLATE, encoding="utf-8") as fh:
        page = fh.read()
    page = page.replace("__TITLE__", html.escape(title)).replace("__DATA__", data)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)


# ------------------------------------------------------------------- main --

def main():
    ap = argparse.ArgumentParser(prog="airtrace", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("session", help="session folder from the Pager (loot/<name>)")
    ap.add_argument("--no-clock-fix", action="store_true",
                    help="(gps.nmea sessions only) do not correct pcap timestamps "
                         "by the Pager-vs-GPS clock offset")
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
    gpslog = os.path.join(session, "gps.log")
    if os.path.exists(gpslog):
        track, offset = load_gpslog(gpslog), 0.0
    else:
        track, offset = load_track(os.path.join(session, "gps.nmea"))
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
    write_html(base + ".html", rows, track, f"AirTrace {stamp}")
    if track:
        write_track_csv(os.path.join(session, f"track-{stamp}.csv"), track)

    counts = Counter(r["Type"] for r in rows)
    located = sum(1 for r in rows if r["Lat"])
    print(f"devices: {len(rows)}  AP={counts['AP']}  "
          f"ASSOCIATED={counts['ASSOCIATED']}  PROBING={counts['PROBING']}  "
          f"geotagged={located}")
    print(f"wrote: {base}.html, {base}.csv, {base}.kml" +
          (f", track-{stamp}.csv" if track else ""))
    print(f"open the map: xdg-open '{base}.html'")


if __name__ == "__main__":
    main()
