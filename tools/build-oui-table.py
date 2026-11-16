#!/usr/bin/env python3
"""Generate crates/sentinel-core/src/oui_table.bin from the IEEE registry.

Run offline, once, and commit the result. Sentinel must never fetch this at
runtime: it is an offline, privacy-sensitive device, and asking a third party
"who makes the device with this MAC?" would leak observed addresses to that
third party.

Source: the `ieee-data` package (/usr/share/ieee-data/oui.csv), which is the
IEEE MA-L registry. Falls back to any CSV given as argv[1].

Layout (little-endian):
    u32  count
    count x record, sorted ascending by oui:
        3 bytes  OUI
        u32      byte offset into the name blob
    name blob, each name NUL-terminated
"""
import csv, struct, sys, pathlib

src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/usr/share/ieee-data/oui.csv")
out = pathlib.Path(__file__).resolve().parent.parent / "crates/sentinel-core/src/oui_table.bin"

entries = {}
with src.open(encoding="utf-8", errors="replace", newline="") as fh:
    for row in csv.DictReader(fh):
        asn = (row.get("Assignment") or "").strip().upper()
        name = " ".join((row.get("Organization Name") or "").split())
        if len(asn) != 6 or not name:
            continue
        try:
            oui = bytes.fromhex(asn)
        except ValueError:
            continue
        # A handful of assignments are placeholders; they carry no information.
        if name.lower() in ("private", "ieee registration authority"):
            continue
        entries.setdefault(oui, name)

names, blob, offsets = {}, bytearray(), {}
for oui in sorted(entries):
    n = entries[oui]
    if n not in names:
        names[n] = len(blob)
        blob += n.encode("utf-8") + b"\0"
    offsets[oui] = names[n]

buf = bytearray(struct.pack("<I", len(offsets)))
for oui in sorted(offsets):
    buf += oui + struct.pack("<I", offsets[oui])
buf += blob

out.write_bytes(buf)
print(f"{len(offsets)} OUIs, {len(names)} distinct vendor names -> {out} ({len(buf)/1024:.0f} KB)")
