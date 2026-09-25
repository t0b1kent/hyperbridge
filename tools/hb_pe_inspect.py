#!/usr/bin/env python3
"""hb_pe_inspect.py — PE inspector CLI."""

import argparse
import struct
import sys
import json

def inspect_pe(data):
    if len(data) < 64:
        return {"error": "too small"}
    dos_magic = struct.unpack('<H', data[0:2])[0]
    if dos_magic != 0x5A4D:
        return {"error": "invalid DOS signature"}
    lfanew = struct.unpack('<I', data[60:64])[0]
    if lfanew + 24 > len(data):
        return {"error": "invalid e_lfanew"}
    nt_sig = struct.unpack('<I', data[lfanew:lfanew+4])[0]
    if nt_sig != 0x00004550:
        return {"error": "invalid NT signature"}
    coff = lfanew + 4
    machine = struct.unpack('<H', data[coff:coff+2])[0]
    sections = struct.unpack('<H', data[coff+2:coff+4])[0]
    opt_size = struct.unpack('<H', data[coff+16:coff+18])[0]
    magic = struct.unpack('<H', data[coff+20:coff+22])[0]
    result = {
        "dos_magic": "MZ",
        "nt_signature": "PE",
        "machine": f"0x{machine:04x}",
        "machine_name": "AMD64" if machine == 0x8664 else "I386" if machine == 0x014c else "UNKNOWN",
        "sections": sections,
        "optional_header_magic": f"0x{magic:04x}",
        "is_pe32_plus": magic == 0x20b,
    }
    # Optional header starts at coff+20
    # entry_point = opt+16, image_base = opt+24 (PE32+) or opt+28 (PE32)
    if magic == 0x20b and coff + 20 + 108 + 8 <= len(data):
        image_base = struct.unpack('<Q', data[coff+44:coff+52])[0]
        entry_point = struct.unpack('<I', data[coff+36:coff+40])[0]
        result["image_base"] = f"0x{image_base:016x}"
        result["entry_point"] = f"0x{entry_point:08x}"
        result["entry_point_rva"] = entry_point
        result["image_base_val"] = image_base
    elif magic == 0x10b and coff + 20 + 28 <= len(data):
        image_base = struct.unpack('<I', data[coff+48:coff+52])[0]
        entry_point = struct.unpack('<I', data[coff+36:coff+40])[0]
        result["image_base"] = f"0x{image_base:08x}"
        result["entry_point"] = f"0x{entry_point:08x}"
        result["entry_point_rva"] = entry_point
        result["image_base_val"] = image_base

    # Sections
    sec_header_offset = coff + 20 + opt_size
    result["sections"] = []
    for i in range(sections):
        soff = sec_header_offset + i * 40
        if soff + 40 > len(data):
            break
        s = {
            "name": data[soff:soff+8].split(b'\x00')[0].decode('ascii', errors='ignore'),
            "virtual_size": struct.unpack('<I', data[soff+8:soff+12])[0],
            "virtual_address": struct.unpack('<I', data[soff+12:soff+16])[0],
            "size_of_raw_data": struct.unpack('<I', data[soff+16:soff+20])[0],
            "pointer_to_raw_data": struct.unpack('<I', data[soff+20:soff+24])[0],
            "characteristics": struct.unpack('<I', data[soff+36:soff+40])[0],
        }
        result["sections"].append(s)
    return result

def main():
    parser = argparse.ArgumentParser(description="HyperBridge PE Inspector")
    parser.add_argument("file", help="PE file path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    with open(args.file, "rb") as f:
        data = f.read()
    result = inspect_pe(data)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for k, v in result.items():
            print(f"{k}: {v}")

if __name__ == "__main__":
    main()
