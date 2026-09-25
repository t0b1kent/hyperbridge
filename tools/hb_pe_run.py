#!/usr/bin/env python3
"""hb_pe_run.py — HyperBridge PE execution runner CLI.

Loads a PE file, extracts the entry point bytes, and runs them through
the in-process interpreter for the MVP subset.
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from hb_run import run_x64, run_x86


def parse_pe(data):
    """Parse minimal PE header and return metadata."""
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
    num_sections = struct.unpack('<H', data[coff+2:coff+4])[0]
    opt_size = struct.unpack('<H', data[coff+16:coff+18])[0]
    magic = struct.unpack('<H', data[coff+20:coff+22])[0]

    arch = "x64" if machine == 0x8664 else "x86" if machine == 0x014c else "unknown"
    is_pe32_plus = magic == 0x20b

    # Optional header starts at coff+20
    if is_pe32_plus and coff + 20 + 108 + 8 <= len(data):
        image_base = struct.unpack('<Q', data[coff+44:coff+52])[0]
        entry_point = struct.unpack('<I', data[coff+36:coff+40])[0]
    elif magic == 0x10b and coff + 20 + 28 <= len(data):
        image_base = struct.unpack('<I', data[coff+48:coff+52])[0]
        entry_point = struct.unpack('<I', data[coff+36:coff+40])[0]
    else:
        return {"error": "unsupported optional header"}

    # Parse sections
    sec_header_offset = coff + 20 + opt_size
    sections = []
    for i in range(num_sections):
        soff = sec_header_offset + i * 40
        if soff + 40 > len(data):
            break
        sections.append({
            "name": data[soff:soff+8].split(b'\x00')[0].decode('ascii', errors='ignore'),
            "virtual_size": struct.unpack('<I', data[soff+8:soff+12])[0],
            "virtual_address": struct.unpack('<I', data[soff+12:soff+16])[0],
            "size_of_raw_data": struct.unpack('<I', data[soff+16:soff+20])[0],
            "pointer_to_raw_data": struct.unpack('<I', data[soff+20:soff+24])[0],
            "characteristics": struct.unpack('<I', data[soff+36:soff+40])[0],
        })

    return {
        "arch": arch,
        "machine": machine,
        "is_pe32_plus": is_pe32_plus,
        "image_base": image_base,
        "entry_point_rva": entry_point,
        "entry_point_va": image_base + entry_point,
        "sections": sections,
    }


def find_entry_section(pe_info):
    """Find the section containing the entry point RVA."""
    ep = pe_info["entry_point_rva"]
    for sec in pe_info["sections"]:
        va = sec["virtual_address"]
        vs = sec["virtual_size"]
        if va <= ep < va + vs:
            return sec
    return None


def extract_entry_bytes(data, pe_info):
    """Extract raw bytes at the entry point from the PE file."""
    sec = find_entry_section(pe_info)
    if not sec:
        return None, "entry point not in any section"
    ep_rva = pe_info["entry_point_rva"]
    raw_off = sec["pointer_to_raw_data"] + (ep_rva - sec["virtual_address"])
    raw_size = sec["size_of_raw_data"] - (ep_rva - sec["virtual_address"])
    if raw_off >= len(data):
        return None, "entry point offset beyond file"
    end = min(raw_off + raw_size, len(data))
    return data[raw_off:end], None


def run_pe_file(path, backend="interp"):
    with open(path, "rb") as f:
        data = f.read()

    pe_info = parse_pe(data)
    if "error" in pe_info:
        return {"status": "ERROR", "reason": pe_info["error"]}

    if pe_info["arch"] not in ("x64", "x86"):
        return {"status": "UNSUPPORTED", "reason": f"machine 0x{pe_info['machine']:04x} not supported"}

    entry_bytes, err = extract_entry_bytes(data, pe_info)
    if err:
        return {"status": "ERROR", "reason": err}

    entry_va = pe_info["entry_point_va"]

    if pe_info["arch"] == "x64":
        result = run_x64(entry_bytes, addr=entry_va)
    else:
        result = run_x86(entry_bytes, addr=entry_va)

    result["pe_info"] = pe_info
    return result


def main():
    parser = argparse.ArgumentParser(description="HyperBridge PE Runner")
    parser.add_argument("file", help="PE file path")
    parser.add_argument("--backend", choices=["interp", "jit", "aot"], default="interp")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--inspect-only", action="store_true", help="Only inspect PE, do not run")
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()

    pe_info = parse_pe(data)
    if "error" in pe_info:
        print(f"ERROR: {pe_info['error']}", file=sys.stderr)
        sys.exit(1)

    if args.inspect_only:
        if args.json:
            print(json.dumps(pe_info, indent=2))
        else:
            print(f"PE: {args.file}")
            print(f"  Arch: {pe_info['arch']} (machine=0x{pe_info['machine']:04x})")
            print(f"  ImageBase: 0x{pe_info['image_base']:016x}")
            print(f"  EntryPoint RVA: 0x{pe_info['entry_point_rva']:08x} (VA=0x{pe_info['entry_point_va']:016x})")
            print(f"  Sections ({len(pe_info['sections'])}):")
            for s in pe_info["sections"]:
                print(f"    {s['name']:<8} VA=0x{s['virtual_address']:08x} VS=0x{s['virtual_size']:08x} Raw=0x{s['pointer_to_raw_data']:08x} Size=0x{s['size_of_raw_data']:08x}")
        sys.exit(0)

    result = run_pe_file(args.file, backend=args.backend)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"PE: {args.file}")
        print(f"  Arch: {pe_info['arch']}")
        print(f"  EntryPoint: 0x{pe_info['entry_point_va']:016x}")
        print(f"  EntryBytes: {len(entry_bytes) if 'entry_bytes' in locals() else '?'} bytes")
        print(f"  Run: {result['status']} — {result['reason']} (steps={result.get('steps', 0)})")
        if result.get("regs"):
            for idx, val in sorted(result["regs"].items()):
                if pe_info["arch"] == "x86":
                    names = ["eax","ecx","edx","ebx","esp","ebp","esi","edi","eip"]
                else:
                    names = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                             "r8","r9","r10","r11","r12","r13","r14","r15","rip"]
                if idx < len(names):
                    print(f"    {names[idx]} = 0x{val:08x}" if pe_info["arch"] == "x86" else f"    {names[idx]} = 0x{val:016x}")
        if result.get("flags"):
            f = result["flags"]
            print(f"    flags: ZF={f['zf']} SF={f['sf']} CF={f['cf']} OF={f['of']}")


if __name__ == "__main__":
    main()
