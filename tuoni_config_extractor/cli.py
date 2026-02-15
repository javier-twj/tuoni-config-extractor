"""CLI entry point for Tuoni C2 Config Extractor.

Workflow
--------
1. Load PE binary and extract TXT#104 resource.
2. Auto-detect A-P hex encoding (base 0x41) and decode.
3. Parse TLV structure per the official protocol spec.
4. Display fields using mappings from official docs and binary analysis.
"""

import json
import os
import struct
import sys

from .crypto import decrypt_config_blob
from .ioc import IOCCollector
from .pe_resources import (
    enumerate_resources,
    extract_pe_resource_txt104,
)
from .summary import print_c2_summary
from .tlv_parser import TLVEntry, extract_tlv_summary, parse_tlv, print_tlv_tree


def dump_shellcode_blobs(entries: list[TLVEntry], base_filename: str) -> int:
    """Extract and dump all shellcode blobs from TLV entries.

    Args:
        entries: Parsed TLV entries
        base_filename: Base filename for output (numbers inserted before extension)

    Returns:
        Number of shellcode blobs dumped
    """
    count = 0

    def extract_from_entry(entry: TLVEntry) -> None:
        nonlocal count
        # Look for Shellcode TLV (0x01, parent)
        if entry.type_id == 0x01 and entry.is_parent:
            for child in entry.children:
                # Find Shellcode Blob (0x03, not parent)
                if child.type_id == 0x03 and not child.is_parent:
                    count += 1
                    base, ext = os.path.splitext(base_filename)
                    filename = f"{base}_{count}{ext}"
                    with open(filename, "wb") as f:
                        f.write(child.data)
                    print(f"[+] Dumped {filename} ({len(child.data)} bytes)")

        # Recurse into children for nested TLVs
        if entry.is_parent:
            for child in entry.children:
                extract_from_entry(child)

    for entry in entries:
        extract_from_entry(entry)

    return count


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Tuoni C2 Config Extractor — Decrypt and parse embedded TLV configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s sample.exe
  %(prog)s sample.exe --dump-raw config_blob.bin
  %(prog)s sample.exe --json
        """,
    )
    parser.add_argument("binary", help="Path to Tuoni agent PE binary")
    parser.add_argument(
        "--dump-raw",
        metavar="FILE",
        help="Dump raw config blob (before decryption) to file",
    )
    parser.add_argument(
        "--dump-decrypted", metavar="FILE", help="Dump decrypted config blob to file"
    )
    parser.add_argument(
        "--dump-shellcode",
        metavar="FILE",
        help="Dump embedded shellcode blobs (numbers inserted before extension: output_1.bin, output_2.bin)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output parsed config as JSON"
    )
    parser.add_argument(
        "--list-resources", action="store_true", help="List all PE resources"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"[!] File not found: {args.binary}")
        sys.exit(1)

    with open(args.binary, "rb") as f:
        pe_data = f.read()

    print(f"[*] Loaded {args.binary} ({len(pe_data)} bytes)")

    # Check PE signature
    if pe_data[:2] != b"MZ":
        print("[!] Not a valid PE file (missing MZ header)")
        sys.exit(1)

    if args.list_resources:
        enumerate_resources(pe_data)

    # Extract config blob from PE resource TXT#104
    print()
    print("=== Config Blob Extraction ===")
    print("[*] Extracting from PE resource (TXT #104 / 0x68)")
    # TXT#104 resource: binary analysis (see pe_resources.py)
    blob = extract_pe_resource_txt104(pe_data)
    if blob:
        print(f"[+] Extracted {len(blob)} bytes from resource")
    else:
        print("[!] Failed to extract PE resource TXT#104")
        enumerate_resources(pe_data)

    if blob is None:
        print("[!] No config blob found, cannot continue")
        sys.exit(1)

    if args.dump_raw:
        with open(args.dump_raw, "wb") as f:
            f.write(blob)
        print(f"[+] Raw blob written to {args.dump_raw}")

    if args.verbose:
        print(f"[*] Raw blob preview: {blob[:64].hex()}...")

    # Decode
    print()
    print("=== Decoding ===")
    # A-P hex encoding (base 0x41): binary analysis (see crypto.py)
    decrypted = decrypt_config_blob(blob)

    if args.dump_decrypted:
        with open(args.dump_decrypted, "wb") as f:
            f.write(decrypted)
        print(f"[+] Decrypted blob written to {args.dump_decrypted}")

    # Parse TLV
    print()
    print("=== TLV Config Parsing ===")
    try:
        # TLV protocol: https://docs.shelldot.com/InsideView/Protocols/TLV.html
        entries = parse_tlv(decrypted)
        if not entries:
            print(
                "[!] No TLV entries parsed — blob may still be encrypted or corrupted"
            )
            print(f"[*] First 32 bytes: {decrypted[:32].hex()}")
            if len(decrypted) >= 5:
                type_byte = decrypted[0]
                length = struct.unpack_from("<I", decrypted, 1)[0]
                print(f"[*] First TLV attempt: type=0x{type_byte:02X}, length={length}")
                if length > len(decrypted):
                    print("[!] Length exceeds data — likely still encrypted")
        else:
            print(f"[+] Parsed {len(entries)} top-level TLV entries\n")
            print_tlv_tree(entries)

            if args.json:
                print()
                print("=== JSON Output ===")
                summary = extract_tlv_summary(entries)
                print(json.dumps(summary, indent=2, default=str))

            # Extract and display key C2 config info
            iocs = IOCCollector()
            print()
            print("=== C2 Configuration Summary ===")
            print_c2_summary(entries, iocs=iocs)

            # Print IOC summary
            print()
            print("=== IOC Summary ===")
            iocs.print_summary()

            # Dump shellcode blobs if requested
            if args.dump_shellcode:
                print()
                print("=== Shellcode Extraction ===")
                dumped = dump_shellcode_blobs(entries, args.dump_shellcode)
                if dumped == 0:
                    print("[*] No shellcode blobs found in config")
                else:
                    print(f"[+] Dumped {dumped} shellcode blob(s)")
    except Exception as e:
        print(f"[!] TLV parsing error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        print(f"[*] First 64 bytes of decrypted data: {decrypted[:64].hex()}")


if __name__ == "__main__":
    main()
