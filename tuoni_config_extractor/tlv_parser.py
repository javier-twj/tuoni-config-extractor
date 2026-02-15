"""TLV (Type-Length-Value) parser for Tuoni C2 protocol.

Wire format
-----------
Each TLV entry is encoded as:
  - Type:   1 byte — bit 7 (0x80) = parent flag; bits 0–6 = type ID.
  - Length: 4 bytes — unsigned 32-bit little-endian integer.
  - Value:  <Length> bytes.
"""

import struct
from typing import Any, Optional

from .tlv_maps import TLV_CHILD_MAPS, TOP_LEVEL_TLV_NAMES


class TLVEntry:
    def __init__(
        self,
        type_id: int,
        is_parent: bool,
        data: bytes,
        children: Optional[list["TLVEntry"]] = None,
    ) -> None:
        self.type_id = type_id
        self.is_parent = is_parent
        self.data = data
        self.children = children or []

    def total_size(self) -> int:
        if not self.is_parent:
            return 5 + len(self.data)
        else:
            child_size = sum(c.total_size() for c in self.children)
            return 5 + child_size

    def __repr__(self) -> str:
        if self.is_parent:
            return (
                f"TLV(id=0x{self.type_id:02X}, PARENT, children={len(self.children)})"
            )
        return f"TLV(id=0x{self.type_id:02X}, data_len={len(self.data)})"


# Wire format per https://docs.shelldot.com/InsideView/Protocols/TLV.html
def parse_tlv(
    data: bytes, offset: int = 0, length: Optional[int] = None
) -> list[TLVEntry]:
    """Parse TLV entries from binary data."""
    if length is None:
        length = len(data) - offset
    entries = []
    pos = 0
    while pos < length:
        if pos + 5 > length:
            break
        type_byte = data[offset + pos]
        value_len = struct.unpack_from("<I", data, offset + pos + 1)[0]
        if pos + 5 + value_len > length:
            break
        is_parent = bool(type_byte & 0x80)
        type_id = type_byte & 0x7F
        value_data = data[offset + pos + 5 : offset + pos + 5 + value_len]
        if is_parent:
            children = parse_tlv(value_data, 0, len(value_data))
            entry = TLVEntry(type_id, True, value_data, children)
        else:
            entry = TLVEntry(type_id, False, value_data)
        entries.append(entry)
        pos += 5 + value_len
    return entries


def format_value(data: bytes, type_id: int, max_hex: int = 64) -> str:
    """Format a TLV value for display."""
    if len(data) == 0:
        return "<empty>"
    if len(data) == 1:
        return f"0x{data[0]:02X} ({data[0]})"
    if len(data) == 2:
        val = struct.unpack("<H", data)[0]
        return f"0x{val:04X} ({val})"
    if len(data) == 4:
        val = struct.unpack("<I", data)[0]
        return f"0x{val:08X} ({val})"
    if len(data) == 16 and type_id in (0x01, 0x02):
        # Possibly a GUID
        try:
            import uuid

            u = uuid.UUID(bytes_le=data)
            return str(u)
        except Exception:
            pass
    # Try UTF-8 string
    try:
        text = data.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in text):
            return f'"{text}"'
    except (UnicodeDecodeError, ValueError):
        pass
    # Hex dump
    hex_str = data.hex()
    if len(hex_str) > max_hex:
        return f"{hex_str[:max_hex]}... ({len(data)} bytes)"
    return f"{hex_str} ({len(data)} bytes)"


def print_tlv_tree(
    entries: list[TLVEntry], indent: int = 0, parent_id: Optional[int] = None
) -> None:
    """Pretty-print a TLV tree."""
    prefix = "  " * indent
    child_name_map = TLV_CHILD_MAPS.get(parent_id, {}) if parent_id is not None else {}
    for entry in entries:
        name = ""
        if parent_id is None:
            name = TOP_LEVEL_TLV_NAMES.get(entry.type_id, "")
        else:
            name = child_name_map.get(entry.type_id, "")
        if name:
            name = f" [{name}]"
        if entry.is_parent:
            print(
                f"{prefix}├─ TLV 0x{entry.type_id:02X} (PARENT, {len(entry.children)} children){name}"
            )
            print_tlv_tree(entry.children, indent + 1, entry.type_id)
        else:
            val_str = format_value(entry.data, entry.type_id)
            print(f"{prefix}├─ TLV 0x{entry.type_id:02X}: {val_str}{name}")


def extract_tlv_summary(
    entries: list[TLVEntry], parent_id: Optional[int] = None
) -> dict[str, Any]:
    """Extract a summary dict of interesting fields from parsed TLV."""
    result: dict[str, Any] = {}
    for entry in entries:
        if entry.is_parent:
            key = f"0x{entry.type_id:02X}"
            name = (
                TOP_LEVEL_TLV_NAMES.get(entry.type_id, "") if parent_id is None else ""
            )
            if name:
                key = f"{key}_{name.replace(' ', '_')}"
            result[key] = extract_tlv_summary(entry.children, entry.type_id)
        else:
            key = f"0x{entry.type_id:02X}"
            child_map = (
                TLV_CHILD_MAPS.get(parent_id, {}) if parent_id is not None else {}
            )
            name = child_map.get(entry.type_id, "")
            if name:
                key = f"{key}_{name.replace(' ', '_').replace('/', '_')}"
            # Store raw value and interpretation
            if len(entry.data) <= 4 and len(entry.data) > 0:
                if len(entry.data) == 1:
                    result[key] = entry.data[0]
                elif len(entry.data) == 2:
                    result[key] = struct.unpack("<H", entry.data)[0]
                elif len(entry.data) == 4:
                    result[key] = struct.unpack("<I", entry.data)[0]
            else:
                try:
                    text = entry.data.decode("utf-8")
                    if all(c.isprintable() or c in "\r\n\t" for c in text):
                        result[key] = text
                    else:
                        result[key] = entry.data.hex()
                except (UnicodeDecodeError, ValueError):
                    result[key] = entry.data.hex()
    return result
