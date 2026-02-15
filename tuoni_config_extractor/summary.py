"""C2 configuration summary display and listener config extraction."""

import hashlib
import struct
from typing import Optional

from .ioc import IOCCollector
from .tlv_maps import (
    BINDSMB_LISTENER_FIELDS,
    BINDTCP_LISTENER_FIELDS,
    HTTP_ENDPOINT_FIELDS,
    HTTP_LISTENER_FIELDS,
    REVERSETCP_LISTENER_FIELDS,
    ROTATION_TYPE,
    ROTATION_UNIT,
)
from .tlv_parser import TLVEntry, format_value, parse_tlv


# Listener type heuristics: inferred from REST API fields per listener type
# https://docs.shelldot.com/REST/Listeners/HttpListener.html
# https://docs.shelldot.com/REST/Listeners/TcpReverseAgentListener.html
# https://docs.shelldot.com/REST/Listeners/RelayBindTCP.html
# https://docs.shelldot.com/REST/Listeners/RelayBindSMB.html
def _detect_listener_type(config_entries: list[TLVEntry]) -> str:
    """Detect listener type from parsed inner TLV of Shellcode Config (0x05).

    Returns one of: 'HTTP', 'HTTPS', 'REVERSETCP', 'BINDSMB', 'BINDTCP', 'UNKNOWN'
    """
    wrapper = None
    for e in config_entries:
        if e.is_parent and e.type_id == 0x01:
            wrapper = e
            break
    if wrapper is None:
        return "UNKNOWN"

    child_ids = {c.type_id for c in wrapper.children}

    # HTTP/HTTPS: has GET/POST path fields (0x03 + 0x04)
    if 0x03 in child_ids and 0x04 in child_ids:
        for c in wrapper.children:
            if c.type_id == 0x08 and not c.is_parent and len(c.data) >= 1:
                if c.data[0] == 1:
                    return "HTTPS"
        return "HTTP"

    # Bind types: exactly {0x01, 0x02} and only 2 children
    if child_ids == {0x01, 0x02} and len(wrapper.children) == 2:
        child_01 = next(c for c in wrapper.children if c.type_id == 0x01)
        if child_01.is_parent:
            return "UNKNOWN"
        if len(child_01.data) == 4:
            return "BINDTCP"
        try:
            text = child_01.data.decode("utf-8")
            if all(c.isprintable() for c in text):
                return "BINDSMB"
        except (UnicodeDecodeError, ValueError):
            pass
        return "BINDTCP"

    # ReverseTCP: has port (0x02) and flat 0x01 leaf entries (addresses)
    if 0x02 in child_ids:
        has_parent_01 = any(c.type_id == 0x01 and c.is_parent for c in wrapper.children)
        if not has_parent_01:
            return "REVERSETCP"

    return "UNKNOWN"


def _get_listener_field_map(listener_type: str) -> dict[int, str]:
    """Get the field name map for a given listener type."""
    return {
        "HTTP": HTTP_LISTENER_FIELDS,
        "HTTPS": HTTP_LISTENER_FIELDS,
        "REVERSETCP": REVERSETCP_LISTENER_FIELDS,
        "BINDSMB": BINDSMB_LISTENER_FIELDS,
        "BINDTCP": BINDTCP_LISTENER_FIELDS,
    }.get(listener_type, {})


# RSA public key is DER-encoded per https://docs.shelldot.com/InsideView/Protocols/Encryption.html
def _format_rsa_key(der_data: bytes) -> Optional[str]:
    """Parse DER-encoded RSA public key and return a summary string."""
    try:
        pos = 0
        if der_data[pos] != 0x30:
            return None
        pos += 1
        if der_data[pos] & 0x80:
            num_len_bytes = der_data[pos] & 0x7F
            pos += 1 + num_len_bytes
        else:
            pos += 1
        # Inner SEQUENCE (AlgorithmIdentifier) — skip it
        if der_data[pos] == 0x30:
            pos += 1
            if der_data[pos] & 0x80:
                num_len_bytes = der_data[pos] & 0x7F
                inner_len = int.from_bytes(
                    der_data[pos + 1 : pos + 1 + num_len_bytes], "big"
                )
                pos += 1 + num_len_bytes + inner_len
            else:
                inner_len = der_data[pos]
                pos += 1 + inner_len
        # BIT STRING
        if der_data[pos] != 0x03:
            return None
        pos += 1
        if der_data[pos] & 0x80:
            num_len_bytes = der_data[pos] & 0x7F
            pos += 1 + num_len_bytes
        else:
            pos += 1
        pos += 1  # skip unused bits byte
        # Inner SEQUENCE { INTEGER modulus, INTEGER exponent }
        if der_data[pos] != 0x30:
            return None
        pos += 1
        if der_data[pos] & 0x80:
            num_len_bytes = der_data[pos] & 0x7F
            pos += 1 + num_len_bytes
        else:
            pos += 1
        # INTEGER modulus
        if der_data[pos] != 0x02:
            return None
        pos += 1
        if der_data[pos] & 0x80:
            num_len_bytes = der_data[pos] & 0x7F
            mod_len = int.from_bytes(der_data[pos + 1 : pos + 1 + num_len_bytes], "big")
            pos += 1 + num_len_bytes
        else:
            mod_len = der_data[pos]
            pos += 1
        if der_data[pos] == 0x00:
            mod_data = der_data[pos + 1 : pos + mod_len]
            mod_len -= 1
        else:
            mod_data = der_data[pos : pos + mod_len]
        key_bits = mod_len * 8
        mod_hash = hashlib.sha256(mod_data).hexdigest()[:16]
        return f"{key_bits}-bit RSA, modulus SHA256: {mod_hash}..."
    except Exception:
        return None


def print_c2_summary(
    entries: list[TLVEntry], depth: int = 0, iocs: Optional[IOCCollector] = None
) -> None:
    """Extract and print key C2 configuration details."""
    for entry in entries:
        if entry.type_id == 0x0C and entry.is_parent:
            print("  [Agent Configuration]")
            for child in entry.children:
                if child.type_id == 0x01 and not child.is_parent:
                    rsa_info = _format_rsa_key(child.data)
                    if rsa_info:
                        print(f"    RSA Public Key: {rsa_info}")
                    else:
                        print(
                            f"    RSA Public Key: {child.data[:32].hex()}... ({len(child.data)} bytes)"
                        )
                elif child.type_id == 0x02 and not child.is_parent:
                    guid_str = format_value(child.data, child.type_id)
                    print(f"    Key GUID: {guid_str}")
                    if iocs:
                        iocs.key_guids.append(guid_str)

        elif entry.type_id == 0x01 and entry.is_parent:
            print("  [Shellcode TLV]")
            for child in entry.children:
                if child.type_id == 0x01 and not child.is_parent:
                    sc_type = child.data[0] if child.data else 0
                    print(
                        f"    Type: {'Listener' if sc_type == 1 else 'Command' if sc_type == 2 else f'Unknown(0x{sc_type:02X})'}"
                    )
                elif child.type_id == 0x02 and child.is_parent:
                    print(
                        f"    Execution Policy: PARENT ({len(child.children)} children)"
                    )
                elif child.type_id == 0x03 and not child.is_parent:
                    print(f"    Shellcode: {len(child.data)} bytes")
                elif child.type_id == 0x04 and not child.is_parent:
                    try:
                        text = child.data.decode("utf-8").strip("\x00")
                        print(f"    Communication Configuration: {text}")
                    except Exception:
                        print(
                            f"    Communication Configuration: {len(child.data)} bytes"
                        )
                elif child.type_id == 0x05 and not child.is_parent:
                    print(f"    Listener Config: {len(child.data)} bytes")
                    try:
                        sub_entries = parse_tlv(child.data)
                        if sub_entries:
                            listener_type = _detect_listener_type(sub_entries)
                            field_map = _get_listener_field_map(listener_type)
                            print(f"      Detected Type: {listener_type}")
                            _extract_listener_config(
                                sub_entries, field_map, listener_type, iocs=iocs
                            )
                    except Exception:
                        pass
                elif child.type_id == 0x06 and not child.is_parent:
                    val = (
                        struct.unpack("<I", child.data)[0]
                        if len(child.data) == 4
                        else child.data.hex()
                    )
                    if val != 0:
                        print(f"    Command ID: {val}")
                elif child.is_parent:
                    if child.children:
                        print_c2_summary(child.children, depth + 1, iocs=iocs)

        elif entry.type_id == 0x21 and entry.is_parent:
            print("  [Get Metadata]")
            _extract_shellcode_context(entry.children)

        # Recurse into parents we haven't handled specifically
        if entry.is_parent and entry.type_id not in (0x01, 0x0C, 0x21):
            for child in entry.children:
                if child.is_parent:
                    print_c2_summary([child], depth + 1, iocs=iocs)


def _extract_shellcode_context(entries: list[TLVEntry]) -> None:
    """Extract and display Get Metadata (TLV 0x21) details."""
    for child in entries:
        if child.is_parent:
            for inner in child.children:
                if inner.type_id == 0x01 and not inner.is_parent:
                    if len(inner.data) == 1:
                        print(
                            f"    Listener Type ID: 0x{inner.data[0]:02X} ({inner.data[0]})"
                        )
                    elif len(inner.data) == 2:
                        val = struct.unpack("<H", inner.data)[0]
                        print(f"    Listener Type ID: 0x{val:04X} ({val})")
                    elif len(inner.data) == 4:
                        val = struct.unpack("<I", inner.data)[0]
                        print(f"    Listener Type ID: 0x{val:02X} ({val})")
                elif inner.type_id == 0x02 and not inner.is_parent:
                    try:
                        name = inner.data.decode("utf-8")
                        print(f"    Listener Type Name: {name}")
                    except (UnicodeDecodeError, ValueError):
                        print(
                            f"    Context Data (0x02): {format_value(inner.data, inner.type_id)}"
                        )
                else:
                    print(
                        f"    Context Field 0x{inner.type_id:02X}: {format_value(inner.data, inner.type_id)}"
                    )
        elif child.data:
            try:
                text = child.data.decode("utf-8")
                if all(c.isprintable() for c in text):
                    print(f"    Context (0x{child.type_id:02X}): {text}")
                    continue
            except (UnicodeDecodeError, ValueError):
                pass
            print(
                f"    Data (0x{child.type_id:02X}): {format_value(child.data, child.type_id)}"
            )


def _resolve_enum(display: str, enum_map: dict[int, str]) -> str:
    """Resolve an integer display value to a named enum, e.g. '1' → 'FAILOVER (1)'."""
    try:
        val = int(display)
        name = enum_map.get(val)
        if name:
            return f"{name} ({val})"
    except (ValueError, TypeError):
        pass
    return display


def _format_leaf_value(entry: TLVEntry) -> tuple[str, bool]:
    """Format a leaf TLV entry. Returns (display_str, is_text)."""
    is_text = False
    display = None
    try:
        text = entry.data.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in text):
            display = text
            is_text = True
    except (UnicodeDecodeError, ValueError):
        pass
    if display is None:
        if len(entry.data) == 1:
            display = f"{entry.data[0]}"
        elif len(entry.data) == 2:
            display = f"{struct.unpack('<H', entry.data)[0]}"
        elif len(entry.data) == 4:
            display = f"{struct.unpack('<I', entry.data)[0]}"
        elif len(entry.data) == 16:
            try:
                import uuid

                u = uuid.UUID(bytes_le=entry.data)
                display = str(u)
            except Exception:
                display = entry.data.hex()
        else:
            display = format_value(entry.data, entry.type_id)
    return display, is_text


def _extract_listener_config(
    entries: list[TLVEntry],
    field_map: dict[int, str],
    listener_type: str,
    indent: int = 6,
    depth: int = 0,
    iocs: Optional[IOCCollector] = None,
) -> None:
    """Extract listener configuration using type-specific field maps."""
    prefix = " " * indent
    for entry in entries:
        if entry.is_parent and entry.type_id == 0x01 and depth == 0:
            _extract_listener_config(
                entry.children, field_map, listener_type, indent, depth + 1, iocs=iocs
            )
            continue

        if entry.is_parent:
            if depth == 1 and entry.type_id == 0x01:
                _extract_endpoint_group(entry.children, indent + 2, iocs=iocs)
            elif entry.type_id == 0x0C:
                _extract_http_headers(entry.children, indent + 2)
            else:
                print(
                    f"{prefix}Parent 0x{entry.type_id:02X}: ({len(entry.children)} children)"
                )
                _extract_listener_config(
                    entry.children, {}, listener_type, indent + 2, depth + 1, iocs=iocs
                )
            continue

        if not entry.data and len(entry.data) == 0:
            continue

        display, is_text = _format_leaf_value(entry)
        field_name = field_map.get(entry.type_id, "")

        # Collect text values that look like network addresses as IOCs
        if iocs and is_text:
            iocs.add_address(display)

        if field_name:
            if (
                field_name in ("HTTPS", "Instant Responses", "Web Proxy Windows Auth")
                and not is_text
            ):
                val = entry.data[0] if len(entry.data) == 1 else int(display)
                print(f"{prefix}{field_name}: {'Yes' if val else 'No'}")
            elif field_name == "Port":
                print(f"{prefix}{field_name}: {display}")
                if iocs:
                    try:
                        iocs.add_port(int(display))
                    except ValueError:
                        pass
            elif field_name == "Rotation Type":
                print(f"{prefix}{field_name}: {_resolve_enum(display, ROTATION_TYPE)}")
            elif field_name == "Rotation Unit":
                print(f"{prefix}{field_name}: {_resolve_enum(display, ROTATION_UNIT)}")
            elif field_name == "Web Proxy" and is_text:
                print(f"{prefix}{field_name}: {display}")
                if iocs:
                    iocs.add_url(display)
            else:
                print(f"{prefix}{field_name}: {display}")
        else:
            print(f"{prefix}Field 0x{entry.type_id:02X}: {display}")


def _extract_endpoint_group(
    children: list[TLVEntry], indent: int = 8, iocs: Optional[IOCCollector] = None
) -> None:
    """Extract a per-endpoint group (HTTP/HTTPS: 0x01 PARENT children)."""
    prefix = " " * indent
    for child in children:
        if not child.data and len(child.data) == 0:
            continue
        display, is_text = _format_leaf_value(child)
        name = HTTP_ENDPOINT_FIELDS.get(child.type_id, "")
        if name:
            if name in ("Rotation Type", "Host Header Rotation Type"):
                resolved = _resolve_enum(display, ROTATION_TYPE)
                print(f"{prefix}{name}: {resolved}")
            elif name in ("Rotation Unit", "Host Header Rotation Unit"):
                resolved = _resolve_enum(display, ROTATION_UNIT)
                print(f"{prefix}{name}: {resolved}")
            else:
                print(f"{prefix}{name}: {display}")
                if name == "Address" and iocs:
                    iocs.add_address(display)
        else:
            print(f"{prefix}Field 0x{child.type_id:02X}: {display}")


# HTTP custom headers (0x0C parent, 0x01=name, 0x02=value): TLV IDs from payload analysis
def _extract_http_headers(children: list[TLVEntry], indent: int = 8) -> None:
    """Extract custom HTTP header name/value pairs from 0x0C parent."""
    prefix = " " * indent
    print(f"{prefix}Custom HTTP Headers:")
    header_name = None
    for child in children:
        if not child.data:
            continue
        display, _ = _format_leaf_value(child)
        if child.type_id == 0x01:
            header_name = display
        elif child.type_id == 0x02:
            if header_name:
                print(f"{prefix}  {header_name}: {display}")
                header_name = None
            else:
                print(f"{prefix}  (value): {display}")
        else:
            print(f"{prefix}  Field 0x{child.type_id:02X}: {display}")
    if header_name:
        print(f"{prefix}  {header_name}: (no value)")
