"""PE resource extraction for Tuoni agent binaries.

The Tuoni agent stores its TLV configuration blob in a PE resource
named ``TXT`` with ID 104 (0x68).  ``TXT`` is a custom named resource
type (not a standard Windows RT_* id).  The agent loads it with
FindResourceW(hModule, 104, L"TXT").
"""

import struct
from typing import Any, Optional

import pefile


# Resource type "TXT", ID 104 (0x68): observed in generated PE payloads
# (confirmed by FindResourceW call in the binary's resource-loading code)
# Docs say to "patch them into the payload file" but don't specify the resource type/ID
# https://docs.shelldot.com/InsideView/Protocols/C2_Agent.html
def extract_pe_resource_txt104(pe_data: bytes) -> Optional[bytes]:
    """Extract TXT resource #104 (0x68) from PE."""
    pe = pefile.PE(data=pe_data)
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        # First pass: look for type name "TXT" specifically
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name = None
            if hasattr(res_type, "name") and res_type.name:
                type_name = str(res_type.name)
            if type_name == "TXT":
                if hasattr(res_type, "directory"):
                    for res_id in res_type.directory.entries:
                        rid = res_id.id if hasattr(res_id, "id") else None
                        if rid == 0x68 or rid == 104:  # type: ignore[comparison-overlap]
                            if hasattr(res_id, "directory"):
                                for res_lang in res_id.directory.entries:
                                    data_rva = res_lang.data.struct.OffsetToData
                                    size = res_lang.data.struct.Size
                                    data: bytes = pe.get_data(data_rva, size)
                                    return data
        # Fallback: iterate all resources
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(res_type, "directory"):
                for res_id in res_type.directory.entries:
                    rid = res_id.id if hasattr(res_id, "id") else None
                    if hasattr(res_id, "directory"):
                        for res_lang in res_id.directory.entries:
                            data_rva = res_lang.data.struct.OffsetToData
                            size = res_lang.data.struct.Size
                            data_inner: bytes = pe.get_data(data_rva, size)
                            type_name = (
                                str(res_type.name)
                                if hasattr(res_type, "name") and res_type.name
                                else f"ID:{res_type.id}"
                            )
                            if (rid == 0x68 or rid == 104) or (type_name == "TXT"):  # type: ignore[comparison-overlap]
                                return data_inner
    # Manual fallback if pefile didn't find it
    return _manual_extract_resource(pe_data)


def _manual_extract_resource(pe_data: bytes) -> Optional[bytes]:
    """Manually parse PE resource directory to find TXT#104."""
    e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
    magic = struct.unpack_from("<H", pe_data, e_lfanew + 24)[0]
    if magic == 0x20B:  # PE32+
        resource_rva_offset = e_lfanew + 24 + 112
    else:  # PE32
        resource_rva_offset = e_lfanew + 24 + 96
    resource_rva = struct.unpack_from("<I", pe_data, resource_rva_offset)[0]
    resource_size = struct.unpack_from("<I", pe_data, resource_rva_offset + 4)[0]
    if resource_rva == 0 or resource_size == 0:
        return None

    num_sections = struct.unpack_from("<H", pe_data, e_lfanew + 6)[0]
    size_opt_hdr = struct.unpack_from("<H", pe_data, e_lfanew + 20)[0]
    section_offset = e_lfanew + 24 + size_opt_hdr
    rsrc_file_offset = None
    rsrc_va = None
    for i in range(num_sections):
        sec_off = section_offset + i * 40
        sec_name = pe_data[sec_off : sec_off + 8].rstrip(b"\x00")
        if sec_name == b".rsrc":
            rsrc_va = struct.unpack_from("<I", pe_data, sec_off + 12)[0]
            rsrc_file_offset = struct.unpack_from("<I", pe_data, sec_off + 20)[0]
            break
    if rsrc_file_offset is None:
        return None

    # At this point, both rsrc_va and rsrc_file_offset are guaranteed to be int, not None
    assert rsrc_va is not None  # for mypy

    def rva_to_offset(rva: int) -> int:
        # rsrc_va and rsrc_file_offset are captured from outer scope and are guaranteed to be int
        return int(rva - rsrc_va + rsrc_file_offset)

    leaves: list[tuple[list[Any], int, int]] = []
    _parse_res_dir(pe_data, rsrc_file_offset, rsrc_file_offset, rsrc_va, leaves, [])

    for path, data_rva, data_size in leaves:
        offset = rva_to_offset(data_rva)
        if offset + data_size <= len(pe_data):
            if len(path) >= 2 and path[1] == 104:
                return pe_data[offset : offset + data_size]

    if leaves:
        best = max(leaves, key=lambda x: x[2])
        offset = rva_to_offset(best[1])
        if offset + best[2] <= len(pe_data):
            return pe_data[offset : offset + best[2]]
    return None


def _parse_res_dir(
    pe_data: bytes,
    base_offset: int,
    dir_offset: int,
    rsrc_va: int,
    leaves: list[tuple[list[Any], int, int]],
    path: list[Any],
) -> None:
    """Recursively parse PE resource directory."""
    if dir_offset + 16 > len(pe_data):
        return
    num_named = struct.unpack_from("<H", pe_data, dir_offset + 12)[0]
    num_id = struct.unpack_from("<H", pe_data, dir_offset + 14)[0]
    total = num_named + num_id
    for i in range(total):
        entry_off = dir_offset + 16 + i * 8
        if entry_off + 8 > len(pe_data):
            break
        name_or_id = struct.unpack_from("<I", pe_data, entry_off)[0]
        data_or_subdir = struct.unpack_from("<I", pe_data, entry_off + 4)[0]

        if name_or_id & 0x80000000:
            str_offset = base_offset + (name_or_id & 0x7FFFFFFF)
            if str_offset + 2 <= len(pe_data):
                str_len = struct.unpack_from("<H", pe_data, str_offset)[0]
                try:
                    entry_name = pe_data[
                        str_offset + 2 : str_offset + 2 + str_len * 2
                    ].decode("utf-16-le")
                except Exception:
                    entry_name = f"Named:{name_or_id & 0x7FFFFFFF}"
            else:
                entry_name = f"Named:{name_or_id & 0x7FFFFFFF}"
            current_id = entry_name
        else:
            current_id = name_or_id

        new_path = path + [current_id]

        if data_or_subdir & 0x80000000:
            subdir_off = base_offset + (data_or_subdir & 0x7FFFFFFF)
            _parse_res_dir(pe_data, base_offset, subdir_off, rsrc_va, leaves, new_path)
        else:
            data_entry_off = base_offset + data_or_subdir
            if data_entry_off + 16 <= len(pe_data):
                data_rva = struct.unpack_from("<I", pe_data, data_entry_off)[0]
                data_size = struct.unpack_from("<I", pe_data, data_entry_off + 4)[0]
                leaves.append((new_path, data_rva, data_size))


def enumerate_resources(pe_data: bytes) -> None:
    """List all PE resources for debugging."""
    pe = pefile.PE(data=pe_data)
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        print("[!] No resource directory found")
        return
    print("\n=== PE Resources ===")
    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_name = str(res_type.name) if res_type.name else f"ID:{res_type.id}"
        if hasattr(res_type, "directory"):
            for res_id in res_type.directory.entries:
                id_name = str(res_id.name) if res_id.name else f"ID:{res_id.id}"
                if hasattr(res_id, "directory"):
                    for res_lang in res_id.directory.entries:
                        size = res_lang.data.struct.Size
                        rva = res_lang.data.struct.OffsetToData
                        print(
                            f"  Type={type_name}, ID={id_name}, Lang={res_lang.id}, Size={size}, RVA=0x{rva:X}"
                        )
