"""Tuoni C2 Config Extractor — Decode and parse embedded TLV configuration."""

from .cli import main
from .crypto import decrypt_config_blob, hex_decode_tuoni
from .ioc import IOCCollector
from .pe_resources import (
    enumerate_resources,
    extract_pe_resource_txt104,
)
from .summary import print_c2_summary
from .tlv_parser import (
    TLVEntry,
    extract_tlv_summary,
    format_value,
    parse_tlv,
    print_tlv_tree,
)

__all__ = [
    "decrypt_config_blob",
    "hex_decode_tuoni",
    "IOCCollector",
    "extract_pe_resource_txt104",
    "enumerate_resources",
    "print_c2_summary",
    "TLVEntry",
    "parse_tlv",
    "format_value",
    "print_tlv_tree",
    "extract_tlv_summary",
    "main",
]
