"""Decoding for Tuoni C2 agent configurations.

The Tuoni agent encodes its TLV configuration blob using a
custom hex encoding with base 0x41 (characters A–P).  Each pair of
bytes encodes one output byte:

    output = ((high - 0x41) << 4) | (low - 0x41)

This is auto-detected by checking whether all blob bytes fall in the
A–P range (0x41–0x50).
"""


# Source: binary analysis of inline decoder in resource loader.
def hex_decode_tuoni(data: bytes) -> bytes:
    """Tuoni custom hex decode.

    byte = ((char1 - 0x41) << 4) | (char2 - 0x41)
    Characters are in the A-P range (0x41-0x50).
    """
    result = bytearray()
    for i in range(0, len(data) - 1, 2):
        hi = (data[i] - 0x41) & 0x0F
        lo = (data[i + 1] - 0x41) & 0x0F
        result.append((hi << 4) | lo)
    return bytes(result)


def decrypt_config_blob(blob: bytes) -> bytes:
    """Decode the Tuoni configuration blob.

    Auto-detects A-P hex encoding by checking if all bytes are in the
    A–P range (0x41–0x50).  If so, applies hex decode; otherwise
    returns the blob as-is.

    Args:
        blob: raw config blob bytes
    """
    data = blob

    # Auto-detect: if all bytes are in A-P range, it's A-P hex encoded
    if len(data) >= 10:
        sample = data[: min(256, len(data))]
        if all(0x41 <= b <= 0x50 for b in sample):
            print("[*] Blob bytes are in A-P range (0x41-0x50), applying hex decode")
            print("[*] A-P hex decode (base 0x41)")
            data = hex_decode_tuoni(data)
            print(f"    Decoded {len(blob)} bytes -> {len(data)} bytes")
            return data

    print("[*] Raw binary (no encoding detected)")
    return data
