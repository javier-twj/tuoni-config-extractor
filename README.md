# Tuoni C2 Config Extractor

Static Python tool to decrypt and parse embedded TLV configuration from **Tuoni Community Edition** C2 agent PE binaries.

Tested against **Tuoni v0.12.2**. TLV field names are taken from the [official Tuoni documentation](https://docs.shelldot.com); exact TLV type IDs were reverse-engineered from generated payloads where the docs do not specify wire-level identifiers.

## Usage

```bash
uv run tuoni-extract sample.exe

# JSON output
uv run tuoni-extract sample.exe --json

# Verbose output
uv run tuoni-extract sample.exe --verbose

# Dump raw config blob before decryption
uv run tuoni-extract sample.exe --dump-raw config_blob.bin

# Dump decrypted config blob
uv run tuoni-extract sample.exe --dump-decrypted decrypted_config.bin

# Dump embedded shellcode blobs (numbers inserted before extension: shellcode_1.bin, shellcode_2.bin, etc.)
uv run tuoni-extract sample.exe --dump-shellcode shellcode.bin

# List all PE resources
uv run tuoni-extract sample.exe --list-resources
```
