"""TLV field maps and constant definitions for Tuoni C2 protocol.

All field *names* and *type IDs* for top-level and child TLVs are taken
directly from the official Tuoni documentation (links inline below).

For listener-specific TLVs (HTTP, ReverseTCP, BindSMB, BindTCP), the
field *names* come from the REST API docs, but the *TLV type IDs* are
not documented in the official docs.  Those IDs were determined by
generating payloads with known configuration values and correlating
the resulting TLV output.  This is noted in each section with
"TLV ID → field mapping inferred".
"""

# ─── Top-level TLV type IDs ────────────────────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/C2_Agent.html

TOP_LEVEL_TLV_NAMES = {
    0x01: "Shellcode",
    0x03: "Built-in Command",
    0x04: "Command Result",
    0x05: "Agent Command Control",
    0x0C: "Agent Configuration",
    0x11: "Agent Metadata",
    0x12: "Encrypted Metadata",
    0x13: "Encrypted Data",
    0x20: "Listener Reconfiguration",
    0x21: "Get Metadata",
    0x22: "Get Next Message",
    0x23: "Received C2 Message",
    0x30: "Send Data",
    0x31: "Command Configuration",
    0x32: "Send Error Data",
    0x33: "Command Successful",
    0x34: "Command Failed",
    0x39: "Data to Command",
    0x3F: "Stop Execution",
}

# ─── Agent Configuration (0x0C) children ───────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/C2_Agent.html
# https://docs.shelldot.com/InsideView/Protocols/Encryption.html

AGENT_CONFIG_CHILDREN = {
    0x01: "RSA Public Key (DER)",
    0x02: "Public Key GUID/UUID",
}

# ─── Agent Metadata (0x11) children ────────────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/C2_Agent.html
# NOTE: Current agents send metadata using type 0x01 (same as Shellcode)
# for backward compatibility. Type 0x11 is reserved for a future revision.

AGENT_METADATA_CHILDREN = {
    0x01: "Agent GUID",
    0x02: "Username",
    0x03: "Process Name",
    0x04: "PID",
    0x05: "Working Directory",
    0x06: "OS Type",
    0x07: "Windows Major Version",
    0x08: "Windows Minor Version",
    0x09: "IPv4 Addresses",
    0x0A: "Hostname",
    0x0B: "Process Architecture",
    0x0C: "OS Architecture",
    0x0D: "ANSI Codepage",
    0x10: "AES Key (16 bytes)",
    0x11: "Encryption Algorithm",
    0x40: "Agent Codename",
    0x41: "Agent Version",
    0x43: "Payload ID",
}

# ─── Shellcode/Listener (0x01) children ────────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/Agent_ShellcodeListener.html
# https://docs.shelldot.com/InsideView/Protocols/Agent_ShellcodeCommand.html

SHELLCODE_CHILDREN = {
    0x01: "Shellcode Type (0x01=listener, 0x02=command)",
    0x02: "Execution Policy",
    0x03: "Shellcode Blob",
    0x04: "Communication Configuration",
    0x05: "Shellcode Config",
    0x06: "Command ID / Type-specific Config",
}

# ─── Encrypted Metadata (0x12) children ────────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/Encryption.html

ENCRYPTED_METADATA_CHILDREN = {
    0x01: "Is Encrypted (0x00=no, 0x01=yes)",
    0x02: "Encryption Key GUID",
    0x03: "Encryption Configuration",
    0x10: "Encrypted Metadata TLV",
}

# ─── Encrypted Data (0x13) children ────────────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/Encryption.html

ENCRYPTED_DATA_CHILDREN = {
    0x01: "Is Encrypted (0x00=no, 0x01=yes)",
    0x03: "Encryption Configuration",
    0x04: "IV Value",
    0x10: "Encrypted Data",
}

# ─── Encryption Configuration (nested inside 0x12.0x03 / 0x13.0x03) ───────
# https://docs.shelldot.com/InsideView/Protocols/Encryption.html

ENCRYPTION_CONFIG_CHILDREN = {
    0x01: "Encryption Algorithm (1=aes128-cbc, 2=aes128-gcm)",
}

# ─── Built-in Command (0x03) children ─────────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/C2_Agent.html

BUILT_IN_CMD_CHILDREN = {
    0x01: "Task ID",
    0x02: "Command Control Code (0x01=DIE)",
    0x03: "Configuration",
}

# ─── Command Result (0x04) children ───────────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/C2_Agent.html

CMD_RESULT_CHILDREN = {
    0x01: "Task ID",
    0x02: "Result Data",
    0x03: "Status (0x00=failed, 0x01=ongoing, 0x02=success)",
    0x04: "Error Data",
}

# ─── Agent Command Control (0x05) children ────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/C2_Agent.html

AGENT_CMD_CTRL_CHILDREN = {
    0x01: "Command ID",
    0x02: "Manipulation Type (0x01=new data, 0xDD=cancel/stop)",
    0x03: "Configuration/Data",
}

# ─── Listener Reconfiguration (0x20) children ─────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/Agent_ShellcodeListener.html

LISTENER_RECONFIG_CHILDREN = {
    0x01: "isRequest (1=request, 0=response)",
    0x02: "Unique Request ID",
    0x03: "isSuccess (response only)",
    0x04: "Configuration Blob/Error Msg",
}

# ─── Get Metadata (0x21) children ─────────────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/Agent_ShellcodeListener.html

GET_METADATA_CHILDREN = {
    0x01: "isRequest",
    0x02: "Unique Request ID",
    0x04: "Metadata Binary",
}

# ─── Get Next Message (0x22) children ─────────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/Agent_ShellcodeListener.html

GET_NEXT_MSG_CHILDREN = {
    0x01: "isRequest",
    0x02: "Unique Request ID",
    0x04: "Command Binary",
}

# ─── Command Configuration (0x31) children ────────────────────────────────
# https://docs.shelldot.com/InsideView/Protocols/Agent_ShellcodeCommand.html

CMD_CONFIG_CHILDREN = {
    0x01: "isOngoingCommand",
    0x02: "isBlockByBlockResult",
    0x03: "setStopWait",
}

# ─── HTTP/HTTPS Listener Configuration ────────────────────────────────────
# Field names: https://docs.shelldot.com/REST/Listeners/HttpListener.html
# Listener overview: https://docs.shelldot.com/Components/Listeners/HttpListener.html
# NOTE: TLV ID → field mapping inferred (binary encoding is undocumented).
# Verified by generating payloads with known config value and correlating TLV output.

HTTP_LISTENER_FIELDS = {
    0x02: "Port",  # port
    0x03: "GET URI",  # getUri
    0x04: "POST URI",  # postUri
    0x05: "Cookie Name",  # metadataCookieName
    0x06: "Metadata Prefix",  # metadataPrefix
    0x07: "Metadata Suffix",  # metadataSuffix
    0x08: "HTTPS",  # https (boolean as int32)
    0x09: "Start Time",  # startTime (ISO 8601 UTC string)
    0x0A: "Sleep (seconds)",  # sleep
    0x0B: "Sleep Random (seconds)",  # sleepRandom
    0x0D: "Instant Responses",  # instantResponses (boolean as int32)
    0x10: "Web Proxy",  # webProxy (URL string)
    0x11: "Web Proxy Username",  # webProxyUsername
    0x12: "Web Proxy Password",  # webProxyPassword
    0x13: "Web Proxy Windows Auth",  # webProxyWindowsAuth (boolean as int32)
}

# Per-endpoint fields inside each 0x01 PARENT group (HTTP/HTTPS)
# Field names: https://docs.shelldot.com/REST/Listeners/HttpListener.html
# NOTE: TLV ID → field mapping inferred (binary encoding is undocumented).
# Each host in httpCallbacks[].hosts[] gets its own 0x01 PARENT group,
# inheriting the callback's sleep/rotation settings.
HTTP_ENDPOINT_FIELDS = {
    0x01: "Address",  # httpCallbacks[].hosts[]
    0x02: "Sleep (seconds)",  # httpCallbacks[].sleep
    0x03: "Sleep Random (seconds)",  # httpCallbacks[].sleepRandom
    0x04: "Rotation Type",  # httpCallbacks[].hostsRotation.type
    0x05: "Rotation Counter",  # httpCallbacks[].hostsRotation.counter
    0x06: "Rotation Unit",  # httpCallbacks[].hostsRotation.unit
    0x07: "Host Header",  # httpCallbacks[].hostHeaders[] (repeated)
    0x08: "Host Header Rotation Type",  # httpCallbacks[].hostHeaderRotation.type
    0x09: "Host Header Rotation Counter",  # httpCallbacks[].hostHeaderRotation.counter
    0x0A: "Host Header Rotation Unit",  # httpCallbacks[].hostHeaderRotation.unit
}

# ─── Enum value mappings for HTTP listener ─────────────────────────────────
# Enum names: https://docs.shelldot.com/REST/Listeners/HttpListener.html
# (FAILOVER, ROTATE, RANDOM; TRIES, SECONDS, MINUTES, HOURS)
# NOTE: Integer → name mapping inferred from payload analysis.

ROTATION_TYPE = {1: "FAILOVER", 2: "ROTATE", 3: "RANDOM"}
ROTATION_UNIT = {1: "TRIES", 2: "SECONDS", 3: "MINUTES", 4: "HOURS"}

# ─── Reverse TCP Agent Listener Configuration ─────────────────────────────
# https://docs.shelldot.com/Components/Listeners/TcpReverseAgentListener.html
# https://docs.shelldot.com/REST/Listeners/TcpReverseAgentListener.html
# NOTE: TLV ID → field mapping inferred (binary encoding is undocumented).

REVERSETCP_LISTENER_FIELDS = {
    0x01: "Host",  # hosts[] — IP addresses or hostnames (repeated)
    0x02: "Port",  # port
    0x03: "Handshake Bytes",  # handshakeBytes — random bytes for initial handshake
    0x0B: "Start Time",  # startTime — optional UTC start time (ISO format)
}

# ─── Relay Bind SMB Listener Configuration ────────────────────────────────
# https://docs.shelldot.com/Components/Listeners/RelayBindSMB.html
# https://docs.shelldot.com/REST/Listeners/RelayBindSMB.html
# NOTE: TLV ID → field mapping inferred (binary encoding is undocumented).

BINDSMB_LISTENER_FIELDS = {
    0x01: "Pipe Name",  # pipename
}

# ─── Relay Bind TCP Listener Configuration ────────────────────────────────
# https://docs.shelldot.com/Components/Listeners/RelayBindTCP.html
# https://docs.shelldot.com/REST/Listeners/RelayBindTCP.html
# NOTE: TLV ID → field mapping inferred (binary encoding is undocumented).

BINDTCP_LISTENER_FIELDS = {
    0x01: "Port",  # port
}

# ─── Parent→children routing table ────────────────────────────────────────

TLV_CHILD_MAPS = {
    0x01: SHELLCODE_CHILDREN,
    0x03: BUILT_IN_CMD_CHILDREN,
    0x04: CMD_RESULT_CHILDREN,
    0x05: AGENT_CMD_CTRL_CHILDREN,
    0x0C: AGENT_CONFIG_CHILDREN,
    0x11: AGENT_METADATA_CHILDREN,
    0x12: ENCRYPTED_METADATA_CHILDREN,
    0x13: ENCRYPTED_DATA_CHILDREN,
    0x20: LISTENER_RECONFIG_CHILDREN,
    0x21: GET_METADATA_CHILDREN,
    0x22: GET_NEXT_MSG_CHILDREN,
    0x31: CMD_CONFIG_CHILDREN,
}
