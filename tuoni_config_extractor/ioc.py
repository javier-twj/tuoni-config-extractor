"""IOC (Indicators of Compromise) collector for Tuoni C2 configs."""

import re

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")
# Domain must have at least one dot and look like a hostname, not a path/date/UUID
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"  # first label
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$"  # at least one more label
)


class IOCCollector:
    """Collect network IOCs (IPs, domains, ports, URLs) during TLV parsing."""

    def __init__(self) -> None:
        self.ipv4: list[str] = []
        self.ipv6: list[str] = []
        self.domains: list[str] = []
        self.ports: list[int] = []
        self.urls: list[str] = []
        self.pipe_names: list[str] = []
        self.kill_dates: list[str] = []
        self.key_guids: list[str] = []

    def add_address(self, addr: str) -> None:
        """Classify and store an address (IP or domain)."""
        addr = addr.strip()
        if not addr:
            return
        if _IPV4_RE.match(addr):
            if addr not in self.ipv4:
                self.ipv4.append(addr)
        elif _IPV6_RE.match(addr.strip("[]")):
            clean = addr.strip("[]")
            if clean not in self.ipv6:
                self.ipv6.append(clean)
        else:
            if _DOMAIN_RE.match(addr) and addr not in self.domains:
                self.domains.append(addr)

    def add_port(self, port: int) -> None:
        if port and port not in self.ports:
            self.ports.append(port)

    def add_url(self, url: str) -> None:
        if url and url not in self.urls:
            self.urls.append(url)

    def print_summary(self) -> None:
        """Print a flat IOC list, separated by type."""
        all_iocs = self.domains + self.urls + self.ipv4 + self.ipv6
        if not all_iocs:
            print("  (no network IOCs found)")
            return
        sections = []
        if self.domains:
            sections.append(("Domains:", self.domains))
        if self.urls:
            sections.append(("URLs:", self.urls))
        if self.ipv4:
            sections.append(("IPv4:", self.ipv4))
        if self.ipv6:
            sections.append(("IPv6:", self.ipv6))
        for i, (header, items) in enumerate(sections):
            if i > 0:
                print()
            print(f"  {header}")
            for item in items:
                print(f"  {item}")
