from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class UFWRule:
    number: int
    to: str                     # e.g. "22/tcp", "80/tcp", "Anywhere"
    action: str                 # "ALLOW", "DENY", "REJECT", "LIMIT"
    from_addr: str              # e.g. "Anywhere", "192.168.0.0/24"
    direction: str              # "IN" or "OUT"
    comment: str | None = None
    v6: bool = False

    # Computed by explanation engine
    service_name: str = ""      # e.g. "SSH", "HTTP", "Beszel"
    source_friendly: str = ""   # e.g. "the Trusted VLAN", "anywhere"
    dest_friendly: str = ""     # e.g. "port 22/tcp"
    explanation: str = ""       # full plain English sentence


@dataclass
class ListeningPort:
    port: int
    protocol: str               # "tcp" or "udp"
    address: str                # bind address: 0.0.0.0, 127.0.0.1, ::, etc.
    process: str                # process name from ss
    has_ufw_rule: bool = False
    is_external: bool = False   # True if bound to 0.0.0.0 or ::

    @property
    def bind_description(self) -> str:
        if self.address in ("127.0.0.1", "::1"):
            return "localhost only"
        if self.address in ("0.0.0.0", "::","*"):
            return "all interfaces"
        return self.address


@dataclass
class HostFirewallState:
    name: str
    hostname: str
    is_docker_host: bool = False

    # UFW state
    ufw_active: bool = False
    ufw_installed: bool = True
    default_incoming: str = ""      # "deny" / "allow" / "reject"
    default_outgoing: str = ""      # "deny" / "allow"
    default_routed: str = ""        # "disabled" / "deny" / "allow"

    # UFW rules
    rules: list[UFWRule] = field(default_factory=list)

    # Listening ports
    listening_ports: list[ListeningPort] = field(default_factory=list)

    # Metadata
    rules_last_modified: datetime | None = None
    fetch_timestamp: datetime | None = None
    fetch_error: str | None = None

    # Computed
    uncovered_ports: list[ListeningPort] = field(default_factory=list)

    @property
    def allowed_services(self) -> list[str]:
        """Unique service names from ALLOW rules, for overview pills."""
        seen = set()
        services = []
        for r in self.rules:
            if r.action == "ALLOW" and r.service_name and r.service_name not in seen:
                seen.add(r.service_name)
                services.append(r.service_name)
        return services

    @property
    def external_gaps(self) -> list[ListeningPort]:
        return [p for p in self.uncovered_ports if p.is_external]

    @property
    def local_gaps(self) -> list[ListeningPort]:
        return [p for p in self.uncovered_ports if not p.is_external]

    @property
    def status_label(self) -> str:
        if not self.ufw_installed:
            return "Not Installed"
        if self.fetch_error:
            return "Unreachable"
        if not self.ufw_active:
            return "Unprotected"
        return "Protected"

    @property
    def status_class(self) -> str:
        if not self.ufw_installed or self.fetch_error or not self.ufw_active:
            return "unprotected"
        return "protected"

    @property
    def default_policy_text(self) -> str:
        if not self.ufw_active:
            return ""
        if self.default_incoming == "deny":
            return "Blocks all incoming by default"
        if self.default_incoming == "reject":
            return "Rejects all incoming by default"
        if self.default_incoming == "allow":
            return "Allows all incoming by default"
        return f"Default incoming: {self.default_incoming}"
