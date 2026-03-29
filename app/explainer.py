"""Rule explanation engine — translates UFW rules to plain English."""

from __future__ import annotations

import ipaddress
from .models import UFWRule, ListeningPort

# Well-known port → service name mapping
WELL_KNOWN_PORTS: dict[int, str] = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    81: "NPM Admin",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1883: "MQTT",
    2283: "Immich",
    3000: "DockHand",
    3001: "Uptime Kuma",
    3005: "DrydDock",
    3030: "Domain Locker",
    3306: "MySQL/MariaDB",
    3333: "Hoarder",
    5000: "Container Registry",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    7007: "Dozzle Agent",
    8000: "Paperless-ngx",
    8001: "Kimai",
    8043: "Omada HTTPS",
    8080: "Termix",
    8088: "Coolify",
    8090: "Beszel",
    8123: "Home Assistant",
    8443: "HTTPS Alt",
    8888: "EventFeed",
    8890: "FencePost",
    9000: "Portainer",
    9090: "Cockpit",
    9898: "Backrest",
    9999: "Dozzle",
    10000: "Webmin",
    27017: "MongoDB",
    51820: "WireGuard",
    55414: "UrBackup",
}


def explain_rules(
    rules: list[UFWRule],
    listening_ports: list[ListeningPort],
    network_names: dict[str, str],
) -> None:
    """Mutate rules in-place, filling explanation fields.

    Also enriches port-to-service mapping using ss process data.
    """
    # Build a process-based port→name map from ss data
    process_services: dict[int, str] = {}
    for lp in listening_ports:
        if lp.process:
            process_services[lp.port] = _process_to_service(lp.process)

    for rule in rules:
        port_num = _extract_port(rule.to)

        # Service name: check process map, then well-known, then fallback
        if port_num and port_num in process_services:
            rule.service_name = process_services[port_num]
        elif port_num and port_num in WELL_KNOWN_PORTS:
            rule.service_name = WELL_KNOWN_PORTS[port_num]
        elif rule.to == "Anywhere" or not port_num:
            rule.service_name = "All Ports"
        else:
            rule.service_name = f"Port {rule.to}"

        # Friendly source
        rule.source_friendly = _friendly_network(rule.from_addr, network_names)

        # Friendly destination
        rule.dest_friendly = _friendly_dest(rule.to, port_num)

        # Build explanation sentence
        rule.explanation = _build_explanation(rule)


def _extract_port(to_field: str) -> int | None:
    """Extract port number from a UFW 'to' field like '22/tcp', '80,443/tcp'."""
    if to_field in ("Anywhere",):
        return None

    # Handle ranges like 8000:8100/tcp
    match_range = to_field.split("/")[0]
    if ":" in match_range:
        return None  # range — can't map to single service

    # Handle multi-port like 80,443/tcp
    if "," in match_range:
        return None

    try:
        return int(match_range.split("/")[0])
    except (ValueError, IndexError):
        return None


def _process_to_service(process: str) -> str:
    """Convert a process name from ss into a display-friendly service name."""
    mapping = {
        "sshd": "SSH",
        "nginx": "Nginx",
        "apache2": "Apache",
        "docker-proxy": "Docker",
        "node": "Node.js",
        "python3": "Python",
        "python": "Python",
        "uvicorn": "Python",
        "postgres": "PostgreSQL",
        "mysqld": "MySQL",
        "mariadbd": "MariaDB",
        "redis-server": "Redis",
        "mosquitto": "MQTT",
        "code-server": "Code Server",
    }
    return mapping.get(process, process.capitalize())


def _friendly_network(addr: str, network_names: dict[str, str]) -> str:
    """Convert a CIDR or address to a friendly name."""
    if addr == "Anywhere":
        return "anywhere"

    # Direct match in network_names
    if addr in network_names:
        return f"the {network_names[addr]}"

    # Check if it's a subnet that matches a named network
    try:
        source_net = ipaddress.ip_network(addr, strict=False)
        for cidr, name in network_names.items():
            try:
                named_net = ipaddress.ip_network(cidr, strict=False)
                if source_net == named_net:
                    return f"the {name}"
            except ValueError:
                continue
    except ValueError:
        pass

    # Single IP — check which named network it belongs to
    try:
        source_addr = ipaddress.ip_address(addr.split("/")[0])
        for cidr, name in network_names.items():
            try:
                named_net = ipaddress.ip_network(cidr, strict=False)
                if source_addr in named_net:
                    return f"{addr} (in {name})"
            except ValueError:
                continue
    except ValueError:
        pass

    return addr


def _friendly_dest(to_field: str, port_num: int | None) -> str:
    """Build a friendly destination description."""
    if to_field == "Anywhere":
        return "all ports"
    if port_num:
        proto = ""
        if "/" in to_field:
            proto = "/" + to_field.split("/")[1]
        return f"port {port_num}{proto}"
    return to_field


def _build_explanation(rule: UFWRule) -> str:
    """Build a full plain English explanation for a rule."""
    action_verb = {
        "ALLOW": "Allow",
        "DENY": "Block",
        "REJECT": "Reject",
        "LIMIT": "Rate-limit",
    }.get(rule.action, rule.action)

    direction_text = "incoming" if rule.direction == "IN" else "outgoing"

    # Special case: default-like rules on Anywhere
    if rule.to == "Anywhere" and rule.from_addr == "Anywhere":
        return f"{action_verb} all {direction_text} traffic"

    service = rule.service_name
    source = rule.source_friendly

    if rule.action == "LIMIT":
        return (
            f"Rate-limit {direction_text} connections to {service} "
            f"from {source} (max 6 hits in 30 seconds)"
        )

    if rule.action == "ALLOW":
        return f"Allow {direction_text} connections to {service} from {source}"

    if rule.action == "DENY":
        return f"Block {direction_text} connections to {service} from {source}"

    if rule.action == "REJECT":
        return (
            f"Reject {direction_text} connections to {service} from {source} "
            f"(sends rejection notice to sender)"
        )

    return f"{action_verb} {direction_text} traffic to {service} from {source}"
