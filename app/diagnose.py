"""Connection diagnostic — trace a connection attempt against UFW rules."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import HostFirewallState, UFWRule


@dataclass
class RuleEvaluation:
    rule: UFWRule
    matched: bool
    reason: str  # why it matched or didn't


@dataclass
class DiagnosticResult:
    source_ip: str
    source_network: str       # friendly name
    dest_host: str
    dest_port: int
    dest_protocol: str
    ufw_active: bool
    default_policy: str       # "deny", "allow", "reject"
    evaluations: list[RuleEvaluation]
    verdict: str              # "ALLOWED", "BLOCKED", "REJECTED"
    verdict_reason: str       # "by Rule #5" or "by default policy"


def diagnose_connection(
    state: HostFirewallState,
    source_ip: str,
    dest_port: int,
    dest_protocol: str,
    network_names: dict[str, str],
) -> DiagnosticResult:
    """Evaluate whether a connection would be allowed by UFW rules."""

    source_network = _identify_network(source_ip, network_names)

    evaluations = []
    matched_rule = None

    # Only evaluate IN rules (incoming connections)
    in_rules = [r for r in state.rules if r.direction == "IN" and not r.v6]

    for rule in in_rules:
        match, reason = _evaluate_rule(rule, source_ip, dest_port, dest_protocol)
        evaluations.append(RuleEvaluation(rule=rule, matched=match, reason=reason))
        if match and matched_rule is None:
            matched_rule = rule

    # Determine verdict
    if matched_rule:
        if matched_rule.action in ("ALLOW", "LIMIT"):
            verdict = "ALLOWED"
        elif matched_rule.action == "REJECT":
            verdict = "REJECTED"
        else:
            verdict = "BLOCKED"
        verdict_reason = f"by Rule #{matched_rule.number} — {matched_rule.explanation}"
    else:
        policy = state.default_incoming
        if policy == "allow":
            verdict = "ALLOWED"
        elif policy == "reject":
            verdict = "REJECTED"
        else:
            verdict = "BLOCKED"
        verdict_reason = f"by default policy ({policy} incoming)"

    return DiagnosticResult(
        source_ip=source_ip,
        source_network=source_network,
        dest_host=state.name,
        dest_port=dest_port,
        dest_protocol=dest_protocol,
        ufw_active=state.ufw_active,
        default_policy=state.default_incoming,
        evaluations=evaluations,
        verdict=verdict,
        verdict_reason=verdict_reason,
    )


def _evaluate_rule(
    rule: UFWRule,
    source_ip: str,
    dest_port: int,
    dest_protocol: str,
) -> tuple[bool, str]:
    """Check if a single rule matches the connection. Returns (matched, reason)."""

    # Check port match
    port_match = _port_matches(rule.to, dest_port, dest_protocol)
    if not port_match:
        expected = rule.to if rule.to != "Anywhere" else "all ports"
        return False, f"port {dest_port}/{dest_protocol} doesn't match {expected}"

    # Check source match
    source_match = _source_matches(rule.from_addr, source_ip)
    if not source_match:
        return False, f"source {source_ip} not in {rule.from_addr}"

    return True, f"port and source both match"


def _port_matches(to_field: str, port: int, protocol: str) -> bool:
    """Check if a UFW 'to' field matches a given port/protocol."""
    if to_field == "Anywhere":
        return True

    rule_proto = None
    port_part = to_field
    if "/" in to_field:
        port_part, rule_proto = to_field.rsplit("/", 1)

    # Protocol mismatch
    if rule_proto and rule_proto != protocol:
        return False

    # Range
    if ":" in port_part:
        try:
            start, end = port_part.split(":")
            return int(start) <= port <= int(end)
        except ValueError:
            return False

    # Multi-port
    if "," in port_part:
        try:
            return port in [int(p.strip()) for p in port_part.split(",")]
        except ValueError:
            return False

    # Single port
    try:
        return port == int(port_part)
    except ValueError:
        return False


def _source_matches(from_addr: str, source_ip: str) -> bool:
    """Check if a source IP matches a UFW 'from' field."""
    if from_addr == "Anywhere":
        return True

    try:
        network = ipaddress.ip_network(from_addr, strict=False)
        addr = ipaddress.ip_address(source_ip)
        return addr in network
    except ValueError:
        return from_addr == source_ip


def _identify_network(ip: str, network_names: dict[str, str]) -> str:
    """Find which named network an IP belongs to."""
    try:
        addr = ipaddress.ip_address(ip)
        for cidr, name in network_names.items():
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if addr in net:
                    return name
            except ValueError:
                continue
    except ValueError:
        pass
    return "Unknown network"
