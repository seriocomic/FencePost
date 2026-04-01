"""Shadow/conflict detection -- finds rules that can never fire."""

from __future__ import annotations

import ipaddress

from .models import UFWRule


def detect_shadows(rules: list[UFWRule]) -> None:
    """Mutate rules in-place, marking shadowed rules.

    A rule is shadowed when an earlier rule (lower number) already covers
    all traffic that would match it. UFW evaluates top-to-bottom, first
    match wins, so the later rule never fires.
    """
    v4_rules = [r for r in rules if not r.v6]

    for j, later in enumerate(v4_rules):
        if later.shadowed_by is not None:
            continue
        for i, earlier in enumerate(v4_rules):
            if i >= j:
                break
            if earlier.direction != later.direction:
                continue
            if not _port_covers(earlier.to, later.to):
                continue
            if not _source_covers(earlier.from_addr, later.from_addr):
                continue

            later.shadowed_by = earlier.number

            if (earlier.to == later.to and earlier.from_addr == later.from_addr
                    and earlier.action == later.action):
                later.shadow_type = "duplicate"
                later.shadow_note = (
                    f"Duplicate of rule #{earlier.number} -- "
                    f"identical port, source, and action."
                )
            elif earlier.action == later.action:
                later.shadow_type = "redundant"
                later.shadow_note = (
                    f"Rule #{earlier.number} already covers this traffic "
                    f"with the same action ({earlier.action}). "
                    f"This rule is redundant and can be removed."
                )
            else:
                later.shadow_type = "conflict"
                later.shadow_note = (
                    f"Rule #{earlier.number} ({earlier.action}) matches first, "
                    f"so this rule's {later.action} action never applies. "
                    f"The rules conflict."
                )
            break


def _port_covers(outer_to: str, inner_to: str) -> bool:
    """Check if outer port spec covers all traffic matched by inner."""
    if outer_to == "Anywhere":
        return True
    if outer_to == inner_to:
        return True

    outer_ports = _expand_ports(outer_to)
    inner_ports = _expand_ports(inner_to)

    if outer_ports is None or inner_ports is None:
        return outer_to == inner_to

    return inner_ports.issubset(outer_ports)


def _expand_ports(to_field: str) -> set[tuple[int, str]] | None:
    """Expand a UFW 'to' field into a set of (port, protocol) tuples."""
    if to_field == "Anywhere":
        return None

    proto = ""
    port_part = to_field
    if "/" in to_field:
        port_part, proto = to_field.rsplit("/", 1)

    ports = set()

    if ":" in port_part:
        try:
            start, end = port_part.split(":")
            for p in range(int(start), int(end) + 1):
                ports.add((p, proto))
        except ValueError:
            return None
    elif "," in port_part:
        try:
            for p in port_part.split(","):
                ports.add((int(p.strip()), proto))
        except ValueError:
            return None
    else:
        try:
            ports.add((int(port_part), proto))
        except ValueError:
            return None

    return ports


def _source_covers(outer_addr: str, inner_addr: str) -> bool:
    """Check if outer source covers all IPs matched by inner."""
    if outer_addr == "Anywhere":
        return True
    if outer_addr == inner_addr:
        return True

    try:
        outer_net = ipaddress.ip_network(outer_addr, strict=False)
        inner_net = ipaddress.ip_network(inner_addr, strict=False)
        return (outer_net.network_address <= inner_net.network_address
                and outer_net.broadcast_address >= inner_net.broadcast_address)
    except ValueError:
        return outer_addr == inner_addr
