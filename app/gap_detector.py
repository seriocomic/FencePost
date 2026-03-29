"""Gap detection — find listening ports without matching UFW rules."""

from __future__ import annotations

from .models import UFWRule, ListeningPort


def detect_gaps(
    rules: list[UFWRule],
    listening_ports: list[ListeningPort],
) -> list[ListeningPort]:
    """Return listening ports that have no matching ALLOW rule in UFW.

    Sets has_ufw_rule on each ListeningPort and returns only uncovered ones.
    """
    allowed_ports = _extract_allowed_ports(rules)

    uncovered = []
    for lp in listening_ports:
        if _port_is_covered(lp, allowed_ports):
            lp.has_ufw_rule = True
        else:
            lp.has_ufw_rule = False
            uncovered.append(lp)

    return uncovered


def _extract_allowed_ports(rules: list[UFWRule]) -> set[tuple[int | None, str | None]]:
    """Extract (port, protocol) pairs from ALLOW rules.

    Returns a set of tuples. A None port means "all ports" (Anywhere).
    """
    allowed = set()
    for r in rules:
        if r.action != "ALLOW" or r.direction != "IN":
            continue

        if r.to == "Anywhere":
            allowed.add((None, None))  # all ports allowed
            continue

        port_proto = _parse_port_proto(r.to)
        if port_proto:
            for pp in port_proto:
                allowed.add(pp)

    return allowed


def _parse_port_proto(to_field: str) -> list[tuple[int, str | None]]:
    """Parse a UFW 'to' field into (port, protocol) pairs.

    Handles: 22/tcp, 80,443/tcp, 8000:8100/tcp, 22 (no proto)
    """
    results = []

    proto = None
    if "/" in to_field:
        port_part, proto = to_field.rsplit("/", 1)
    else:
        port_part = to_field

    # Range: 8000:8100
    if ":" in port_part:
        try:
            start, end = port_part.split(":")
            for p in range(int(start), int(end) + 1):
                results.append((p, proto))
        except (ValueError, TypeError):
            pass
        return results

    # Multi-port: 80,443
    if "," in port_part:
        for p_str in port_part.split(","):
            try:
                results.append((int(p_str.strip()), proto))
            except ValueError:
                pass
        return results

    # Single port
    try:
        results.append((int(port_part), proto))
    except ValueError:
        pass

    return results


def _port_is_covered(
    lp: ListeningPort,
    allowed_ports: set[tuple[int | None, str | None]],
) -> bool:
    """Check if a listening port is covered by any ALLOW rule."""
    # "All ports" rule covers everything
    if (None, None) in allowed_ports:
        return True

    # Exact port+protocol match
    if (lp.port, lp.protocol) in allowed_ports:
        return True

    # Port match with no protocol restriction
    if (lp.port, None) in allowed_ports:
        return True

    return False
