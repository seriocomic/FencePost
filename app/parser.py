"""Parsers for UFW and ss command output."""

from __future__ import annotations

import re
from datetime import datetime

from .models import UFWRule, ListeningPort


def parse_ufw_status_verbose(output: str) -> dict:
    """Parse `sudo ufw status verbose` output.

    Returns dict with keys: active, default_incoming, default_outgoing,
    default_routed, rules (list of partial UFWRule without numbers).
    """
    result = {
        "active": False,
        "default_incoming": "",
        "default_outgoing": "",
        "default_routed": "",
        "rules": [],
    }

    if not output or "inactive" in output.lower().split("\n")[0]:
        return result

    if "Status: active" in output:
        result["active"] = True

    # Parse default policies
    # Example: "Default: deny (incoming), allow (outgoing), disabled (routed)"
    default_match = re.search(
        r"Default:\s*(\w+)\s*\(incoming\),\s*(\w+)\s*\(outgoing\),\s*(\w+)\s*\(routed\)",
        output,
    )
    if default_match:
        result["default_incoming"] = default_match.group(1)
        result["default_outgoing"] = default_match.group(2)
        result["default_routed"] = default_match.group(3)

    # Parse rules from verbose output (used for direction + comment info)
    # Lines after the "---" separator
    in_rules = False
    for line in output.splitlines():
        if re.match(r"^-+\s*$", line):
            in_rules = True
            continue
        if not in_rules or not line.strip():
            continue

        rule = _parse_verbose_rule_line(line)
        if rule:
            result["rules"].append(rule)

    return result


def _parse_verbose_rule_line(line: str) -> UFWRule | None:
    """Parse a single rule line from ufw status verbose.

    Example lines:
      22/tcp                     ALLOW IN    192.168.0.0/24
      80/tcp                     ALLOW IN    Anywhere
      Anywhere                   DENY IN     Anywhere
      22/tcp (v6)                ALLOW IN    Anywhere (v6)
      80,443/tcp                 ALLOW IN    Anywhere              # web server
    """
    # Check for v6
    v6 = "(v6)" in line

    # Remove v6 markers for simpler parsing
    clean = line.replace("(v6)", "").strip()
    if not clean:
        return None

    # Extract comment (after #)
    comment = None
    if "#" in clean:
        parts = clean.split("#", 1)
        clean = parts[0].strip()
        comment = parts[1].strip()

    # Split into columns — UFW uses variable whitespace
    # Pattern: TO  ACTION DIRECTION  FROM
    match = re.match(
        r"^(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(.+)$",
        clean,
    )
    if not match:
        return None

    to_field = match.group(1).strip()
    action = match.group(2)
    direction = match.group(3)
    from_field = match.group(4).strip()

    return UFWRule(
        number=0,  # filled from numbered output
        to=to_field,
        action=action,
        from_addr=from_field,
        direction=direction,
        comment=comment,
        v6=v6,
    )


def parse_ufw_status_numbered(output: str) -> list[UFWRule]:
    """Parse `sudo ufw status numbered` output.

    Example lines:
      [ 1] 22/tcp                     ALLOW IN    192.168.0.0/24
      [ 2] 80/tcp                     ALLOW IN    Anywhere
      [12] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
    """
    rules = []
    for line in output.splitlines():
        # Match the [N] prefix
        num_match = re.match(r"^\[\s*(\d+)\]\s+(.+)$", line)
        if not num_match:
            continue

        number = int(num_match.group(1))
        rest = num_match.group(2)

        rule = _parse_verbose_rule_line(rest)
        if rule:
            rule.number = number
            rules.append(rule)

    return rules


def merge_rule_data(
    verbose_rules: list[UFWRule],
    numbered_rules: list[UFWRule],
) -> list[UFWRule]:
    """Merge data from verbose and numbered outputs.

    Numbered output is the authority for rule numbers.
    Verbose output may have extra info (comments are more reliably shown).
    We use numbered as the base and backfill comments from verbose.
    """
    # Build a lookup from verbose by (to, action, from_addr, v6)
    verbose_map: dict[tuple, UFWRule] = {}
    for r in verbose_rules:
        key = (r.to, r.action, r.from_addr, r.v6)
        verbose_map[key] = r

    for r in numbered_rules:
        key = (r.to, r.action, r.from_addr, r.v6)
        if key in verbose_map and verbose_map[key].comment:
            r.comment = verbose_map[key].comment

    return numbered_rules


def parse_ss_output(output: str) -> list[ListeningPort]:
    """Parse `sudo ss -tlnp` output.

    Example lines:
      LISTEN  0  4096  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
      LISTEN  0  128   127.0.0.1:8080  0.0.0.0:*  users:(("python3",pid=5678,fd=5))
      LISTEN  0  4096  [::]:22  [::]:*  users:(("sshd",pid=1234,fd=4))
      LISTEN  0  4096  *:80  *:*  users:(("nginx",pid=900,fd=6))
    """
    ports = []
    for line in output.splitlines():
        if not line.startswith("LISTEN"):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        # Parse local address:port
        local = parts[3]
        addr, port_str = _split_addr_port(local)
        if port_str is None:
            continue

        try:
            port = int(port_str)
        except ValueError:
            continue

        # Parse process name
        process = ""
        for part in parts:
            proc_match = re.search(r'users:\(\("([^"]+)"', part)
            if proc_match:
                process = proc_match.group(1)
                break

        is_external = addr in ("0.0.0.0", "::", "*", "[::]")

        ports.append(
            ListeningPort(
                port=port,
                protocol="tcp",
                address=addr,
                process=process,
                is_external=is_external,
            )
        )

    # Deduplicate — same port may appear for v4 and v6
    seen = set()
    unique = []
    for p in ports:
        key = (p.port, p.protocol)
        if key not in seen:
            seen.add(key)
            # Prefer the external-facing entry
            if not p.is_external:
                external = next(
                    (q for q in ports if q.port == p.port and q.is_external),
                    None,
                )
                if external:
                    continue
            unique.append(p)

    return unique


def _split_addr_port(local: str) -> tuple[str, str | None]:
    """Split an ss local address into (addr, port).

    Handles: 0.0.0.0:22, [::]:22, *:80, 127.0.0.1:8080
    """
    if local.startswith("["):
        # IPv6: [::]:22
        bracket_end = local.rfind("]")
        if bracket_end == -1:
            return local, None
        addr = local[: bracket_end + 1].strip("[]")
        port = local[bracket_end + 2 :]  # skip ]:
        return addr, port
    elif local.startswith("*:"):
        return "*", local[2:]
    else:
        # IPv4: 0.0.0.0:22
        last_colon = local.rfind(":")
        if last_colon == -1:
            return local, None
        return local[:last_colon], local[last_colon + 1 :]


def parse_stat_mtime(output: str) -> datetime | None:
    """Parse mtime from `stat /etc/ufw/user.rules` output.

    Looks for the Modify: line.
    Example: Modify: 2024-01-15 09:30:00.000000000 +1100
    """
    for line in output.splitlines():
        if line.strip().startswith("Modify:"):
            time_str = line.split("Modify:", 1)[1].strip()
            # Remove nanoseconds, parse
            time_str = re.sub(r"\.\d+", "", time_str)
            try:
                return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S %z")
            except ValueError:
                pass
    return None
