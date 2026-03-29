"""SSH client wrapper using paramiko for remote command execution."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone

import paramiko
import yaml

from .models import HostFirewallState
from .parser import (
    merge_rule_data,
    parse_ss_output,
    parse_stat_mtime,
    parse_ufw_status_numbered,
    parse_ufw_status_verbose,
)
from .explainer import explain_rules
from .gap_detector import detect_gaps

logger = logging.getLogger(__name__)

COMMANDS = [
    "sudo ufw status verbose",
    "sudo ufw status numbered",
    "sudo ss -tlnp",
    "stat /etc/ufw/user.rules 2>/dev/null",
]


@dataclass
class HostConfig:
    name: str
    hostname: str
    ssh_user: str
    ssh_port: int = 22
    is_docker_host: bool = False


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def get_hosts(config: dict) -> list[HostConfig]:
    return [
        HostConfig(
            name=h["name"],
            hostname=h["hostname"],
            ssh_user=h["ssh_user"],
            ssh_port=h.get("ssh_port", 22),
            is_docker_host=h.get("is_docker_host", False),
        )
        for h in config.get("hosts", [])
    ]


def fetch_host(
    host: HostConfig,
    ssh_key_path: str,
    timeout: int = 10,
    network_names: dict[str, str] | None = None,
) -> HostFirewallState:
    """SSH into a host, run commands, parse output, return state."""
    state = HostFirewallState(
        name=host.name,
        hostname=host.hostname,
        is_docker_host=host.is_docker_host,
        fetch_timestamp=datetime.now(timezone.utc),
    )

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host.hostname,
            port=host.ssh_port,
            username=host.ssh_user,
            key_filename=ssh_key_path,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
        )

        results = {}
        for cmd in COMMANDS:
            try:
                _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                results[cmd] = stdout.read().decode("utf-8", errors="replace")
            except Exception as e:
                logger.warning("Command %r failed on %s: %s", cmd, host.name, e)
                results[cmd] = ""

        client.close()

    except Exception as e:
        state.fetch_error = str(e)
        logger.error("SSH failed for %s: %s", host.name, e)
        return state

    # Parse UFW verbose
    verbose = parse_ufw_status_verbose(results[COMMANDS[0]])
    state.ufw_active = verbose["active"]
    state.default_incoming = verbose["default_incoming"]
    state.default_outgoing = verbose["default_outgoing"]
    state.default_routed = verbose["default_routed"]

    # Check if UFW is installed (if verbose output is empty/error-like)
    verbose_output = results[COMMANDS[0]]
    if "command not found" in verbose_output.lower() or (
        not verbose_output.strip()
        and not results[COMMANDS[1]].strip()
    ):
        state.ufw_installed = False
        # Still parse ss data
        state.listening_ports = parse_ss_output(results[COMMANDS[2]])
        return state

    # Parse UFW numbered
    numbered_rules = parse_ufw_status_numbered(results[COMMANDS[1]])
    verbose_rules = verbose["rules"]

    # Merge rule data
    state.rules = merge_rule_data(verbose_rules, numbered_rules)

    # Parse listening ports
    state.listening_ports = parse_ss_output(results[COMMANDS[2]])

    # Parse rules modification time
    state.rules_last_modified = parse_stat_mtime(results[COMMANDS[3]])

    # Explain rules
    explain_rules(state.rules, state.listening_ports, network_names or {})

    # Detect gaps
    state.uncovered_ports = detect_gaps(state.rules, state.listening_ports)

    return state


def fetch_all_hosts(
    config: dict,
) -> list[HostFirewallState]:
    """Fetch firewall state from all configured hosts in parallel."""
    hosts = get_hosts(config)
    ssh_config = config.get("ssh", {})
    key_path = ssh_config.get("key_path", "/app/ssh/id_ed25519")
    timeout = ssh_config.get("timeout", 10)
    network_names = config.get("networks", {})

    states = []
    with ThreadPoolExecutor(max_workers=len(hosts)) as executor:
        futures = {
            executor.submit(
                fetch_host, host, key_path, timeout, network_names
            ): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                state = future.result()
            except Exception as e:
                state = HostFirewallState(
                    name=host.name,
                    hostname=host.hostname,
                    is_docker_host=host.is_docker_host,
                    fetch_error=str(e),
                    fetch_timestamp=datetime.now(timezone.utc),
                )
            states.append(state)

    # Sort by config order
    host_order = {h["name"]: i for i, h in enumerate(config.get("hosts", []))}
    states.sort(key=lambda s: host_order.get(s.name, 999))

    return states


def fetch_single_host(
    config: dict,
    host_name: str,
) -> HostFirewallState | None:
    """Fetch state for a single host by name."""
    hosts = get_hosts(config)
    target = next((h for h in hosts if h.name == host_name), None)
    if not target:
        return None

    ssh_config = config.get("ssh", {})
    key_path = ssh_config.get("key_path", "/app/ssh/id_ed25519")
    timeout = ssh_config.get("timeout", 10)
    network_names = config.get("networks", {})

    return fetch_host(target, key_path, timeout, network_names)
