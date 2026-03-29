"""EventFeed integration — change detection and webhook posting."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .models import HostFirewallState

logger = logging.getLogger(__name__)

STATE_FILE = Path("/app/data/last_state.json")


def _state_snapshot(hosts: list[HostFirewallState]) -> dict:
    """Create a comparable snapshot of current state."""
    snapshot = {}
    for h in hosts:
        snapshot[h.name] = {
            "ufw_active": h.ufw_active,
            "ufw_installed": h.ufw_installed,
            "reachable": h.fetch_error is None,
            "rule_count": len(h.rules),
            "rules": [
                {"number": r.number, "to": r.to, "action": r.action, "from_addr": r.from_addr}
                for r in h.rules
            ],
            "uncovered_external": [
                {"port": p.port, "process": p.process}
                for p in h.external_gaps
            ],
        }
    return snapshot


def _load_previous() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_current(snapshot: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(snapshot, indent=2))


def detect_and_notify(
    hosts: list[HostFirewallState],
    eventfeed_url: str,
    api_key: str,
    channel: str,
) -> list[str]:
    """Compare current state to previous, POST events for changes.

    Returns list of event descriptions that were sent.
    """
    current = _state_snapshot(hosts)
    previous = _load_previous()
    events = []

    for h in hosts:
        name = h.name
        prev = previous.get(name, {})

        # Host became unreachable
        if h.fetch_error and prev.get("reachable", True):
            events.append(_event(
                channel, f"Cannot reach {name} via SSH",
                f"Error: {h.fetch_error}", "error",
                ["ssh", "unreachable", _slug(name)],
                f"unreachable-{_slug(name)}",
            ))

        # Host became reachable again
        if not h.fetch_error and not prev.get("reachable", True):
            events.append(_event(
                channel, f"{name} is reachable again via SSH",
                None, "success",
                ["ssh", "recovered", _slug(name)],
                f"reachable-{_slug(name)}",
            ))

        # UFW deactivated
        if prev.get("ufw_active") and not h.ufw_active and not h.fetch_error:
            events.append(_event(
                channel, f"UFW is INACTIVE on {name}",
                "Firewall has been disabled", "error",
                ["ufw", "inactive", _slug(name)],
                f"ufw-inactive-{_slug(name)}",
            ))

        # UFW activated
        if not prev.get("ufw_active", True) and h.ufw_active:
            events.append(_event(
                channel, f"UFW is now ACTIVE on {name}",
                None, "success",
                ["ufw", "active", _slug(name)],
                f"ufw-active-{_slug(name)}",
            ))

        # Rules added/removed
        prev_rules = {(r["to"], r["action"], r["from_addr"]) for r in prev.get("rules", [])}
        curr_rules = {(r.to, r.action, r.from_addr) for r in h.rules}

        for added in curr_rules - prev_rules:
            events.append(_event(
                channel, f"UFW rule added on {name}",
                f"{added[1]} {added[0]} from {added[2]}", "info",
                ["ufw", "rule-added", _slug(name)],
                f"rule-add-{_slug(name)}-{added[0]}-{added[1]}",
            ))

        for removed in prev_rules - curr_rules:
            events.append(_event(
                channel, f"UFW rule removed on {name}",
                f"{removed[1]} {removed[0]} from {removed[2]}", "warning",
                ["ufw", "rule-removed", _slug(name)],
                f"rule-rm-{_slug(name)}-{removed[0]}-{removed[1]}",
            ))

        # New uncovered external ports
        prev_gaps = {p["port"] for p in prev.get("uncovered_external", [])}
        curr_gaps = {p.port for p in h.external_gaps}
        for port in curr_gaps - prev_gaps:
            lp = next((p for p in h.external_gaps if p.port == port), None)
            proc = lp.process if lp else "unknown"
            events.append(_event(
                channel, f"Uncovered port on {name}: {port}/tcp ({proc})",
                "Listening on all interfaces with no UFW rule", "warning",
                ["gap", _slug(name)],
                f"gap-{_slug(name)}-{port}",
            ))

    # Send events
    sent = []
    for ev in events:
        try:
            _post_event(ev, eventfeed_url, api_key)
            sent.append(ev["title"])
        except Exception as e:
            logger.error("Failed to post event: %s — %s", ev["title"], e)

    # Save current state
    _save_current(current)

    return sent


def _event(
    channel: str,
    title: str,
    body: str | None,
    level: str,
    tags: list[str],
    idempotency_suffix: str,
) -> dict:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
    return {
        "channel": channel,
        "title": title,
        "body": body or "",
        "level": level,
        "tags": tags,
        "idempotency_key": f"fencepost-{idempotency_suffix}-{ts}",
    }


def _post_event(event: dict, url: str, api_key: str) -> None:
    resp = httpx.post(
        url,
        json=event,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        timeout=10,
    )
    resp.raise_for_status()
    logger.info("EventFeed: %s → %s", event["title"], resp.status_code)


def _slug(name: str) -> str:
    return name.lower().replace(" ", "-")
