"""Offline blue-team rules for synthetic lab events; no target mutation."""

from __future__ import annotations

from datetime import datetime
from typing import Any


L4_RULE_ID = "GADE-LAB-L4-SYNTHETIC-ROLE-LEASE-V1"
ADVANCED_RULE_EVENTS = {
    "l5-canary": "l5_canary_accessed", "l5-visibility": "l5_visibility_simulated",
    "l6-discovery": "l6_topology_discovered", "l6-session": "l6_session_established",
    "l7-collection": "l7_collection_created", "l7-c2": "l7_local_c2_acknowledged",
    "l7-transfer": "l7_receiver_accepted", "l7-impact": "l7_impact_simulated",
}


def detect_l4_role_lease(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Alert only on two independent event types with exact shared identity/hash.

    This is a rule result over supplied logs, not proof that a live blue-team
    service received or alerted on them.
    """
    created: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    alerts: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        identity = tuple(event.get(key) for key in (
            "run_id", "test_case_id", "request_id", "state_sha256"))
        if not all(isinstance(value, str) and value for value in identity):
            continue
        if event.get("event") == "l4_synthetic_persistence_created":
            created[identity] = event
        elif event.get("event") == "l4_test_role_granted" and identity in created:
            first = created[identity]
            try:
                first_time = datetime.fromisoformat(first["time_utc"].replace("Z", "+00:00"))
                alert_time = datetime.fromisoformat(event["time_utc"].replace("Z", "+00:00"))
                latency_ms = (alert_time - first_time).total_seconds() * 1000
            except (KeyError, TypeError, ValueError):
                continue
            if latency_ms < 0:
                continue
            alerts.append({"rule_id": L4_RULE_ID, "run_id": identity[0],
                           "test_case_id": identity[1], "request_id": identity[2],
                           "state_sha256": identity[3],
                           "source_events": [first["event"], event["event"]],
                           "first_event_utc": first["time_utc"],
                           "alert_event_utc": event["time_utc"],
                           "detection_latency_ms": round(latency_ms, 3),
                           "simulation": True})
    return alerts


def detect_advanced_synthetic(events: list[dict[str, Any]],
                              node_events: dict[str, list[dict[str, Any]]] | None = None) -> list[dict[str, Any]]:
    """Offline replay only. Correlate request/result and independent L6 node files."""
    starts: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    alerts: list[dict[str, Any]] = []
    node_events = node_events or {}
    for event in events:
        if not isinstance(event, dict):
            continue
        action = event.get("action")
        key = tuple(event.get(field) for field in
                    ("run_id", "test_case_id", "request_id", "state_sha256", "action"))
        if action not in ADVANCED_RULE_EVENTS or not all(isinstance(value, str) and value for value in key):
            continue
        if event.get("event") == "advanced_action_requested":
            starts[key] = event
            continue
        if event.get("event") != ADVANCED_RULE_EVENTS[action] or key not in starts:
            continue
        if action == "l6-session":
            source = [row for row in node_events.get("node-alpha", []) if row.get("event") == "l6_source_session_opened"]
            destination = [row for row in node_events.get("node-beta", []) if row.get("event") == "l6_destination_session_accepted"]
            if not all(any(all(row.get(field) == event.get(field) for field in
                               ("run_id", "test_case_id", "request_id", "state_sha256")) for row in rows)
                       for rows in (source, destination)):
                continue
        try:
            started = datetime.fromisoformat(starts[key]["time_utc"].replace("Z", "+00:00"))
            completed = datetime.fromisoformat(event["time_utc"].replace("Z", "+00:00"))
            latency_ms = (completed - started).total_seconds() * 1000
        except (KeyError, AttributeError, ValueError, TypeError):
            continue
        if latency_ms < 0:
            continue
        alerts.append({"rule_id": f"GADE-LAB-{action.upper()}-V1", "run_id": key[0],
                       "test_case_id": key[1], "request_id": key[2],
                       "state_sha256": key[3], "action": action,
                       "source_events": [starts[key]["event"], event["event"]],
                       "first_event_utc": starts[key]["time_utc"],
                       "alert_event_utc": event["time_utc"],
                       "detection_latency_ms": round(latency_ms, 3),
                       "detection_mode": "OFFLINE_REPLAY", "simulation": True})
    return alerts
