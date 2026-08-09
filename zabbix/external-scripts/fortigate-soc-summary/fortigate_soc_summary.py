#!/usr/bin/env python3
"""Build read-only FortiGate SOC summaries from a local FortiGate syslog file."""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from typing import Any

KV_RE = re.compile(r'(\w+)=(".*?"|\S+)')
DEFAULT_LOG = "/var/log/fw/fortigate.json"
DEFAULT_LINES = 5000


def parse_kv(message: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in KV_RE.findall(message):
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        result[key] = value
    return result


def first(record: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def top(counter: Counter[str], limit: int = 10) -> list[dict[str, Any]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def enriched_top(
    counter: Counter[str],
    metadata: dict[str, dict[str, str]],
    limit: int = 10,
) -> list[dict[str, Any]]:
    return [
        {"value": value, "count": count, **metadata.get(value, {})}
        for value, count in counter.most_common(limit)
    ]


def read_tail(path: str, maximum: int) -> tuple[deque[str], int]:
    lines: deque[str] = deque(maxlen=maximum)
    read_errors = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                lines.append(line.rstrip("\n"))
    except OSError:
        read_errors += 1
    return lines, read_errors


def collect(path: str, maximum: int) -> dict[str, Any]:
    lines, parse_errors = read_tail(path, maximum)
    actions: Counter[str] = Counter()
    directions: Counter[str] = Counter()
    destination_ips: Counter[str] = Counter()
    destination_countries: Counter[str] = Counter()
    destination_services: Counter[str] = Counter()
    destination_ports: Counter[str] = Counter()
    destination_names: Counter[str] = Counter()
    destination_owners: Counter[str] = Counter()
    inbound_sources: Counter[str] = Counter()
    inbound_countries: Counter[str] = Counter()
    denied_ports: Counter[str] = Counter()
    policies: Counter[str] = Counter()
    internal_devices: Counter[str] = Counter()
    source_targets: dict[str, set[str]] = defaultdict(set)
    source_ports: dict[str, set[str]] = defaultdict(set)
    destination_metadata: dict[str, dict[str, str]] = {}
    source_metadata: dict[str, dict[str, str]] = {}
    recent: deque[dict[str, Any]] = deque(maxlen=20)
    traffic_events = 0

    for raw_line in lines:
        try:
            outer = json.loads(raw_line)
        except (TypeError, ValueError):
            parse_errors += 1
            continue
        if not isinstance(outer, dict):
            parse_errors += 1
            continue

        parsed = parse_kv(str(outer.get("message", "")))
        record: dict[str, Any] = {**outer, **parsed}
        if first(record, "type").lower() != "traffic":
            continue

        traffic_events += 1
        action = first(record, "action", default="unknown").lower()
        srcip = first(record, "srcip", "src", default="unknown")
        dstip = first(record, "dstip", "dst", default="unknown")
        dstport = first(record, "dstport", default="0")
        srcrole = first(record, "srcintfrole", default="").lower()
        dstrole = first(record, "dstintfrole", default="").lower()
        srccountry = first(record, "srccountry", "src_country", default="unknown")
        dstcountry = first(record, "dstcountry", "dst_country", default="unknown")
        service = first(record, "service", "app", "application", default=dstport)
        policy = first(record, "policyname", "policyid", default="unknown")
        destination_name = first(
            record, "dsthostname", "dstname", "hostname", default=dstip
        )
        destination_owner = first(
            record, "dstowner", "organization", "owner", default=dstcountry
        )

        if srcrole == "wan":
            direction = "inbound"
        elif dstrole == "wan":
            direction = "outbound"
        else:
            direction = "internal"
        directions[direction] += 1
        actions[action] += 1

        if direction == "outbound":
            destination_ips[dstip] += 1
            destination_countries[dstcountry] += 1
            destination_services[service] += 1
            destination_ports[dstport] += 1
            destination_names[destination_name] += 1
            destination_owners[destination_owner] += 1
            internal_devices[srcip] += 1
            destination_metadata[dstip] = {
                "country": dstcountry,
                "service": service,
                "port": dstport,
                "name": destination_name,
                "owner": destination_owner,
            }

        if direction == "inbound":
            inbound_sources[srcip] += 1
            inbound_countries[srccountry] += 1
            source_targets[srcip].add(dstip)
            source_ports[srcip].add(dstport)
            source_metadata[srcip] = {
                "country": srccountry,
                "service": service,
                "destination_port": dstport,
            }
            if action == "deny":
                denied_ports[dstport] += 1

        policies[policy] += 1
        recent.append(
            {
                "time": first(outer, "timestamp", default=""),
                "direction": direction,
                "action": action,
                "srcip": srcip,
                "dstip": dstip,
                "dstcountry": dstcountry,
                "service": service,
                "dstport": dstport,
                "policy": policy,
            }
        )

    possible_scanners = []
    for source, count in inbound_sources.most_common():
        target_count = len(source_targets[source])
        port_count = len(source_ports[source])
        if count >= 20 and (target_count >= 3 or port_count >= 5):
            possible_scanners.append(
                {
                    "source_ip": source,
                    "events": count,
                    "distinct_targets": target_count,
                    "distinct_ports": port_count,
                    **source_metadata.get(source, {}),
                }
            )
        if len(possible_scanners) >= 10:
            break

    denied = actions.get("deny", 0)
    accepted = actions.get("accept", 0) + actions.get("close", 0)
    anomalies = []
    if traffic_events and denied / traffic_events >= 0.50:
        anomalies.append(
            {
                "code": "high_deny_ratio",
                "severity": "warning",
                "deny_ratio": round(denied / traffic_events, 3),
            }
        )
    if parse_errors:
        anomalies.append(
            {
                "code": "parse_errors",
                "severity": "warning",
                "count": parse_errors,
            }
        )
    if possible_scanners:
        anomalies.append(
            {
                "code": "possible_scanners",
                "severity": "warning",
                "count": len(possible_scanners),
            }
        )

    generated_at = datetime.now(timezone.utc).isoformat()
    top_outbound = enriched_top(destination_ips, destination_metadata)
    top_inbound = enriched_top(inbound_sources, source_metadata)
    rich_summary = {
        "schema": "fortigate_soc_summary_v1",
        "generated_at": generated_at,
        "source_log": path,
        "window_lines": len(lines),
        "total_events": traffic_events,
        "parse_errors": parse_errors,
        "traffic": dict(directions),
        "actions": dict(actions),
        "top_destination_ips": top_outbound,
        "top_destination_countries": top(destination_countries),
        "top_destination_services": top(destination_services),
        "top_destination_ports": top(destination_ports),
        "top_external_sources": top_inbound,
        "top_source_countries": top(inbound_countries),
        "top_policies": top(policies),
        "possible_scanners": possible_scanners,
        "anomalies": anomalies,
        "recent": list(recent),
    }
    summary_text = (
        f"{traffic_events} events: "
        f"{directions.get('outbound', 0)} outbound, "
        f"{directions.get('inbound', 0)} inbound, "
        f"{directions.get('internal', 0)} internal; "
        f"{denied} denied and {accepted} accepted/closed."
    )

    items: dict[str, Any] = {
        "fortigate.actions": [],
        "fortigate.anomalies": anomalies,
        "fortigate.denied_port_heatmap": top(denied_ports, 20),
        "fortigate.distributed_scan_targets": [
            {
                "source_ip": source,
                "targets": sorted(source_targets[source])[:20],
                "target_count": len(source_targets[source]),
            }
            for source, _ in inbound_sources.most_common(10)
            if len(source_targets[source]) > 1
        ],
        "fortigate.expected_vs_unexpected": {
            "expected": accepted,
            "unexpected": denied,
            "unknown": actions.get("unknown", 0),
        },
        "fortigate.grouped_destination_names": top(destination_names),
        "fortigate.grouped_destination_owners": top(destination_owners),
        "fortigate.new_findings": anomalies,
        "fortigate.ollama.summary": summary_text,
        "fortigate.parse_errors": parse_errors,
        "fortigate.policy_summary": top(policies, 20),
        "fortigate.possible_scanners": possible_scanners,
        "fortigate.soc.rich_summary": rich_summary,
        "fortigate.suspicious_country_scores": top(inbound_countries),
        "fortigate.top_external_attackers_enriched": top_inbound,
        "fortigate.top_internal_devices_grouped": top(internal_devices),
        "fortigate.top_internal_to_external_destinations_enriched": top_outbound,
        "fortigate.total_events": traffic_events,
    }
    return {
        "schema": "fortigate_soc_sender_v1",
        "generated_at": generated_at,
        "items": items,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default=os.getenv("FORTIGATE_LOG", DEFAULT_LOG))
    parser.add_argument(
        "--lines",
        type=int,
        default=int(os.getenv("FORTIGATE_SOC_LINES", str(DEFAULT_LINES))),
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    payload = collect(args.log, max(100, min(args.lines, 100000)))
    json.dump(
        payload,
        fp=os.sys.stdout,
        ensure_ascii=False,
        indent=2 if args.pretty else None,
        separators=None if args.pretty else (",", ":"),
    )
    os.sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
