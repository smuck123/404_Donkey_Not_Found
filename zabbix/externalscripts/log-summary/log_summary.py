#!/usr/bin/env python3
"""Incrementally summarize local logs and publish structured results to Zabbix."""

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_STATE = "/var/lib/404-donkey-not-found/log-summary-state.json"
DEFAULT_LOCK = "/run/404-donkey-log-summary.lock"

LOG_GROUPS = {
    "security": ["/var/log/secure", "/var/log/audit/audit.log", "/var/log/firewalld"],
    "system": ["/var/log/messages", "/var/log/cron", "/var/log/spooler"],
    "package": ["/var/log/dnf.log", "/var/log/dnf.librepo.log"],
    "web": ["/var/log/nginx/access.log", "/var/log/nginx/error.log", "/var/log/php-fpm/error.log"],
    "zabbix": ["/var/log/zabbix/zabbix_server.log", "/var/log/zabbix/zabbix_agent2.log"],
    "custom": ["/var/log/fortigate_ai_sender.log", "/var/log/linux-ansible.log"],
}

RULES = {
    "ssh_failed_password": (r"sshd.*Failed password", 2),
    "ssh_invalid_user": (r"sshd.*Invalid user", 2),
    "sudo_auth_failure": (r"sudo:.*authentication failure", 5),
    "audit_avc_denied": (r"\btype=AVC\b.*\bdenied\b", 2),
    "audit_anom": (r"\btype=ANOM_[A-Z_]+\b", 8),
    "firewall_denied": (r"\b(denied|reject|drop)\b", 1),
    "kernel_io_error": (r"I/O error|blk_update_request|Buffer I/O error", 20),
    "filesystem_error": (r"EXT4-fs error|XFS.*Corruption|filesystem read-only", 25),
    "oom_killer": (r"Out of memory|Killed process .* out of memory", 25),
    "segfault": (r"\bsegfault\b", 15),
    "service_failed": (r"Failed to start|entered failed state|Start request repeated", 8),
    "network_error": (r"No route to host|Network is unreachable|connection timed out|link is down", 5),
    "cron_missing_script": (r"No such file or directory", 8),
    "cron_permission_denied": (r"Permission denied", 8),
    "repo_error": (r"Cannot download|Failed to download|Curl error|GPG error", 3),
    "dnf_traceback": (r"Traceback \(most recent call last\):", 5),
    "nginx_5xx": (r'"\s5\d\d\s', 2),
    "nginx_upstream_error": (r"upstream timed out|connect\(\) failed|no live upstreams", 6),
    "php_fatal": (r"PHP Fatal error", 6),
    "custom_connection_problem": (r"connection refused|failed to connect|name resolution", 4),
    "custom_error": (r"\bERROR\b|Traceback|fatal:", 5),
    "zabbix_unsupported": (r"unsupported item key|not supported", 2),
    "zabbix_database_problem": (r"cannot connect to database|database is down", 15),
    "zabbix_queue_problem": (r"queue.*seconds behind", 8),
    "zabbix_active_checks_error": (r"cannot send list of active checks|host \[.*\] not found", 6),
    "zabbix_allowed_hosts_reject": (r'connection from ".*" rejected, allowed hosts:', 3),
    "zabbix_permission_denied": (r"zabbix.*Permission denied|Permission denied.*zabbix", 8),
    "zabbix_sender_failed": (r"zabbix_sender failed rc=\d+", 6),
}
COMPILED = {name: (re.compile(pattern, re.I), weight) for name, (pattern, weight) in RULES.items()}

# Do not let sender/summary failures become input for the next summary.
SELF_NOISE = re.compile(
    r"zabbix_log_forwarder\.py.*zabbix_sender failed|"
    r"log_summary\.py.*zabbix_sender|"
    r"send_log_summary\.sh",
    re.I,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, path)


def selected_files(groups: list[str]) -> list[Path]:
    selected = list(LOG_GROUPS) if "all" in groups else groups
    return sorted({Path(name) for group in selected for name in LOG_GROUPS.get(group, []) if Path(name).is_file()})


def read_increment(path: Path, previous: dict, max_lines: int) -> tuple[list[str], dict, int]:
    stat = path.stat()
    previous_inode = previous.get("inode")
    offset = int(previous.get("offset", stat.st_size))
    # A new installation establishes a baseline at EOF. Only a known file that
    # rotated or shrank should be read from the beginning.
    if previous_inode is not None and (previous_inode != stat.st_ino or offset > stat.st_size):
        offset = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        all_lines = handle.readlines()
        new_offset = handle.tell()
    dropped = max(0, len(all_lines) - max_lines)
    return all_lines[-max_lines:], {"inode": stat.st_ino, "offset": new_offset}, dropped


def analyze(lines: list[str]) -> tuple[Counter, Counter]:
    counts: Counter = Counter()
    samples: Counter = Counter()
    for raw in lines:
        if SELF_NOISE.search(raw):
            counts["self_noise_ignored"] += 1
            continue
        matched = False
        for name, (pattern, _) in COMPILED.items():
            if pattern.search(raw):
                counts[name] += 1
                matched = True
        if not matched and raw.strip():
            normalized = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<IP>", raw.strip())
            samples[normalized[:240]] += 1
    return counts, samples


def score(counts: Counter) -> int:
    value = sum(counts[name] * weight for name, (_, weight) in COMPILED.items())
    return min(100, value)


def label(value: int) -> str:
    return "high" if value >= 70 else "medium" if value >= 30 else "low"


def deterministic_summary(counts: Counter) -> str:
    findings = [f"{name.replace('_', ' ')}: {count}" for name, count in counts.most_common() if count and name != "self_noise_ignored"]
    return "; ".join(findings[:5]) if findings else "No notable new log events."


def ollama_summary(payload: dict, url: str, model: str, timeout: float, retries: int) -> str:
    request_body = {
        "model": model,
        "stream": False,
        "think": False,
        "messages": [
            {"role": "system", "content": "You are a Linux operations analyst. Answer in at most two plain-text sentences. State the main operational issue and whether a security breach is suspected. Use only supplied facts. Do not use Markdown. dropped_lines only indicates an input safety cap and is not itself an incident or severity signal."},
            {"role": "user", "content": json.dumps(payload, separators=(",", ":"))},
        ],
    }
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, json.dumps(request_body).encode(), {"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                result = json.loads(response.read().decode())
            answer = result.get("message", {}).get("content", "").strip()
            if answer:
                return re.sub(r"\s+", " ", answer)[:1000]
            raise RuntimeError("Ollama returned an empty answer")
        except Exception as exc:  # network and malformed-response failures use the safe fallback
            last_error = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(str(last_error))


def send_value(server: str, host: str, key: str, value: str) -> None:
    completed = subprocess.run(
        ["/usr/bin/zabbix_sender", "-z", server, "-s", host, "-k", key, "-o", value],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if completed.returncode or "failed: 0" not in completed.stdout:
        raise RuntimeError(f"sender rejected {key}: {completed.stdout.strip()} {completed.stderr.strip()}")


def run(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file)
    state = load_state(state_path)
    now = int(time.time())
    previous_run = int(state.get("last_run", now))
    next_state = {"last_run": now, "files": {}}
    totals: Counter = Counter()
    file_results = []
    total_lines = 0
    dropped_lines = 0

    for path in selected_files(args.group):
        lines, file_state, dropped = read_increment(path, state.get("files", {}).get(str(path), {}), args.max_lines_per_file)
        counts, samples = analyze(lines)
        totals.update(counts)
        total_lines += len(lines)
        dropped_lines += dropped
        next_state["files"][str(path)] = file_state
        file_results.append({"path": str(path), "new_lines_analyzed": len(lines), "dropped_lines": dropped, "counts": dict(counts), "top_unmatched": [{"message": text, "count": count} for text, count in samples.most_common(3)]})

    severity_score = score(totals)
    breach = int(bool(totals["audit_anom"] or (totals["ssh_failed_password"] >= 20 and totals["ssh_invalid_user"] >= 5)))
    attack_type = "audit_anomaly" if totals["audit_anom"] else "ssh_bruteforce" if breach else "none"
    stable_counts = {name: int(totals.get(name, 0)) for name in RULES}
    stable_counts["self_noise_ignored"] = int(totals.get("self_noise_ignored", 0))
    result = {
        "schema": "donkey_log_summary_v2",
        "generated_at": utc_now(),
        "period_seconds": max(0, now - previous_run),
        "status": "ok",
        "analysis_source": "deterministic",
        "total_new_lines": total_lines,
        "dropped_lines": dropped_lines,
        "severity_score": severity_score,
        "severity_label": label(severity_score),
        "breach_suspected": breach,
        "attack_type": attack_type,
        "summary_text": deterministic_summary(totals),
        "counts_flat": stable_counts,
        "files": file_results,
    }
    fallback = deterministic_summary(totals)
    if args.mode in ("ollama", "both"):
        try:
            result["ai_summary"] = ollama_summary(result, args.ollama_url, args.ollama_model, args.ollama_timeout, args.ollama_retries)
            result["analysis_source"] = "ollama"
        except Exception as exc:
            result["status"] = "partial"
            result["analysis_error"] = f"ollama unavailable: {exc}"
            result["ai_summary"] = fallback
    else:
        result["ai_summary"] = fallback

    # Advance offsets before publishing so our own sender logs cannot be re-read.
    save_state(state_path, next_state)
    if args.send_zabbix:
        send_value(args.zabbix_server, args.zabbix_host, args.raw_key, json.dumps(result, separators=(",", ":")))
        send_value(args.zabbix_server, args.zabbix_host, args.text_key, result["ai_summary"])
    print(result["ai_summary"] if args.output == "text" else json.dumps(result, separators=(",", ":")))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--group", action="append", default=[])
    parser.add_argument("--mode", choices=["basic", "ollama", "both"], default="both")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434/api/chat")
    parser.add_argument("--ollama-model", default="qwen3.5:9b")
    parser.add_argument("--ollama-timeout", type=float, default=45)
    parser.add_argument("--ollama-retries", type=int, default=2)
    parser.add_argument("--max-lines-per-file", type=int, default=5000)
    parser.add_argument("--state-file", default=DEFAULT_STATE)
    parser.add_argument("--lock-file", default=DEFAULT_LOCK)
    parser.add_argument("--send-zabbix", action="store_true")
    parser.add_argument("--zabbix-server", default="127.0.0.1")
    parser.add_argument("--zabbix-host", default="")
    parser.add_argument("--raw-key", default="log.summary.raw")
    parser.add_argument("--text-key", default="log.summary.text")
    parser.add_argument("--output", choices=["json", "text"], default="json")
    args = parser.parse_args()
    args.group = args.group or ["all"]
    if args.send_zabbix and not args.zabbix_host:
        parser.error("--zabbix-host is required with --send-zabbix")
    with open(args.lock_file, "w", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("log summary already running", file=sys.stderr)
            return 0
        return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

