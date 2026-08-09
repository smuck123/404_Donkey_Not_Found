import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import quote

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(
    title="404 Donkey FortiGate Actions",
    version="0.1.0",
    description="Approval-gated IP block and unblock actions for two fixed FortiGate groups.",
)


class FortiGateNotFound(Exception):
    pass
DATA_DIR = Path(os.getenv("ACTION_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "actions.db"
AUDIT_PATH = DATA_DIR / "audit.jsonl"
TTL = max(60, min(int(os.getenv("ACTION_APPROVAL_TTL_SECONDS", "300")), 1800))
FG_URL = os.getenv("FORTIGATE_URL", "").rstrip("/")
FG_TOKEN = os.getenv("FORTIGATE_WRITE_TOKEN", "")
FG_VDOM = os.getenv("FORTIGATE_VDOM", "root")
VERIFY_SSL = os.getenv("FORTIGATE_VERIFY_SSL", "true").lower() in {"1", "true", "yes"}
ACTION_KEY = os.getenv("FORTIGATE_ACTION_KEY", "")
GROUPS = {"inbound": "AI-BLOCK-IN", "outbound": "AI-BLOCK-OUT"}
PROTECTED = [
    ipaddress.ip_network(value.strip(), strict=False)
    for value in os.getenv(
        "FORTIGATE_PROTECTED_CIDRS",
        "192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fe80::/10",
    ).split(",")
    if value.strip()
]


class PreviewRequest(BaseModel):
    action: Literal["block", "unblock"]
    ip: str = Field(min_length=2, max_length=64)
    direction: Literal["inbound", "outbound"]
    reason: str = Field(min_length=3, max_length=500)
    requested_by: str = Field(min_length=1, max_length=100)


class ConfirmRequest(BaseModel):
    proposal_id: str = Field(pattern=r"^[a-f0-9]{24}$")
    confirmation_code: str = Field(pattern=r"^[A-Z0-9]{8}$")
    approved_by: str = Field(min_length=1, max_length=100)


def require_action_key(x_action_key: str = Header(default="")) -> None:
    if not ACTION_KEY or not hmac.compare_digest(x_action_key, ACTION_KEY):
        raise HTTPException(status_code=401, detail="Valid X-Action-Key required")


def normalize_ip(raw: str) -> str:
    try:
        address = ipaddress.ip_address(raw.strip())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="A valid IP address is required") from exc
    if address.version != 4:
        raise HTTPException(status_code=422, detail="The first release supports IPv4 only")
    if not address.is_global or any(address in network for network in PROTECTED):
        raise HTTPException(status_code=422, detail="Only unprotected public IP addresses are allowed")
    return address.compressed


def object_name(ip: str, direction: str) -> str:
    digest = hashlib.sha256(ip.encode()).hexdigest()[:12].upper()
    return f"AI_{'IN' if direction == 'inbound' else 'OUT'}_{digest}"


@contextmanager
def database():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS proposals (
        id TEXT PRIMARY KEY, code TEXT NOT NULL, action TEXT NOT NULL, ip TEXT NOT NULL,
        direction TEXT NOT NULL, reason TEXT NOT NULL, requested_by TEXT NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL,
        approved_by TEXT, completed_at INTEGER, result TEXT)"""
    )
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def audit(event: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with AUDIT_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"timestamp": int(time.time()), **event}, separators=(",", ":")) + "\n")


def settings_ready() -> None:
    if not FG_URL or not FG_TOKEN or not ACTION_KEY:
        raise HTTPException(status_code=503, detail="Action service is not fully configured")


async def fg_request(method: str, path: str, body: dict | None = None) -> dict:
    headers = {"Authorization": f"Bearer {FG_TOKEN}", "Content-Type": "application/json"}
    timeout = httpx.Timeout(15.0, connect=4.0)
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=timeout) as client:
        response = await client.request(
            method, f"{FG_URL}{path}", headers=headers,
            params={"vdom": FG_VDOM}, json=body,
        )
    if response.status_code == 404:
        raise FortiGateNotFound(path)
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"FortiGate rejected the approved action (HTTP {response.status_code})")
    if not response.content:
        return {}
    try:
        data = response.json()
    except ValueError:
        return {}
    if isinstance(data, dict) and str(data.get("status", "success")).lower() not in {"success", ""}:
        raise HTTPException(status_code=502, detail="FortiGate did not report success")
    return data if isinstance(data, dict) else {}


async def group_members(group: str) -> list[dict[str, str]]:
    data = await fg_request("GET", f"/api/v2/cmdb/firewall/addrgrp/{quote(group, safe='')}")
    results = data.get("results", {})
    if isinstance(results, list):
        results = results[0] if results else {}
    members = results.get("member", []) if isinstance(results, dict) else []
    return [{"name": str(row["name"])} for row in members if isinstance(row, dict) and row.get("name")]


async def apply_action(action: str, ip: str, direction: str, reason: str) -> dict:
    group = GROUPS[direction]
    name = object_name(ip, direction)
    members = await group_members(group)
    names = {row["name"] for row in members}
    address_path = f"/api/v2/cmdb/firewall/address/{quote(name, safe='')}"
    if action == "block":
        created = False
        try:
            await fg_request("GET", address_path)
        except FortiGateNotFound:
            await fg_request("POST", "/api/v2/cmdb/firewall/address", {
                "name": name, "type": "ipmask", "subnet": f"{ip} 255.255.255.255",
                "comment": f"404-Donkey: {reason}"[:255],
            })
            created = True
        if name not in names:
            try:
                await fg_request("PUT", f"/api/v2/cmdb/firewall/addrgrp/{quote(group, safe='')}", {"member": members + [{"name": name}]})
            except Exception:
                if created:
                    try:
                        await fg_request("DELETE", address_path)
                    except Exception:
                        pass
                raise
        return {"changed": name not in names, "object": name, "group": group, "ip": ip, "action": "blocked"}
    if name in names:
        await fg_request("PUT", f"/api/v2/cmdb/firewall/addrgrp/{quote(group, safe='')}", {"member": [row for row in members if row["name"] != name]})
        await fg_request("DELETE", address_path)
    return {"changed": name in names, "object": name, "group": group, "ip": ip, "action": "unblocked"}


@app.get("/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok", "configured": bool(FG_URL and FG_TOKEN and ACTION_KEY), "groups": GROUPS}


@app.post("/actions/preview", operation_id="propose_fortigate_ip_action", dependencies=[Depends(require_action_key)])
async def preview(request: PreviewRequest) -> dict:
    settings_ready()
    ip = normalize_ip(request.ip)
    now = int(time.time())
    proposal_id = secrets.token_hex(12)
    code = secrets.token_hex(4).upper()
    with database() as connection:
        connection.execute(
            "INSERT INTO proposals VALUES (?,?,?,?,?,?,?,?,?,'pending',NULL,NULL,NULL)",
            (proposal_id, code, request.action, ip, request.direction, request.reason,
             request.requested_by, now, now + TTL),
        )
    event = {"event": "proposal_created", "proposal_id": proposal_id, "action": request.action, "ip": ip, "direction": request.direction, "requested_by": request.requested_by}
    audit(event)
    return {
        "requires_human_confirmation": True,
        "proposal_id": proposal_id,
        "confirmation_code": code,
        "expires_at": now + TTL,
        "preview": {"action": request.action, "ip": ip, "direction": request.direction, "group": GROUPS[request.direction], "object": object_name(ip, request.direction), "reason": request.reason},
        "instruction": f"Ask the human to reply exactly: CONFIRM {code}. Do not call confirmation in the same turn.",
    }


@app.post("/actions/confirm", operation_id="confirm_fortigate_ip_action", dependencies=[Depends(require_action_key)])
async def confirm(request: ConfirmRequest) -> dict:
    settings_ready()
    now = int(time.time())
    with database() as connection:
        row = connection.execute("SELECT * FROM proposals WHERE id=?", (request.proposal_id,)).fetchone()
        if not row or row["status"] != "pending":
            raise HTTPException(status_code=409, detail="Proposal is missing or no longer pending")
        if row["expires_at"] < now:
            connection.execute("UPDATE proposals SET status='expired' WHERE id=?", (request.proposal_id,))
            raise HTTPException(status_code=409, detail="Proposal has expired")
        if not hmac.compare_digest(row["code"], request.confirmation_code.upper()):
            raise HTTPException(status_code=403, detail="Confirmation code is incorrect")
        connection.execute("UPDATE proposals SET status='executing', approved_by=? WHERE id=?", (request.approved_by, request.proposal_id))
    try:
        result = await apply_action(row["action"], row["ip"], row["direction"], row["reason"])
    except Exception as exc:
        with database() as connection:
            connection.execute("UPDATE proposals SET status='failed', result=? WHERE id=?", (str(exc)[:500], request.proposal_id))
        audit({"event": "action_failed", "proposal_id": request.proposal_id, "error": str(exc)[:500]})
        raise
    with database() as connection:
        connection.execute("UPDATE proposals SET status='completed', completed_at=?, result=? WHERE id=?", (now, json.dumps(result), request.proposal_id))
    audit({"event": "action_completed", "proposal_id": request.proposal_id, "approved_by": request.approved_by, **result})
    return {"status": "completed", **result}


@app.get("/actions", operation_id="list_fortigate_ip_action_audit", dependencies=[Depends(require_action_key)])
async def list_actions(limit: int = 50) -> dict:
    with database() as connection:
        rows = connection.execute(
            "SELECT id,action,ip,direction,reason,requested_by,created_at,expires_at,status,approved_by,completed_at,result FROM proposals ORDER BY created_at DESC LIMIT ?",
            (max(1, min(limit, 200)),),
        ).fetchall()
    return {"count": len(rows), "data": [dict(row) for row in rows]}

