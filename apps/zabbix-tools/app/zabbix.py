import os
from typing import Any

import httpx


class ConfigurationError(Exception):
    pass


class ZabbixAPIError(Exception):
    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


class ZabbixClient:
    def __init__(self) -> None:
        base_url = os.getenv("ZABBIX_URL", "").strip().rstrip("/")
        self.token = os.getenv("ZABBIX_TOKEN", "").strip()
        if not base_url or not self.token:
            raise ConfigurationError("ZABBIX_URL and ZABBIX_TOKEN must be configured")

        self.url = (
            base_url
            if base_url.endswith("api_jsonrpc.php")
            else f"{base_url}/api_jsonrpc.php"
        )
        self.timeout = httpx.Timeout(10.0, connect=3.0)

    async def call(self, method: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json-rpc",
                        "Authorization": f"Bearer {self.token}",
                    },
                )
                response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise ZabbixAPIError("Zabbix API request timed out", status_code=504) from exc
        except httpx.HTTPError as exc:
            raise ZabbixAPIError("Unable to reach the Zabbix API") from exc

        try:
            body = response.json()
        except ValueError as exc:
            raise ZabbixAPIError("Zabbix API returned invalid JSON") from exc

        if "error" in body:
            error = body["error"]
            message = error.get("data") or error.get("message") or "Zabbix API error"
            raise ZabbixAPIError(str(message))

        result = body.get("result")
        if not isinstance(result, list):
            raise ZabbixAPIError("Zabbix API returned an unexpected response")
        return result

