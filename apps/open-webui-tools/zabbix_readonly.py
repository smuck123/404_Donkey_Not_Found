"""
title: Zabbix Read Only
author: 404 Donkey Not Found
description: Read-only access to Zabbix hosts, problems, item discovery, and history.
version: 0.2.0
"""

import json
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class Tools:
    def __init__(self):
        self.base_url = "http://127.0.0.1:8889"
        self.timeout = 20

    def _get(self, path: str, parameters: Optional[dict] = None) -> dict:
        query = urlencode(
            {
                key: value
                for key, value in (parameters or {}).items()
                if value is not None
            }
        )
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{query}"

        request = Request(url, method="GET", headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            try:
                details = json.loads(error.read().decode("utf-8"))
            except Exception:
                details = {"message": str(error)}
            return {
                "error": {
                    "code": "zabbix_service_http_error",
                    "status": error.code,
                    "details": details,
                }
            }
        except (URLError, TimeoutError) as error:
            return {
                "error": {
                    "code": "zabbix_service_unavailable",
                    "message": str(error),
                }
            }
        except Exception as error:
            return {
                "error": {
                    "code": "zabbix_tool_error",
                    "message": str(error),
                }
            }

    def get_zabbix_hosts(self, limit: int = 100) -> dict:
        """
        List Zabbix hosts. Trust the returned enabled, monitored, and
        status_label fields. Zabbix raw host status 0 means enabled/monitored
        and raw status 1 means disabled/unmonitored.

        :param limit: Maximum number of hosts to return, from 1 to 1000.
        """
        limit = max(1, min(limit, 1000))
        return self._get("/hosts", {"limit": limit})

    def get_zabbix_problems(self, limit: int = 100) -> dict:
        """
        Get current and recent Zabbix problems and alerts.

        :param limit: Maximum number of problems to return, from 1 to 500.
        """
        limit = max(1, min(limit, 500))
        return self._get("/problems", {"limit": limit})

    def get_zabbix_items(
        self,
        query: Optional[str] = None,
        hostid: Optional[str] = None,
        limit: int = 100,
    ) -> dict:
        """
        Find Zabbix items and their numeric item IDs before requesting history.
        Search by a human-readable item name or key fragment. Optionally limit
        results to a numeric host ID. Use the returned itemid and value_type
        with get_zabbix_item_history.

        :param query: Item name or key fragment, for example fgSysSesCount.
        :param hostid: Optional numeric Zabbix host ID.
        :param limit: Maximum number of matching items, from 1 to 500.
        """
        limit = max(1, min(limit, 500))
        return self._get(
            "/items",
            {"query": query, "hostid": hostid, "limit": limit},
        )

    def get_zabbix_item_history(
        self,
        itemid: str,
        history: int = 0,
        limit: int = 100,
    ) -> dict:
        """
        Get recent history for a numeric Zabbix item ID. First call
        get_zabbix_items and use its returned itemid and value_type. Pass
        value_type as the history argument.

        :param itemid: Numeric Zabbix item ID returned by get_zabbix_items.
        :param history: Zabbix value_type returned by get_zabbix_items.
        :param limit: Maximum number of history values to return.
        """
        limit = max(1, min(limit, 1000))
        return self._get(
            "/history",
            {"itemid": itemid, "history": history, "limit": limit},
        )
