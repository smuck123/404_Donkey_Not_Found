"""
title: Zabbix Read Only Stable
author: 404 Donkey Not Found
description: Stable read-only gateway for Zabbix monitoring data and official documentation.
version: 1.0.0
"""

import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class Tools:
    def read_zabbix(
        self,
        action: str,
        query: str = "",
        hostid: str = "",
        itemid: str = "",
        history: int = 0,
        time_from: int = 0,
        time_till: int = 0,
        limit: int = 100,
    ) -> dict:
        """
        Read Zabbix monitoring data or official Zabbix 8.0 documentation.

        Allowed actions:
        hosts - list hosts.
        problems - list current and recent problems.
        items - find items using query and optional hostid.
        history - retrieve item history using numeric itemid and history value type.
        host_summary - summarize one numeric hostid.
        triggers - list problem triggers for one numeric hostid.
        trends - retrieve aggregated trends for one numeric itemid.
        documentation - read an official manual path supplied in query, for
        example api/reference/item/get.

        Zabbix host status 0 means enabled/monitored and 1 means
        disabled/unmonitored. Trust status_label and monitored in responses.
        This function is read-only and must never claim that it changed Zabbix.

        :param action: One allowed action name from the list above.
        :param query: Search text, or a Zabbix 8.0 manual path for documentation.
        :param hostid: Numeric Zabbix host ID when required.
        :param itemid: Numeric Zabbix item ID when required.
        :param history: Zabbix item value_type for history calls.
        :param time_from: Optional Unix start timestamp for trends; use 0 to omit.
        :param time_till: Optional Unix end timestamp for trends; use 0 to omit.
        :param limit: Maximum result count, normally 1 through 1000.
        """
        parameters = {
            "action": action,
            "query": query,
            "hostid": hostid,
            "itemid": itemid,
            "history": history,
            "limit": max(1, min(limit, 1000)),
        }
        if time_from > 0:
            parameters["time_from"] = time_from
        if time_till > 0:
            parameters["time_till"] = time_till

        url = "http://127.0.0.1:8889/read?" + urlencode(parameters)
        request = Request(url, method="GET", headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as error:
            return {
                "error": {
                    "code": "zabbix_read_error",
                    "message": str(error),
                }
            }
