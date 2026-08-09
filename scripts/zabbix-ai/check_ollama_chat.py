#!/usr/bin/env python3
"""Verify that an Ollama server supports the chat request used by Zabbix jobs."""

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Ollama /api/chat URL")
    parser.add_argument("--model", required=True, help="Installed Ollama model")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    payload = {
        "model": args.model,
        "stream": False,
        "think": False,
        "messages": [
            {
                "role": "system",
                "content": "Reply with exactly OLLAMA_CHAT_OK.",
            },
            {"role": "user", "content": "Compatibility test"},
        ],
    }
    request = Request(
        args.url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=args.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        print(f"HTTP error {exc.code}: {exc.reason}", file=sys.stderr)
        return 1
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Ollama request failed: {exc}", file=sys.stderr)
        return 1

    content = body.get("message", {}).get("content", "").strip()
    if "OLLAMA_CHAT_OK" not in content:
        print(f"Unexpected Ollama response: {content!r}", file=sys.stderr)
        return 1

    print("OLLAMA_CHAT_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
