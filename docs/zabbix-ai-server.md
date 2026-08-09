# Zabbix log summaries using the local AI server

The former `log_summary.py` integration is compatible with the current stack.
It calls Ollama's native `POST /api/chat` endpoint, independently of the
read-only Zabbix FastAPI and MCP services.

## Recommended configuration

On the Zabbix server, point the existing script at the analyzer host:

```bash
OLLAMA_URL="http://192.168.0.111:11434/api/chat"
OLLAMA_MODEL="qwen3.5:9b"
```

Confirm the actual model name first:

```bash
curl -fsS http://192.168.0.111:11434/api/tags
```

Then check compatibility from the Zabbix server:

```bash
python3 scripts/zabbix-ai/check_ollama_chat.py \
  --url http://192.168.0.111:11434/api/chat \
  --model qwen3.5:9b
```

Expected output is `OLLAMA_CHAT_OK`.

## Network requirement

Ollama must listen on a LAN-reachable address and TCP port 11434 must be allowed
from the Zabbix server only. Do not expose Ollama to the public internet.

For systemd-managed Ollama, set an appropriate `OLLAMA_HOST`, for example
`0.0.0.0:11434`, and restrict access with the host firewall.

## Architecture

- The old log parser reads local Zabbix-server log files.
- It sends only the structured summary to Ollama for concise analysis.
- It writes the raw and text summaries back through `zabbix_sender`.
- The new Zabbix tools remain read-only and are used by OpenClaw for interactive
  questions. They do not replace Ollama's `/api/chat` endpoint.

No Zabbix API token is needed by the old log summarizer because it uses
`zabbix_sender`, but its trapper items and allowed-host settings must already
exist in Zabbix.
