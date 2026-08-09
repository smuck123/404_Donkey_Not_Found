# OpenClaw Zabbix read-only tools

The test stack exposes a curated MCP server on loopback port 8890. It contains
five read-only tools and never receives the Zabbix API token directly.

After deployment, register it once in the persistent OpenClaw configuration:

```bash
cd /opt/ai-stack/test

docker compose -p donkey-test -f compose.test.yml --profile openclaw run --rm --no-deps \
  openclaw-cli mcp set zabbix-read \
  '{"url":"http://127.0.0.1:8890/mcp","transport":"streamable-http","connectionTimeoutMs":5000,"requestTimeoutMs":20000,"supportsParallelToolCalls":true}'

docker compose -p donkey-test -f compose.test.yml --profile openclaw run --rm --no-deps \
  openclaw-cli mcp tools zabbix-read \
  --include 'list_hosts,get_host_overview,get_active_problems,find_items,get_item_history'

docker compose -p donkey-test -f compose.test.yml --profile openclaw run --rm --no-deps \
  openclaw-cli mcp doctor zabbix-read --probe

docker compose -p donkey-test -f compose.test.yml --profile openclaw restart openclaw-gateway
```

In Telegram send `/reset`, then test:

```text
Give me a short health overview of Zabbix-Analyzer.
```

Expected tool: `zabbix-read__get_host_overview`.

The specialized REST endpoints remain available for detailed investigations, but
the normal agent should start with the compact overview and expand only when asked.
