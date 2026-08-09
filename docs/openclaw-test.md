# OpenClaw test gateway

This optional profile adds OpenClaw without changing the normal Zabbix deployment.
It uses host networking so the container can reach the existing loopback-only
Ollama and Zabbix endpoints. The Gateway itself binds only to loopback.

## Security boundary

- no Docker socket
- no host filesystem mounts
- persistent state only in the `openclaw-state` Docker volume
- no Zabbix write actions
- no public or LAN listener
- Bonjour discovery disabled
- `NET_RAW` and `NET_ADMIN` removed
- `no-new-privileges` enabled

Do not add shell, Docker, or unrestricted filesystem tools during initial testing.

## One-time server setup

Run from `/opt/ai-stack/test`.

Generate and save a Gateway token without printing it:

```bash
umask 077
token="$(openssl rand -hex 32)"
if grep -q '^OPENCLAW_GATEWAY_TOKEN=' .env; then
  sed -i "s/^OPENCLAW_GATEWAY_TOKEN=.*/OPENCLAW_GATEWAY_TOKEN=$token/" .env
else
  printf '\nOPENCLAW_GATEWAY_TOKEN=%s\n' "$token" >> .env
fi
unset token
```

Pull the pinned image and run local onboarding:

```bash
docker compose -p donkey-test -f compose.test.yml --profile openclaw pull openclaw-gateway openclaw-cli

docker compose -p donkey-test -f compose.test.yml --profile openclaw run --rm --no-deps   openclaw-cli onboard --mode local --no-install-daemon
```

During onboarding choose:

- provider: Ollama
- Ollama URL: `http://127.0.0.1:11434`
- model: `qwen3:8b` initially
- Gateway mode: local
- do not enable shell, exec, Docker, browser automation, or filesystem access

Set and verify the native Ollama provider. Do not use Ollama's `/v1` URL:

```bash
docker compose -p donkey-test -f compose.test.yml --profile openclaw run --rm --no-deps   openclaw-cli models list --provider ollama

docker compose -p donkey-test -f compose.test.yml --profile openclaw run --rm --no-deps   openclaw-cli models set ollama/qwen3:8b
```

Start the Gateway:

```bash
docker compose -p donkey-test -f compose.test.yml --profile openclaw up -d openclaw-gateway
curl -fsS http://127.0.0.1:18789/healthz
```

Inspect it without exposing the token:

```bash
docker compose -p donkey-test -f compose.test.yml --profile openclaw ps
docker compose -p donkey-test -f compose.test.yml logs --tail=100 openclaw-gateway
```

## Local Control UI

Use an SSH tunnel from a trusted computer:

```bash
ssh -L 18789:127.0.0.1:18789 user@zabbix-analyzer
```

Then open `http://127.0.0.1:18789/` locally and enter the token stored in the
server's `.env`.

## Android phase

Do not publish port 18789 directly. The next phase should add Tailscale and an
authenticated HTTPS route to the loopback Gateway, followed by Android pairing.

## Zabbix integration phase

The existing Zabbix service remains available read-only at
`http://127.0.0.1:8889`. First validate OpenClaw chat and Android pairing.
Then add a narrowly scoped OpenClaw tool that exposes only the existing
`/read` operations. Do not give OpenClaw the Zabbix token.
