# FortiGate approved actions

Separate, disabled-by-default write service for the fixed FortiGate groups
`AI-BLOCK-IN` and `AI-BLOCK-OUT`. It cannot accept arbitrary API paths,
policy IDs, groups, subnets, or CLI commands.

Every block/unblock requires a preview followed by a distinct confirmation.
Only public, non-protected IP addresses are accepted. State is stored in
SQLite and every proposal/result is appended to `/data/audit.jsonl`.

Required secrets belong in the server `.env`, never Git:

```dotenv
FORTIGATE_WRITE_TOKEN=...
FORTIGATE_ACTION_KEY=...
```

Enable after FortiGate groups, policies, restricted API profile, trusted host,
and protected CIDRs have been reviewed:

```bash
docker compose -p donkey-test -f compose.test.yml --profile fortigate-write up -d --build
```

