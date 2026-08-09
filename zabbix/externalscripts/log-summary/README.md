# Zabbix server log summary collector

This directory is deliberately separate from `apps/zabbix-tools`. The files run
on the Zabbix server, read local logs incrementally, optionally ask Ollama for a
short explanation, and publish two trapper values:

- `log.summary.raw`: Zabbix 8.0 JSON item
- `log.summary.text`: Text item

The script does not use the Zabbix API and contains no credentials.

## Improvements over the original

- Non-blocking process lock prevents overlapping cron runs.
- Lines produced by the old forwarding/summarizing pipeline are excluded to
  prevent feedback loops.
- Input is bounded per file while offsets still advance.
- Ollama calls use `think: false`, a concise prompt, retries, and a timeout.
- `analysis_source` shows `ollama` or `deterministic` fallback.
- Results include `period_seconds`, dropped-line count, and a stable schema.
- Runtime settings live in a root-managed environment file.

## Install on the Zabbix server

```bash
install -d -m 0755 /usr/local/libexec/404-donkey-not-found
install -m 0755 log_summary.py /usr/local/libexec/404-donkey-not-found/log_summary.py
install -m 0755 send_log_summary.sh /usr/local/bin/send_log_summary.sh
install -m 0644 log-summary.cron /etc/cron.d/log-summary
install -m 0600 404-donkey-log-summary.example /etc/sysconfig/404-donkey-log-summary
install -d -m 0750 /var/lib/404-donkey-not-found
```

Edit `/etc/sysconfig/404-donkey-log-summary`, then test manually:

```bash
/usr/local/bin/send_log_summary.sh
```

Verify both sender operations report no errors and inspect Latest data. Keep any
older log forwarder stopped until its keys are fixed; this collector replaces
the summary cron job, not arbitrary per-line forwarding.

