# FortiGate SOC summary sender

This package analyzes recent FortiGate traffic records from the local syslog
file and sends compact read-only summaries to the existing **Firewall AI SOC
Full Sender** Zabbix trapper items.

It does not call the FortiGate API and does not change firewall configuration.

## Install on the Zabbix server

Install both Python files in the same directory so the sender can import the
collector:

```bash
install -m 0755 fortigate_soc_summary.py /usr/local/bin/fortigate_soc_summary.py
install -m 0755 send_fortigate_soc_summary.py /usr/local/bin/send_fortigate_soc_summary.py
install -m 0755 send_fortigate_soc_summary.sh /usr/local/bin/send_fortigate_soc_summary.sh
install -m 0600 404-donkey-fortigate-soc-summary.example /etc/sysconfig/404-donkey-fortigate-soc-summary
install -m 0644 fortigate-soc-summary.cron /etc/cron.d/fortigate-soc-summary
```

Verify that `ZABBIX_HOST` is the exact Zabbix technical host name and that
`FORTIGATE_LOG` points to the current FortiGate JSON syslog.

## Test

Preview the structured data without sending:

```bash
source /etc/sysconfig/404-donkey-fortigate-soc-summary
/usr/local/bin/fortigate_soc_summary.py --pretty
```

Send one complete window:

```bash
/usr/local/bin/send_fortigate_soc_summary.sh
```

The sender should report 18 processed values and zero failures. Check
`fortigate.soc.rich_summary`, `fortigate.total_events`, and the top
destination items under Monitoring > Latest data.
