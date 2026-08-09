# FortiGate API Summary for Zabbix

This package is separate from the FortiGate SOC syslog parser. It reads only
current device/configuration/performance information from the FortiGate API and
sends one JSON document to the `fortigate.api.raw` trapper item.

## Install on the Zabbix server

```bash
install -o root -g root -m 0755 fortigate_api_summary.py /usr/local/bin/
install -o root -g root -m 0755 send_fortigate_api_summary.sh /usr/local/bin/
install -o root -g root -m 0600 404-donkey-fortigate-api-summary.example \
  /etc/sysconfig/404-donkey-fortigate-api-summary
install -o root -g root -m 0644 fortigate-api-summary.cron \
  /etc/cron.d/fortigate-api-summary
```

Edit `/etc/sysconfig/404-donkey-fortigate-api-summary` and add the real
read-only API token. Import and link
`template_fortigate_api_summary_by_trapper.yaml` to the Zabbix host named in
`ZABBIX_HOST`.

Test before enabling cron:

```bash
/usr/local/bin/fortigate_api_summary.py --pretty
/usr/local/bin/send_fortigate_api_summary.sh
```

The collector performs GET requests only. It has no configuration-write
functions and does not send the API token to Zabbix.
