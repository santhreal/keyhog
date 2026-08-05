# Alerts and notifications

Send a finding somewhere a human will see it.

## Slack / Discord / webhook alerts

Post a one-line summary on every finding:

```bash
#!/usr/bin/env bash
set -euo pipefail
set +e
findings_json="$(keyhog scan . --format json-envelope --min-confidence 0.4)"
scan_status=$?
set -e
case "$scan_status" in
  0|1) ;;
  *) echo "keyhog scan did not complete (exit $scan_status)" >&2; exit "$scan_status" ;;
esac
count="$(echo "$findings_json" | jq '.findings | length')"
if [ "$count" -gt 0 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"⚠ keyhog: $count secret(s) detected in $(basename "$PWD")\"}" \
    "$SLACK_WEBHOOK_URL"
  exit 1
fi
exit "$scan_status"
```

For Discord, replace `text` with `content`. For PagerDuty, use the
`events/v2/enqueue` endpoint with severity `critical` for `--severity
critical` findings.
