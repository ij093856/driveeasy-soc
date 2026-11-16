#!/usr/bin/env bash
# Export Splunk brute-force detections (last 15 min) to JSON.
cd "$(dirname "$0")/.."
/opt/splunk/bin/splunk search 'index=linux_auth source="/var/log/auth.log" ("Invalid user" OR "authenticating user" OR "Failed password" OR "not allowed because not listed in AllowUsers") earliest=-15m | rex "(?<src_ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+" | where isnotnull(src_ip) | transaction src_ip maxpause=30s | where eventcount >= 10 | eval attempts=eventcount | table _time src_ip attempts' -output json -auth admin 2>/dev/null | grep '^{' > sample_data/splunk_raw.json
head -1 sample_data/splunk_raw.json > sample_data/real_alert.json
echo "Exported $(wc -l < sample_data/splunk_raw.json) alert(s) to sample_data/real_alert.json"
