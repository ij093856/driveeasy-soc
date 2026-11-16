# DriveEasy Rentals: SOC Hardening and Detection (Task 3)

Incident response playbook, automated ticket creation and final security report for the SSH brute-force detection built in Tasks 1 and 2.

**Author:** Ikram Javed (Ezitech internship, Cyber Security)

## Deliverables

| Deliverable | Where |
|---|---|
| Incident response playbook (MITRE ATT&CK T1110) | [`docs/playbook.md`](docs/playbook.md) |
| Final security report (PDF) | [`report.pdf`](report.pdf) |
| Report source | [`docs/report.md`](docs/report.md) |
| Splunk detection rule (SPL) | [`splunk/brute_force_ssh.spl`](splunk/brute_force_ssh.spl) |
| Ticket creation script | [`scripts/create_ticket.py`](scripts/create_ticket.py) |
| Splunk export script | [`scripts/export_alert.sh`](scripts/export_alert.sh) |
| **Demo video** (unlisted, about 2 min) | https://youtu.be/ap3mHOtiZAA |
| Hardening evidence (Task 1) | Task 1 repository `driveeasy-hardening` |

## How it works

```
SSH attack -> /var/log/auth.log -> Splunk (linux_auth index)
  -> saved search "SSH Brute Force Detected" (10+ events from one IP, one row per attack)
  -> export_alert.sh -> real_alert.json -> create_ticket.py -> tickets.csv
  -> analyst follows docs/playbook.md
```

- **Detection:** the search groups log events from one source IP into one attack (a gap of more than 30 seconds starts a new attack) and reports attacks with 10 or more events. It matches `Invalid user`, `authenticating user`, `Failed password` and `not listed in AllowUsers`, because the hardened host has password login disabled.
- **Ticketing:** `create_ticket.py` reads the alert JSON and appends a row with timestamp, source IP, severity and attempt count.
- **Severity bands:** 10 to 49 Medium, 50 to 199 High, 200 or more Critical (same as the playbook).

## Usage

Requires Python 3 (standard library only). Run from the repository root.

```bash
# 1. Export the latest detection from Splunk (needs Splunk on this machine)
bash scripts/export_alert.sh

# 2. Create a ticket from the alert JSON
python3 scripts/create_ticket.py sample_data/real_alert.json

# 3. View the tickets
cat tickets.csv
```

Example `tickets.csv` row:

```
timestamp,source_ip,severity,attempts
2026-11-15 15:20:00.000 PKT,10.0.2.2,Medium,36
```

A full example is in [`sample_data/tickets_example.csv`](sample_data/tickets_example.csv). The script prints a clear message for a missing file, invalid JSON or missing fields.

### Rebuild the PDF report

```bash
sudo apt install pandoc texlive-xetex
cd docs
pandoc report.md -o ../report.pdf --pdf-engine=xelatex --toc --number-sections -V geometry:margin=1in -V colorlinks=true
```

## Splunk Free limitation

Splunk Free does not support scheduled alerts or alert actions. Detection is therefore a saved search run on demand, and `export_alert.sh` exports its result as JSON for the ticket script. With a licence that supports alerting, the same search would run on a schedule and call the ticket script through a webhook.

## Lab notes

- The server is an Ubuntu 26.04 LTS VM in VirtualBox (the brief specifies 22.04; documented in Task 1).
- Attacks from the Windows host arrive through a NAT port forward, so the log shows the source IP as `10.0.2.2`.

## Repository layout

```
docs/           playbook.md, report.md
splunk/         brute_force_ssh.spl
scripts/        create_ticket.py, export_alert.sh
sample_data/    alert.json, real_alert.json, splunk_raw.json, tickets_example.csv
screenshots/    evidence images used in the report
report.pdf      final security report
```

## Tools

Markdown, Pandoc, OBS Studio, Python, Git, Splunk, Ubuntu.
