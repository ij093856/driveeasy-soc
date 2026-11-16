# Incident Response Playbook: SSH Brute Force

| Field | Value |
|---|---|
| Alert name | SSH Brute Force Detected (Splunk saved search) |
| Detection rule | [`splunk/brute_force_ssh.spl`](../splunk/brute_force_ssh.spl) |
| MITRE ATT&CK | **T1110 Brute Force** (Credential Access), sub-techniques T1110.001 Password Guessing and T1110.003 Password Spraying |
| Asset | DriveEasy Ubuntu reservation server (customer and vehicle data) |
| Owner | SOC analyst; escalate High and Critical to the IT lead |

## Environment notes

The server has password login disabled and only the user `adminops` is allowed to log in over SSH (set up in Task 1). Because of this, password guessing cannot succeed. The main risk is a stolen SSH key.

In this lab the server is a VirtualBox VM. Connections from the host computer arrive through a port forward, so the log shows the source IP as `10.0.2.2`. In a real deployment this would be the attacker's actual IP address.

Because the host refuses password logins, attacks do not appear as `Failed password`. They appear as `Invalid user`, `Connection closed by authenticating user ... [preauth]`, or `not allowed because not listed in AllowUsers`. The Splunk search matches all of these.

**Lab caution:** the legitimate `adminops` logins also come from `10.0.2.2`. In this lab, an `Accepted publickey for adminops` line from `10.0.2.2` is the administrator, not an attacker.

## Severity

Severity is based on the number of matching log events in one attack. An attack is a burst of events from one source IP, with gaps of less than 30 seconds between events. `scripts/create_ticket.py` applies the same bands.

| Events in one attack | Severity | Respond within |
|---|---|---|
| 10 to 49 | Medium | 4 hours |
| 50 to 199 | High | 1 hour |
| 200 or more | Critical | 15 minutes |
| Any number, followed by a successful login from the same IP | Critical | Immediately |

Fewer than 10 events does not trigger the detection, so it gets no ticket.

## 1. Detection

**Goal:** Confirm the alert is real and record the trigger details.

1. Open the saved search `SSH Brute Force Detected` in Splunk (Reports) and set the time range to the last 60 minutes. Write down for each result:
   - Source IP (`src_ip`)
   - Number of events (`attempts`)
   - Start time (`_time`) and duration
2. Check whether the attack is still going on:
   ```spl
   index=linux_auth source="/var/log/auth.log" "<src_ip>" | timechart span=1m count
   ```
   If events are still arriving in the last few minutes, the attack is ongoing.
3. Export the alert and create the ticket:
   ```bash
   bash scripts/export_alert.sh
   python3 scripts/create_ticket.py sample_data/real_alert.json
   ```
   Open `tickets.csv`, note the ticket's severity, and set its status to Investigating.
4. Continue to **2. Triage** to find out whether any login succeeded.

## 2. Triage

**Goal:** Decide whether the alert is noise, a failed attack, or a compromise.

1. **Check whether any login succeeded from the source IP.** This is the most important check.
   ```bash
   sudo grep "<ip>" /var/log/auth.log | grep Accepted
   ```
   - No output: no login succeeded.
   - Any `Accepted` line from an unknown IP: treat as a compromise and go to Containment immediately.
   - In this lab, `Accepted publickey for adminops` from `10.0.2.2` is the legitimate admin (see Environment notes).
2. **List the usernames that were targeted.**
   ```bash
   sudo grep "<ip>" /var/log/auth.log | grep -oP 'Invalid user \K\S+' | sort | uniq -c | sort -rn
   ```
   - Many different usernames, few tries each: password spraying (T1110.003).
   - One or two usernames, many tries: password guessing (T1110.001).
   - Note whether `adminops` appears. It is the only allowed account.
3. **Check whether the source IP is known.** Compare it to the list of office, VPN and admin addresses. For unknown external IPs, look it up on AbuseIPDB (abuseipdb.com) for previous reports.
4. **Check whether the same IP appears on other hosts or logs.**
   ```spl
   index=* "<ip>" | stats count BY host, source
   ```
   More than one host means the attack is wider than this server. Tell the IT lead.
5. **Classify the alert** using what you found:

| Finding | Classification | Next step |
|---|---|---|
| Known or internal IP | False positive | Confirm with the owner and close the ticket |
| Unknown IP, no `Accepted` lines | True positive, attack failed (blocked by hardening) | Go to Containment: preserve evidence and block the IP. Then do the baseline check in Eradication |
| Any `Accepted` line from an unknown IP | Confirmed compromise | Escalate to the IT lead now. Do all of Containment, Eradication and Recovery |

## 3. Containment

**Goal:** Stop the attacker from continuing, without destroying evidence.

1. **Preserve evidence before changing anything.**
   ```bash
   sudo cp /var/log/auth.log /var/log/auth.log.$(date +%F-%H%M).evidence
   sudo sha256sum /var/log/auth.log.*.evidence
   ```
   Record the hash in the ticket notes.
2. **Block the source IP at the firewall.**
   ```bash
   sudo ufw insert 1 deny from <ip> to any port 22 proto tcp
   sudo ufw status numbered
   ```
   Confirm the deny rule is number 1.
3. **If triage found a successful login** from the attacker's IP, end the session and lock the account:
   ```bash
   who -u
   sudo pkill -KILL -u <user>
   sudo usermod -L <user>
   ```
   Skip this step if no login succeeded.
4. Update the ticket in `tickets.csv`: set the status to **Contained** and note the time, the IP blocked, and the action taken.

**Containment is complete when:** the deny rule is active, no sessions remain from the attacker's IP (`who -u`), and the evidence copy is saved.

## 4. Eradication

**Goal:** Make sure the attacker has no remaining access and the server is back to its hardened baseline.

### A. Always: verify the hardened baseline

1. Check the live SSH settings:
   ```bash
   sudo sshd -T | grep -Ei "permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|allowusers|x11forwarding"
   ```
2. Expected values (from Task 1):
   ```
   permitrootlogin no
   passwordauthentication no
   pubkeyauthentication yes
   maxauthtries 3
   allowusers adminops
   x11forwarding no
   ```
3. If any value is different, restore it in `/etc/ssh/sshd_config`, run `sudo sshd -t` to test the syntax, then `sudo systemctl restart ssh`.
4. Check that only the expected ports are open and compare with the Task 1 `after/listening_after.txt`:
   ```bash
   sudo ss -tulpn
   ```

### B. If a login succeeded or a key may be exposed

1. Remove the old public key from `/home/adminops/.ssh/authorized_keys`, create a new key pair, and install the new public key.
2. Look for keys you did not add: `cat /home/adminops/.ssh/authorized_keys`.
3. Look for persistence:
   ```bash
   awk -F: '$3>=1000 {print $1}' /etc/passwd
   crontab -l; sudo ls /etc/cron.*
   sudo find / -xdev -mtime -2 -type f -not -path "/proc/*" 2>/dev/null | head -50
   ```
4. If customer or vehicle data may have been accessed, tell the IT lead and the data-protection contact.

### C. Patch

```bash
sudo apt update && sudo apt upgrade
```

Automatic updates (`unattended-upgrades`) are already enabled from Task 1.

**Eradication is complete when:** SSH settings match the baseline, no unknown keys, users or jobs exist, no unexpected ports are open, and any exposed key has been replaced.

## 5. Recovery

**Goal:** Return the server to normal operation and confirm the attacker has not come back.

1. **Confirm normal admin access.** From the admin computer, `ssh -p 2222 adminops@127.0.0.1` must work with the key and no password. Password login must still be refused:
   ```bash
   ssh -p 2222 -o PubkeyAuthentication=no adminops@127.0.0.1
   ```
   Expected: `Permission denied (publickey)`.
2. If system integrity is in doubt after a confirmed compromise, restore the VM snapshot `hardened-final` from Task 1 and re-apply any updates.
3. **Monitor for 72 hours.** Re-run the Splunk search with a 72-hour time range and watch for new activity from the blocked IP or against the same usernames.
4. **Keep the firewall block** for at least 30 days, then review whether to remove it.
5. **Close the ticket.** In `tickets.csv` set the status to **Resolved** and add short closure notes: what happened, what was done, and when.

**Recovery is complete when:** admin access works, no new attack activity appears for 72 hours, and the ticket is closed.

## 6. Lessons learned

Hold a short review after every Medium or higher incident.

### What worked
- Hardening stopped the attack: password logins are disabled, so guessing could not succeed.
- The Splunk search found each attack separately and the script turned each detection into a ticket in seconds.

### What did not work, or surprised me
- After hardening, the logs no longer contain `Failed password`. The first version of the search found nothing until it was changed to match `Invalid user` and `authenticating user`.
- Grouping events in fixed 5-minute buckets merged two separate attacks into one. Grouping by gaps in time (`transaction ... maxpause=30s`) fixed this.
- Splunk Free cannot run alert actions, so the export and the ticket script are run by hand.

### What I would improve
- Use Splunk Enterprise so the alert triggers the ticket script automatically.
- Add fail2ban to block repeat offenders without a human.
- Add a second detection for a successful login from a new IP.
- Replace the CSV with a real ticketing system.
- Review the threshold (10 events) against real traffic.

## Ticket workflow

| Status | Meaning |
|---|---|
| Open | Created automatically by `create_ticket.py` |
| Investigating | Analyst working on Detection and Triage |
| Contained | Containment done |
| Resolved | Eradication and Recovery done, review complete |
| False positive | Closed at triage, with a reason |

