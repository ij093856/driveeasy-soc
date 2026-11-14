# Incident Response Playbook: SSH Brute Force

| Field | Value |
|---|---|
| Alert name | SSH Brute Force Detection |
| Detection rule | splunk/brute_force_ssh.spl |
| MITRE ATT&CK | T1110 Brute Force (Credential Access) |
| Asset | DriveEasy Ubuntu reservation server |
| Owner | SOC analyst |

## Environment notes

The server has password login disabled and only the user adminops is allowed to log in over SSH (set up in Task 1). Because of this, password guessing cannot succeed. The main risk is a stolen SSH key.

In this lab, the server runs as a VM in VirtualBox. Connections from the host computer come through a port forward, so the log shows the source IP as 10.0.2.2. In a real deployment, this would be the attacker's actual IP address.





## Severity

Severity is based on the number of failed or invalid SSH attempts from one source IP in a 5-minute window.

| Failed attempts in 5 min | Severity | Respond within |
|---|---|---|
| 10 to 49 | Medium | 4 hours |
| 50 to 199 | High | 1 hour |
| 200 or more | Critical | 15 minutes |
| Any number, followed by a successful login from the same IP | Critical | Immediately |

Fewer than 10 attempts does not trigger the alert, so it gets no ticket.





## 1. Detection

## 2. Triage

## 3. Containment

## 4. Eradication

## 5. Recovery

## 6. Lessons learned


## 1. Detection

**Goal:** Confirm the alert is real and record the trigger details.

1. Open the alert in Splunk (saved search:'<SSH Brute Force Detection>`). Write down:
   - Source IP
   - Number of attempts
   - Time window
   - Usernames targeted
2. Check whether the attack is still happening:
   ```spl
   index=main source="/var/log/auth.log" "<src_ip>" | timechart span=1m count
   ```
   If the count is still above zero in the last few minutes, the attack is ongoing.
3. Find the matching ticket in `tickets.csv` (created automatically by `create_ticket.py`) and note its ticket ID and severity. Set its status to Investigating.
4. Continue to **2. Triage** to find out whether any login succeeded.


**Goal:** Decide whether the alert is noise, a failed attack, or a compromise.

1. **Check whether any login succeeded from the source IP.** This is the most important check.
   ```bash
   sudo grep "<ip>" /var/log/auth.log | grep Accepted
   ```
   - No output: no login succeeded.
   - Any `Accepted` line from an unknown IP: treat as a compromise (go to Containment immediately).

2. **List the usernames that were targeted.**
   ```bash
   sudo grep "<ip>" /var/log/auth.log | grep -oP 'Invalid user \K\S+' | sort | uniq -c | sort -rn
   ```
   - Many different usernames, few tries each: password spraying (MITRE T1110.003).
   - One or two usernames, many tries: password guessing (MITRE T1110.001).
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
| Unknown IP, no `Accepted` lines | (e.g. True positive, attack failed) | (what the analyst does next) |
| Any `Accepted` line from the IP | (e.g. confirmed compromise) | (what the analyst does next) |

## 3. Containment

**Goal:** Stop the attacker from continuing, without destroying evidence.

1. **Preserve evidence before changing anything.**
   ```bash
   sudo cp /var/log/auth.log /var/log/auth.log.evidence
   sudo sha256sum /var/log/auth.log.evidence
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

**Goal:** Make sure the attacker has no remaining access and the server is back to its hardened baseline.

### A. Always: verify the hardened baseline

1. Check the live SSH settings:
   ```bash
   sudo sshd -T | grep -Ei "permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|allowusers|x11forwarding"
   ```
2. Expected values: (write the six values here, from your output)
3. If any value is different, restore it in `/etc/ssh/sshd_config`, then run `sudo sshd -t` to test the syntax, then `sudo systemctl restart ssh`.

**Eradication is complete when:** SSH settings match the baseline, no unknown keys, users or jobs exist, no unexpected ports are open, and the attacker's key or access has been removed.
