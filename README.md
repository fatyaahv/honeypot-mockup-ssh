FIX THE DUPLICATE ISSUE
MALFORMED LOG BEHAVIOUR
MITRE ID STUFF IS FISHY LOOK INTO IT LATER(DON'T LET IT OZUNNEN HOQQA VERMESIN)


# AI-Powered Adaptive SSH Honeypot

A project skeleton for an adaptive SSH honeypot with a Python backend, security analysis, persistent data, and a dashboard. Work is being added incrementally.

## Project structure

- `backend/` — future Python API and application logic
- `analyzer/` — future security and AI analysis
- `honeypot/` — Cowrie integration and its persistent runtime logs
- `dashboard/` — future dashboard interface
- `tests/` — future automated checks
- `data/` — future application data, including a SQLite database

## Cowrie SSH honeypot

The Cowrie container accepts SSH connections on `127.0.0.1:2222` on this computer. It uses Cowrie's default emulated shell and does not provide a real host shell. The published port is bound to loopback so it is reachable only from this computer.

Start the services:

```sh
docker compose up -d
```

View service status and Cowrie startup logs:

```sh
docker compose ps
docker compose logs -f cowrie
```

Connect locally from a terminal:

```sh
ssh -p 2222 root@127.0.0.1
```

At the SSH authenticity prompt, type `yes`. Use any test password if prompted; Cowrie records the attempt and provides its simulated shell. Try harmless commands such as `whoami`, `pwd`, `ls`, and `uname -a`, then type `exit` to end the session. A failed password attempt can also be recorded; no real account login is required.

Cowrie logs and session data are persisted under `honeypot/var/` on the host. The JSON audit log is `honeypot/var/log/cowrie/cowrie.json`; Cowrie's operational log is `honeypot/var/log/cowrie/cowrie.log`; session recordings are stored under `honeypot/var/lib/cowrie/tty/`.

Stop the services with:

```sh
docker compose down
```

Keep this honeypot bound to localhost during local testing. Do not publish it to the internet or connect it to a production host.

## SQLite event persistence

The analyzer stores normalized Cowrie events in `data/security_events.sqlite3` by default. Set `HONEYPOT_DATABASE_PATH` to use another SQLite file. The collector function parses a Cowrie JSON Lines log and persists supported events:

```python
from analyzer.collector import collect_cowrie_log

count = collect_cowrie_log(
    "honeypot/var/log/cowrie/cowrie.json",
    "data/security_events.sqlite3",
)
print(f"Stored {count} events")
```

Run parser and database tests with the workspace Python runtime:

```powershell
.\.tools\python313\python.exe -m unittest discover -v
```

If the SQLite command-line tool is installed, inspect records with:

```sh
sqlite3 data/security_events.sqlite3 "SELECT id, timestamp, source_ip, event_type, command, login_result FROM security_events ORDER BY id;"
```

## Rule-based detections

`analyzer.detector.detect_database_events()` loads persisted events and returns explainable alerts; `detect_events(events, config)` can also evaluate an event list directly. `DetectionConfig` controls thresholds and windows. Defaults are 5 failed logins from one IP within 300 seconds for brute force, 3 prior failures within 600 seconds before a successful login, and 10 commands in one session within 60 seconds for a command burst.

Brute-force alerts are medium because repeated failures can be user error. A successful login after repeated failures is high priority for review, but does not prove compromise. Reconnaissance commands such as `whoami`, `uname`, and `id` are low severity; shell, transfer, permission, interpreter, and network utility commands are medium because context is needed. Command bursts are medium because they can also come from automation. Alerts include relevant database event IDs when available.

## MITRE ATT&CK mapping and risk enrichment

Run `analyzer.enrichment.analyze_database()` to detect stored events, add ATT&CK context and a deterministic risk score, and upsert enriched alerts into the `security_alerts` table. Event records stay in `security_events`; alerts store references to them through `related_event_ids`.

The ATT&CK catalog is maintained separately in `analyzer/mitre_mapping_data.py`; the resolver is in `analyzer/mitre_mapping.py`. Initial behavior associations are:

| Observed behavior | Technique | Tactic |
|---|---|---|
| Repeated failed SSH authentication | T1110.001 Password Guessing | Credential Access |
| Cowrie-accepted SSH login after failures | T1078 Valid Accounts | Initial Access |
| `whoami`, `id` | T1033 System Owner/User Discovery | Discovery |
| `uname` | T1082 System Information Discovery | Discovery |
| `ip addr`, `ifconfig` | T1016 System Network Configuration Discovery | Discovery |
| `ls`, `find` | T1083 File and Directory Discovery | Discovery |
| `cat /etc/passwd` | T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow | Credential Access |
| `wget`, `curl` | T1105 Ingress Tool Transfer | Command and Control |
| `bash` | T1059.004 Unix Shell | Execution |
| `python` | T1059.006 Python | Execution |
| `chmod` | T1222.002 Linux and Mac Permissions | Defense Impairment |
| `nc`, `ncat` | T1095 Non-Application Layer Protocol | Command and Control |

These are behavior associations, not claims that an attack succeeded. Cowrie-accepted login does not prove real credentials were valid; a command such as `nc` alone does not prove the protocol or purpose; and reading `/etc/passwd` does not prove credentials were extracted. Alerts without a specific supported mapping have `None` in their MITRE fields. The IDs, names, and tactics are checked against the official ATT&CK technique pages: [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078](https://attack.mitre.org/techniques/T1078/), [T1033](https://attack.mitre.org/techniques/T1033/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1016](https://attack.mitre.org/techniques/T1016/), [T1083](https://attack.mitre.org/techniques/T1083/), [T1003.008](https://attack.mitre.org/techniques/T1003/008/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1059.006](https://attack.mitre.org/techniques/T1059/006/), [T1222.002](https://attack.mitre.org/techniques/T1222/002/), and [T1095](https://attack.mitre.org/techniques/T1095/).

The risk score is clamped to 0–100 and sums these points:

- Base severity: Low 10, Medium 25, High 40, Critical 55
- Repeated related events: 5 per event after the first, capped at 15
- Related successful authentication: +20
- Suspicious-command alert: +10
- Other nearby alerts for the same source/session: +5 each, capped at 10
- Activity in the same session: +2 per event after the first, capped at 10

Score levels are Low 0–24, Medium 25–49, High 50–74, and Critical 75–100. The result is an internal, explainable prioritization score, not a probability of compromise. `risk_factors` stores the point breakdown. Stable alert IDs make repeated runs idempotent; existing rows are refreshed if the score or context changes.
