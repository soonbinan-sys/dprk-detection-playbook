# Selected atomics

Which Atomic Red Team and Caldera procedures were considered, and what was actually
run. The techniques below were covered by custom scripts and Caldera abilities
instead of the standard atomics, documented here so the decision is explicit
rather than silent. The FP (false positive) baseline session is also recorded
here since it represents a distinct category of testing — normal activity rather
than simulated attack behavior.

| ATT&CK ID | Atomic / procedure | Why chosen | Run |
|---|---|---|---|
| T1071.001 | Caldera custom ability, BeaverTail HTTP C2 Beacon | HTTP POST with host recon data, matches WAVESHAPER.V2 callback pattern | 2026-07-22, Ubuntu VM (192.168.56.2) and Windows 11 VM (192.168.56.3), Sandcat agents tasked via Caldera server on Mac host (192.168.56.1:8888). Ubuntu: auditd confirmed Sandcat (pid=135108) → sh (pid=137616) → hostname → curl POST to 192.168.56.1:8787. Windows: Sysmon Event ID 1 confirmed splunkd.exe (pid=3128) → powershell.exe -ExecutionPolicy Bypass (pid=4232) → HOSTNAME.EXE (pid=3936) + whoami.exe (pid=1920), Event ID 3 confirmed network connection 192.168.56.3 → 192.168.56.1:8888 |
| T1552.001 | Atomic Red Team T1552.001, credentials in files | Stands in for the documented targeting of cloud credential files and browser stored data | not run, remains a gap, listed in coverage-matrix.md under known gaps |
| FP baseline (not an attack technique) | Custom: npm installs across 8 packages + 2 git commits, auditd + check-fp.py | Exercises the exact process patterns the two Sigma rules are built to detect, using clean packages rather than simulated malware, to establish whether the rules over-trigger on normal dev activity | 2026-07-22, Ubuntu VM (192.168.56.2), 22:48–22:58 EDT. 0 Rule 1 hits across bcrypt, sqlite3, canvas, husky, puppeteer, lodash, express, axios. 0 Rule 2 hits across 2 git commits. Full results in false-positives.md. |

The custom scripts were chosen over the standard atomics because they produce
observable behavior (process creation, network callback) without touching real
credentials, real external infrastructure, or requiring the full Atomic Red Team
toolchain to be installed on the lab VM. The tradeoff is less standardization.
If this project were extended, running the actual atomics against the same logging
setup would be the right next step for T1071.001.
