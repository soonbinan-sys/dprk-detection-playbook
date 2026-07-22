# Coverage matrix

Status as of 2026-07-20. All rules tested against simulated telemetry in controlled
lab environments. False positive testing against a real baseline has not yet been
run, see `false-positives.md`.

| Technique | ATT&CK ID | Rule | Tested | Result |
|---|---|---|---|---|
| Lifecycle script execution | T1059.007 | sigma/suspicious_child_process_from_npm.yml | yes, Windows VM, postinstall-callback-simulator.js, 2026-07-20 | 4 matches across 2 test runs, matched on node.exe spawning cmd.exe during simulated lifecycle script, no matches on normal npm init steps |
| Git hook abuse | T1546 (closest fit) | sigma/process_execution_from_git_hooks.yml | yes, real auditd telemetry, Ubuntu VM, 2026-07-18 | condition confirmed true by manual check, see note below |
| Known malicious package name | T1195.001 | yara/DPRK_NPM_Known_Malicious_Package_Name | verified against synthetic strings, not real telemetry | matched intended string, did not match clean sample |
| Lifecycle plus network heuristic | T1195.001 | yara/Suspicious_NPM_Package_Lifecycle_Network_Heuristic | verified against synthetic strings, not real telemetry | matched intended pattern, did not match clean sample |
| Lifecycle script presence, static | T1195.001 | static-checks/check_package_lifecycle_scripts.py | tested against synthetic package.json fixtures | correctly flagged lifecycle scripts and known bad name, correctly skipped node_modules, correctly passed clean input |

## Known gaps, not yet covered by a rule

From `01-research/attack-mapping.md`, rows 5, 6, 7, and 9: C2 callback rarity
detection, credential and wallet theft on host, and require time (not install time)
execution. Listed here deliberately, a portfolio that shows what isn't covered yet
is more credible than one that implies full coverage.

## Git hook rule, tested 2026-07-18

Ran as a real pre-commit hook on the Ubuntu VM with auditd capturing execve. The
invocation (`/usr/bin/env bash .git/hooks/pre-commit`) was captured, and
`.git/hooks/pre-commit` appears in both the `proctitle` and `EXECVE` fields, so the
rule's condition is true for this event. auditd has no native `CommandLine` field,
the match was confirmed by hand against `proctitle` and `EXECVE` argv, not by
running the rule through an actual conversion backend. A real deployment would need
a small pySigma processing pipeline mapping `CommandLine` to `proctitle` for this to
convert and run automatically, that's a reasonable stretch goal, not required for
this to count as tested.

