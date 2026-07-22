# DPRK detection playbook

This project focuses on a single documented software supply chain intrusion and 
follows the process of turning publicly reported TTPs into practical detections. 
Rather than covering every aspect of the campaign, the emphasis is on detection 
engineering, including ATT&CK mapping, rule development, and validation.

The anchor is the March 2026 compromise of the axios npm package, attributed by
Google Threat Intelligence Group to a North Korea linked actor tracked as UNC1069.
Around that single incident sits the broader Contagious Interview campaign
(also tracked as Famous Chollima), which has targeted developers since 2023. 
Using both gives the project depth on one incident and breadth across a pattern, so 
the detections in this project focus on the underlying technique rather than 
campaign specific indicators.

## What's real and what's lab

Worth stating plainly before anything else, since it's easy to blur once the
narrative gets going. The table below defines that boundary.

| Real attack component | What's simulated in this project | What it explicitly does not do |
|---|---|---|
| WAVESHAPER.V2 RAT, delivered via the SILKBELL dropper (UNC1069, axios compromise) | `02-simulation/custom/postinstall-callback-simulator.js` | No malware code, no persistence, no credential access. Logs what a real stealer would target as plain text, spawns one harmless echo, makes one HTTP call to a listener on the same machine |
| Malicious git hook, part of the broader Contagious Interview pattern | `02-simulation/custom/git-hook-simulator.sh` | Same, logs intent, one local call, nothing else |
| The attacker's actual C2 infrastructure | `02-simulation/custom/local-test-listener.py`, bound to `127.0.0.1:8787` | Never leaves the lab machine, receives only a synthetic JSON payload, no real data of any kind |
| The real npm registry compromise and the maintainer social engineering that enabled it | Not simulated | This project starts after initial access, at the point malicious code is already running on a developer's machine, not before |

Everything under "what's simulated" ran on a disposable VM. Nothing here touched
the real npm registry, any real North Korea linked infrastructure, or any actual
malware sample.

## The anchor incident

On March 31, 2026, UNC1069 gained publish access to the axios npm package, one of
the most widely used HTTP libraries in the JavaScript ecosystem, and published two
backdoored versions carrying a cross platform remote access trojan. The malicious
versions were live for roughly three hours before being caught, but the blast
radius reached a GitHub Actions workflow inside OpenAI's own macOS code signing
pipeline.

The initial access wasn't a code vulnerability, it was social engineering aimed at
the maintainer. The attackers impersonated the founder of a legitimate company,
stood up a convincingly branded fake Slack workspace, and scheduled a video call to
build trust before the actual compromise happened.

The root cause is the part most relevant to a detection role. Axios had already
adopted OIDC based publishing with SLSA provenance attestations, the modern, more
secure approach. When both authentication methods were present, npm defaulted to 
the legacy token, effectively bypassing the intended provenance protections. 
This project focuses on that credential precedence issue because it illustrates how 
a modern publishing workflow can still be undermined by legacy credentials. 
It also wasn't an isolated stunt, GTIG's own reporting estimates UNC1069 activity 
has seeded roughly 1,700 malicious packages across npm, PyPI, Go, and Rust 
since January 2025.

## The broader pattern

Contagious Interview (also tracked as DeceptiveDevelopment, Gwisin Gang, and Famous
Chollima, among other names) is a North Korea aligned group active since 2023 that
runs both espionage and financially motivated operations against developers and
crypto workers across Windows, Linux, and macOS. Its malware chain, BeaverTail into
InvisibleFerret, more recently consolidated into a strain called OtterCookie, is the
broader family UNC1069 sits inside.

Reporting from May 2026 documented the group abusing git pre-commit and post-checkout 
hooks alongside Jenkins CI/CD pipelines, turning the developer workflow itself into the 
infection point rather than relying only on `npm install`. A campaign called PolinRider 
surfaced in July 2026, publishing over a hundred malicious packages across public 
repositories. Reporting has also documented attackers adapting to newer npm security 
controls. One Lazarus linked campaign hid a remote access toolkit inside fake Rollup
polyfill packages that executed at import time instead of install time, avoiding
npm's newer install-time script blocking defaults.

Building the project around this pattern, not just the one incident, is what makes
the detections in this repo technique level instead of indicator matching. A rule based 
solely on a campaign specific C2 domain has a limited lifespan. A rule based on observable 
behavior, such as a package lifecycle script spawning an unexpected child process, is more 
likely to remain useful across future campaigns.

## Threat model

The full technique mapping is in `01-research/attack-mapping.md`, ten rows covering
initial access through the credential precedence root cause, execution, command and control, 
and the adjacent DPRK IT worker insider access pattern. Several rows are marked as gaps 
rather than mapped to a rule that doesn't really cover them, C2 rarity detection and require 
time execution evasion both need infrastructure this project doesn't build, and are named as 
future work instead of skipped silently.

## Detection approach

Two Sigma rules. One flags a script interpreter or shell spawned as a child process
of npm, npx, yarn, or node, the pattern behind malicious lifecycle script execution.
The other flags process execution referencing a `.git/hooks` path, covering the
newer hook based infection vector. Both include documented false positives: 
native module builds for the lifecycle script rule and legitimate pre-commit tooling 
for the Git hook rule. Each rule documents expected false positives so the assumptions 
and limitations are clear.

Two YARA rules, deliberately different in kind. One matches a known malicious
package name from the Axios campaign specifically, IOC based, short shelf life by
design. The other is a heuristic for package.json files combining an install time
lifecycle script with network calls or common obfuscation patterns, technique
level, not tied to any one campaign. Keeping both in the repo, clearly labeled, is
meant to make the IOC versus technique tradeoff visible rather than picking one
silently.

One static check script, a Python scanner for package.json files that flags
lifecycle scripts and known malicious package names, and skips the node_modules 
directory so it's usable in a real CI job.

## Validation results

The validation process focused on confirming that the simulated behaviors produced 
the telemetry expected by the detection logic rather than attempting to recreate 
the full intrusion.

### Windows lifecycle script simulation

The Windows simulation used `postinstall-callback-simulator.js` to represent a malicious 
npm lifecycle script. During npm install, normal npm execution launched node.exe, which 
in turn spawned cmd.exe to execute the simulator.

<img width="4008" height="1545" alt="windows-postinstall-simulation-setup" src="https://github.com/user-attachments/assets/ad56e81b-52f6-46eb-887e-9f05fccf349a" />


The telemetry reader (`05-validation/check_telemetry.ps1`) correctly identified these 
child process relationships and marked the expected events as matches.

<img width="1119" height="880" alt="windows-npm-rule-match" src="https://github.com/user-attachments/assets/d1cb2296-e722-4f44-b0f6-4a42da915244" />


Observed execution chain:

```text
PowerShell
└── node.exe (npm install)
    └── cmd.exe
        └── node postinstall-callback-simulator.js
            └── cmd.exe /c echo ...
```

The rule generated matches only after `node.exe` spawned additional command execution 
associated with the simulated lifecycle script. Normal npm startup activity, including 
execution of `npm-cli.js` and `npm-prefix.js`, appeared in the telemetry but did not 
satisfy the detection criteria.

The simulation produced four rule matches across two test runs, corresponding to
the expected child process creation events generated by the simulator. No matches
were observed during the normal npm initialization steps preceding execution of
the simulated lifecycle script.

This behavior was expected. The rule is intended to identify unexpected child process 
creation during package installation rather than alert on every `npm install` invocation.

### Git hook simulation (Ubuntu)

The Linux simulation exercised the Git hook detection using `git-hook-simulator.sh`.

<img width="860" height="91" alt="linux-git-hook-simulation" src="https://github.com/user-attachments/assets/c3987ec5-78c1-4394-b8e9-23ff22af79b2" />

Auditd captured each stage of the workflow, including copying the simulated hook into 
`.git/hooks/pre-commit`, making it executable with `chmod +x`, and executing it during 
a Git operation. The resulting records contained the executable path, working directory, 
and command-line arguments expected by the Git hook Sigma rule.

The captured telemetry confirmed that the fields required by the rule were present in 
the simulated audit records.

### Static package analysis

The static package scanner successfully detected synthetic package manifests
containing:

- install-time lifecycle scripts
- known malicious package names used for testing

Directories under `node_modules` were skipped as intended to reduce unnecessary
scanning.

### YARA validation

The YARA rules were compiled successfully and tested against synthetic package samples.

The IOC-based rule matched the expected test artifact, while the heuristic rule matched 
package manifests containing the intended combinations of lifecycle scripts, networking 
behavior, and simple obfuscation patterns.

These tests confirm that the rules compile successfully and behave as expected against 
representative synthetic samples. They should not be considered a substitute for validation 
against production telemetry.

Overall, the validation demonstrated that the simulated behaviors generated the expected telemetry, 
the Sigma rules matched the intended process relationships, the YARA rules compiled and matched 
their synthetic samples, and the static package scanner identified the expected package 
characteristics. While these results are limited to controlled lab environments, they provide 
an initial validation of the detection logic before broader testing against production telemetry.

### Limitations

The validation performed for this project was intentionally limited to controlled simulations 
running inside disposable lab environments.

The simulations reproduce observable behaviors rather than the original malware and do 
not exercise persistence, credential theft, privilege escalation, or communication with 
external infrastructure.

The Sigma rules were validated against telemetry generated by the simulations, but they 
have not been tested against enterprise scale datasets or diverse production environments. 
As a result, the documented false positive guidance should be treated as an initial assessment 
rather than a complete evaluation.

This project is intended to demonstrate the workflow of researching a documented intrusion, 
mapping TTPs to ATT&CK, developing detections, and validating those detections against 
controlled telemetry. It is not intended to reproduce the original malware or serve as a 
substitute for testing in a production environment.


## Sources

Full bibliography in `01-research/sources.md`.
