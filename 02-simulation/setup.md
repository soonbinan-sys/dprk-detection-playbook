# Simulation setup

Goal, generate realistic telemetry for the techniques in
`01-research/attack-mapping.md` without downloading or running any real North Korea
linked malware. Everything here is either an open source, purpose built adversary
emulation tool, or a small script you write yourself that only logs and makes a
local network call.

## Environment

Use a disposable VM or container, not your main machine. A single Linux VM covers
most of this project, since the core techniques are process execution and network
callbacks, not OS specific behavior. Snapshot it before you start so you can reset
between runs.

## Tool coverage versus custom scripts

Atomic Red Team and Caldera have broad, well tested coverage for generic techniques
like credential access, discovery, and C2 style network beaconing. Neither has a
ready made procedure for "malicious npm postinstall script" or "malicious git hook,"
because those are specific to this campaign family, not generic enough to be a
library atomic. Use the tools where they actually fit, write your own small scripts
where they don't. Don't force a generic atomic to stand in for a technique it wasn't
built for, that produces telemetry that doesn't match what you're trying to detect.

## Atomic Red Team

```
git clone https://github.com/redcanaryco/atomic-red-team.git
```

Relevant folders for this project's gaps, `atomics/T1071.001/` (application layer
C2) and `atomics/T1552.001/` (credentials in files). Browse and run individual
tests, don't run the framework unattended. Selected tests get logged in
`02-simulation/atomics/selected-atomics.md`.

## Caldera

```
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip install -r requirements.txt
python3 server.py --insecure
```

Heavier to set up than Atomic Red Team, but gives you a real adversary profile and
an operation log, useful if the writeup should show an actual operation record
rather than one off script runs.

## Custom scripts for the campaign specific techniques

See `02-simulation/custom/`. Two scripts.

- `postinstall-callback-simulator.js`, stands in for a malicious npm lifecycle
  script. Logs what it would have targeted and makes one HTTP request to a local
  test listener you control. Doesn't touch real credentials, files, or external
  hosts.
- `git-hook-simulator.sh`, the same pattern for a malicious pre-commit hook.

Start a local listener first so the callback has somewhere to go:

```
python3 02-simulation/custom/local-test-listener.py
```

Plain `python3 -m http.server` only serves GET and returns a 501 for the POST the
simulators send, that's real, tested behavior, not a hypothetical. It's harmless
for telemetry purposes, the outbound connection still happens and still shows up in
network logs, but `local-test-listener.py` actually accepts the callback and prints
the payload, which is more useful for confirming things work end to end.

Then run the simulator scripts and capture whatever telemetry your environment
produces.

## Capturing telemetry

You need a way to actually record process creation and network events. Roughly in
order of setup effort:

- `auditd` on Linux with a process/execve rule, cheapest to stand up
- Sysmon for Linux or a lightweight EDR trial, more detail, more setup
- Wazuh, if you also want a SIEM to query against later, the heaviest setup of the
  three

Whichever you pick, write the exact field names you're capturing into
`03-telemetry/sample-logs/README.md` so the Sigma rules can be checked against the
real fields, not assumed ones.

## Querying what you captured

Two things caused a false lead during testing, worth knowing before they cost you
time again.

`ausearch -ts recent` means the last 10 minutes, literally, not "since I started
this project." Search more than 10 minutes after triggering a simulator and it
comes back empty even though the event is still in the log. Use `-ts today` or an
explicit `-ts <time> -te <time>` range for anything older.

Grepping for a tool name like `curl` isn't specific enough on a machine running
anything else, Docker health checks, cron jobs, and monitoring agents all use curl
too, and they'll outnumber your one test run. `cwd` is a far more reliable filter,
everything a given test actually runs shares the same working directory, so grep
for `cwd=/path/to/your/scratch/repo` instead of the tool name.
