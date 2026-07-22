# Selected atomics

Which Atomic Red Team and Caldera procedures were considered, and what was actually
run. The two techniques below were covered by custom scripts instead of the
standard atomics, documented here so the decision is explicit rather than silent.

| ATT&CK ID | Atomic / procedure | Why chosen | Run |
|---|---|---|---|
| T1071.001 | Atomic Red Team T1071.001, generic C2 style beacon | Stands in for WAVESHAPER.V2's callback behavior | replaced by `02-simulation/custom/postinstall-callback-simulator.js` and `git-hook-simulator.sh`, both make a single HTTP POST to `local-test-listener.py` on 127.0.0.1:8787, running the actual atomic was out of scope given the controlled lab constraint |
| T1552.001 | Atomic Red Team T1552.001, credentials in files | Stands in for the documented targeting of cloud credential files and browser stored data | not run, remains a gap, listed in coverage-matrix.md under known gaps |

The custom scripts were chosen over the standard atomics because they produce
observable behavior (process creation, network callback) without touching real
credentials, real external infrastructure, or requiring the full Atomic Red Team
toolchain to be installed on the lab VM. The tradeoff is less standardization.
If this project were extended, running the actual atomics against the same logging
setup would be the right next step for T1071.001.
