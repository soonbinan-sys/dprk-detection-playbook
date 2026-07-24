# False positive testing

Status: baseline completed 2026-07-22. Both rules produced zero false positives
across a 10-minute active session on Ubuntu VM covering 8 npm package installs
(native modules, postinstall scripts, and clean packages) and 2 git commits.
See Results section for full findings and tuning decisions.

## Method

For each Sigma rule, run it against a normal window of your own development
activity, not just the simulated malicious telemetry. A rule only tested against
the thing it was built to catch tells you nothing about whether it's usable in a
real environment.

1. Capture 24 to 48 hours of your own normal dev activity with the same logging
   setup from `02-simulation/setup.md`.
2. Run each Sigma rule against that baseline.
3. For every hit, record what triggered it and whether it's a real false positive or
   something the rule should reasonably tune around.
4. Adjust the rule, re-run, repeat.

## Known false positive risks to check first

Seeded from the false positives field already written into each rule, verify these
specifically rather than waiting to discover them.

- `suspicious_child_process_from_npm.yml`, native module builds that shell out
  during install (node-gyp and similar). Expect this to fire on a normal
  `npm install` in some projects. During the Windows simulation, normal npm
  initialization steps (npm-cli.js, npm-prefix.js) did not trigger the rule,
  only the simulated lifecycle script execution did. That's a good sign but not
  a substitute for baseline testing across real projects.
- `process_execution_from_git_hooks.yml`, legitimate pre-commit linters and
  commit-msg validators. Expect this to be noisy by default in any repo using
  husky, pre-commit, or similar tooling. The auditd field mapping also needs
  a pySigma (Python-based Sigma rule conversion library) processing pipeline
  to convert CommandLine to proctitle before this rule can run automatically
  against Linux telemetry.

## Results

Baseline session run 2026-07-22 on Ubuntu VM (192.168.56.2), approximately 22:48
to 22:58 EDT. auditd captured all process activity. check-fp.py parsed the
ausearch output against both rule conditions.

### Rule 1: suspicious_child_process_from_npm

0 hits across the following installs:

| Package | Type | node-gyp triggered | Shell child spawned |
|---|---|---|---|
| bcrypt | native module | no | no |
| sqlite3 | native module | no | no |
| canvas | native module | no | no |
| husky | postinstall script | no | no |
| puppeteer | postinstall script | no | no |
| lodash | clean | no | no |
| express | clean | no | no |
| axios | clean | no | no |

All native module packages (bcrypt, sqlite3, canvas) installed via prebuilt
binaries rather than compiling from source. No node-gyp invocation, no shell
spawning. The FP risk documented in the rule is real in theory but did not
materialize on this platform (Ubuntu aarch64, node v22, npm 10).

Tuning decision: no change to the rule. The falsepositives field already
documents node-gyp as the expected FP source. The baseline confirms the rule
does not over-trigger on modern packages using prebuilt binaries. A follow-up
test on a platform that forces source compilation (older node, missing prebuilt
binary for the architecture) would be the right next step to confirm the FP
behavior actually occurs before adding an exclusion.

### Rule 2: process_execution_from_git_hooks

0 hits across 2 git commits in a freshly initialized repo with no hooks
installed. Expected result — the rule fires on CommandLine containing
`.git/hooks`, which only appears when a hook is actually invoked. A repo with
no hooks produces no hook-related process events.

Tuning decision: no change to the rule. To observe the expected FP behavior
(legitimate pre-commit linter triggering the rule), the next step would be to
install husky or pre-commit in the test repo, configure a hook, and commit
again. That test is documented as a gap here rather than skipped silently.

### Noise observed

The ausearch output contained significant background noise from a Docker
healthcheck (`pg_isready -U reportcreator`) firing every 2 seconds throughout
the session. This was filtered out and is unrelated to either rule. In a
production deployment, auditd rules scoped to specific UIDs or working
directories would reduce this noise at the collection layer rather than at
query time.
