# False positive testing

Status: baseline testing against normal dev activity not yet run. The simulations
confirmed the rules fire on the intended behavior. What isn't known yet is how
noisy they are in a real environment.

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
  a pySigma processing pipeline to convert CommandLine to proctitle before
  this rule can run automatically against Linux telemetry.

## Results

Not yet recorded. Baseline capture against normal dev activity is the next step.
