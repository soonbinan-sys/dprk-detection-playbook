# ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) mapping

Covers two things on purpose. The anchor incident (UNC1069's compromise of the axios
npm (Node Package Manager) package, March 2026) gives depth on one real, current,
well documented intrusion. The broader Contagious Interview / Famous Chollima pattern
it sits inside gives breadth, so the detections built from this table target
techniques, not one campaign's indicators.

Gaps are listed deliberately. A table that implies full coverage is less credible
than one that shows what isn't covered yet.

## Table

| # | Technique | ATT&CK ID | How it appeared | Primary telemetry | Coverage |
|---|---|---|---|---|---|
| 1 | Compromise software supply chain | T1195.001 | UNC1069 gained npm publish access to axios and pushed malicious versions 1.14.1 and 0.30.4 directly to the registry | npm registry publish logs, package version diffs | upstream, no local rule, see note 1 |
| 2 | Establish accounts / impersonation | T1585.001 | Attackers impersonated a company founder, built a branded fake Slack workspace, and scheduled a call to build trust with the maintainer before the compromise | outside telemetry scope | process control, note in writeup |
| 3 | Steal application access token | T1528 | A legacy long lived npm token stayed active alongside OIDC (OpenID Connect) / SLSA (Supply-chain Levels for Software Artifacts) provenance publishing, npm defaults to the token when both exist | npm registry auth logs, package provenance metadata | static-checks/, see note 2 |
| 4 | Command and scripting interpreter | T1059.007 | Malicious dependency "plain-crypto-js" executed at package install/require time, delivering the WAVESHAPER.V2 RAT via the SILKBELL dropper | process creation, parent npm/node, child script interpreter | sigma/suspicious_child_process_from_npm.yml |
| 5 | Ingress tool transfer | T1105 | Multi stage loader pattern, consistent with the BeaverTail to InvisibleFerret chain used across the wider campaign | network logs, outbound connection following install | gap, see note 3 |
| 6 | Application layer protocol (C2) | T1071 | WAVESHAPER.V2 establishes outbound C2 after install | network / DNS logs | gap, see note 3 |
| 7 | Credentials from password stores | T1555 / T1552.001 | BeaverTail is documented targeting browser data, crypto wallets, and cloud credential files on infected developer machines | EDR file access logs, browser extension directory access | gap, not yet built |
| 8 | Event triggered execution via dev lifecycle hooks | T1546 (closest fit) | May 2026 reporting documents git pre-commit and post-checkout hook abuse plus Jenkins CI/CD (Continuous Integration/Continuous Deployment) used to run malware as part of routine developer workflow, not only at npm install | process creation, parent path contains .git/hooks; CI job logs | sigma/process_execution_from_git_hooks.yml |
| 9 | Compromise software dependencies, timing evasion | T1195.001 | A documented case (the Rollup polyfill npm campaign, reported July 2026) fires at require/import time instead of install time, specifically to dodge npm v12's new install time script blocking default | requires runtime/require hook instrumentation, not install time monitoring alone | gap, partial static coverage, see note 4 |
| 10 | Trusted relationship via fraudulent employment | closest fit T1199 | Separate but related cluster, UNC5267, tracked by GTIG (Google Threat Intelligence Group) as DPRK (Democratic People's Republic of Korea) IT Workers, obtains privileged access via fraudulent remote employment, then uses it for data theft and extortion | HR/identity verification, access reviews | out of scope for this project's telemetry, adjacent pattern worth knowing |

## Notes

**Note 1.** Row 1 is a registry side control problem, not something a local Sigma
rule catches. Worth naming in the writeup as the actual first failure point, not
skipping because it doesn't produce a rule.

**Note 2.** Row 3 is the root cause with the most detection engineering relevance.
It is a credential precedence bug, the same class of problem IAM (Identity and
Access Management) systems like Cloud IAM exist to close. A local static check
can flag it in your own CI (continuous integration) config (publishing workflow
using a token when OIDC is also configured), see `04-detections/static-checks/`.

**Note 3.** Rows 5 and 6 need a rarity or baselining layer, not pure Sigma. "New
outbound connection from a CI or build process to a domain never seen before in this
environment" is the right detection, but it needs a frequency analysis backend
behind the SIEM, not a static rule. Naming this gap explicitly is itself a fair
thing to raise in an interview.

**Note 4.** Row 9 is the most technically interesting gap. Install time script
blocking is now a mainstream npm default, so the next campaign is already moving to
require time execution to route around it. A static check on package.json alone
cannot catch this, it needs runtime instrumentation of the require/import path.
Flagging this as future work in the writeup shows you're tracking where the field is
moving, not just where it's been.

**Note on row 8.** MITRE ATT&CK does not currently have a clean dedicated
sub-technique for development lifecycle hook abuse (git hooks, CI pipeline hooks).
T1546 (event triggered execution) is the closest parent technique but was designed
around OS level triggers, not developer tooling. Tagged here as the best available
fit, noted explicitly rather than forced into a technique it doesn't quite match.

## Sources

See `01-research/sources.md` for the full bibliography. Rows 1 to 6 draw primarily
from Google Threat Intelligence Group's own writeup and corroborating vendor
reporting. Rows 8 and 9 draw from AhnLab ASEC's May 2026 and July 2026 reporting.
Row 10 draws from Google Cloud's Threat Horizons H1 2026 report.
