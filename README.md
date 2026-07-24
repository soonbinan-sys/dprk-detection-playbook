# DPRK Detection Playbook

A detection engineering project based on a documented North Korea linked software
supply chain intrusion. The repository follows the workflow from threat research
and ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) mapping 
through Sigma and YARA rule development, supporting utilities, and a documented 
validation process.

The project is intended to demonstrate how publicly documented TTPs (tactics,
techniques, and procedures) can be translated into practical detections rather
than provide a complete malware analysis or threat actor profile.

## Why this project

This project is centered on the March 2026 UNC1069 compromise of the axios npm
package, attributed by Google Threat Intelligence Group, and the broader North
Korea linked developer targeting campaign known as Contagious Interview (also
tracked as Famous Chollima), including the BeaverTail, InvisibleFerret, and 
OtterCookie malware families.

The goal is not to profile a threat actor. It is to take publicly documented
TTPs (tactics, techniques, and procedures) and turn them into practical, testable
detections the way a detection engineering team would.

## Structure

- `01-research/`, the anchor incident, the broader campaign pattern, and the ATT&CK mapping
- `02-simulation/`, how telemetry for this project gets generated, safely
- `03-telemetry/`, expected log schema and sample data
- `04-detections/`, Sigma rules, YARA heuristics, and a static package.json check
- `05-validation/`, coverage matrix and false positive notes
- `docs/writeup.md`, the full narrative writeup

## A note on scope

No live malware samples were downloaded or executed anywhere in this project.
Simulated behavior uses MITRE Caldera (an ATT&CK-based adversary emulation
platform), Atomic Red Team, and small custom scripts that reproduce observable
behavior without executing the original malware.
See `02-simulation/setup.md`.

### What happened in the real attack

In March 2026, a North Korea linked hacker group called UNC1069 broke into the
publishing account of a popular open source software package called axios. Axios
is a tool used by millions of software developers worldwide to make web requests
in their code. The attackers pushed two poisoned versions of the package to the
public software registry where developers download it. For about three hours,
anyone who downloaded axios got malware along with it.

The malware, once installed on a developer's machine, quietly collected
information about the computer — the hostname, the logged-in user, the operating
system — and sent it back to the attackers. It then waited for further
instructions. This kind of malware is called a remote access trojan, or RAT.
The attackers could use it to steal files, credentials, or cryptocurrency wallets
from the infected machine.

The attackers got access to the axios publishing account through social engineering, 
where they impersonated a real company executive, built a fake Slack workspace, and 
scheduled a video call with the package maintainer to build trust before making their 
move. No code was hacked. An employee was deceived.

### What this project does

This project does not reproduce the attack or the malware. Instead, it asks what the 
event would look like in the logs if it happened again and how you could write a 
rule to catch it automatically.

The answer involves two main detection rules:

**Rule 1** watches for a specific process pattern. When you install a software
package using npm (the tool developers use to download JavaScript packages), the
installation process normally runs quietly in the background. Malicious packages
abuse a feature called lifecycle scripts to run hidden commands the moment you
install them — before you've reviewed anything. The rule watches for the package
manager spawning a shell or command interpreter as a child process, which is the
computer-level signature of that behavior. A normal, clean install does not do
this. A malicious one does.

**Rule 2** watches for a different attack pattern documented in the same campaign. 
Git is the tool developers use to track changes to their code and has a feature 
called hooks. These are scripts that run automatically when you do things like save 
your work (commit). Attackers planted malicious hooks in repositories so that the
malware ran automatically the next time a developer did routine work. The rule
watches for any process that references the hooks folder, which is specific enough
to be worth investigating every time it appears.

### What was built and tested

Both rules were tested in two ways. First, simulated attack behavior was run in a 
controlled virtual machine environment to confirm the rules fire when they should. 
Second, normal development activity such as installing real and clean software 
packages and saving code changes was run against the same rules to confirm they do 
not fire constantly on innocent activity. Both rules produced zero false alarms 
during the normal activity test.

The simulations used a tool called MITRE Caldera, which is an industry-standard
adversary simulation platform used by professional red teams. A simulated implant
was deployed on a virtual machine and tasked to collect system information and
send it to a listener, replicating the documented behavior of the real malware.
The logging system captured the full chain of events, confirming the behavior is 
visible and detectable.

### What this project does not do

It does not contain any real malware. It does not connect to any real attacker
infrastructure. It does not reproduce the social engineering or the npm registry
compromise. Everything ran inside isolated virtual machines with no connection
to the internet. The goal is to understand the behavior well enough to detect it,
not to replicate the harm.
