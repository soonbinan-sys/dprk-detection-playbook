# DPRK Detection Playbook

A detection engineering project based on a documented North Korea linked software
supply chain intrusion. The repository follows the workflow from threat research
and ATT&CK mapping through Sigma and YARA rule development, supporting utilities,
and a documented validation process.

The project is intended to demonstrate how publicly documented tactics,
techniques, and procedures can be translated into practical detections rather
than provide a complete malware analysis or threat actor profile.

## Why this project

This project is centered on the March 2026 UNC1069 compromise of the axios npm
package, attributed by Google Threat Intelligence Group, and the broader North
Korea linked developer targeting campaign known as Contagious Interview (also
tracked as Famous Chollima), including the BeaverTail,
InvisibleFerret, and OtterCookie malware families.

The goal is not to profile a threat actor. It is to take publicly documented
TTPs and turn them into practical, testable detections the way a detection
engineering team would.

## Structure

- `01-research/`, the anchor incident, the broader campaign pattern, and the ATT&CK mapping
- `02-simulation/`, how telemetry for this project gets generated, safely
- `03-telemetry/`, expected log schema and sample data
- `04-detections/`, Sigma rules, YARA heuristics, and a static package.json check
- `05-validation/`, coverage matrix and false positive notes, fill in after testing
- `docs/writeup.md`, the full narrative writeup

## A note on scope

No live malware samples were downloaded or executed anywhere in this project.
Simulated behavior uses MITRE Caldera, Atomic Red Team, and small custom scripts 
that reproduce observable behavior without executing the original malware. 
See `02-simulation/setup.md`.
