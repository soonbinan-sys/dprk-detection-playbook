# Sources

## Primary attribution, UNC1069 / axios

- Google Cloud Blog, Google Threat Intelligence Group. "North Korea-Nexus Threat
  Actor Compromises Widely Used Axios NPM Package in Supply Chain Attack." April 2026.
  https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package
  Official GTIG attribution and technical writeup. Includes a hunting YARA rule for
  one loader stage, worth reading as a model, not copying.

- Tenable. "Axios npm Supply Chain Attack FAQ, North Korea UNC1069." April 2026.
  https://www.tenable.com/blog/faq-about-the-axios-npm-supply-chain-attack-by-north-korea-nexus-threat-actor-unc1069
  Clearest technical FAQ. Best source for the token versus OIDC precedence detail.

- Huntress. "Supply Chain Compromise of axios npm Package." March 2026.
  https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package
  BlueNoroff lineage detail, the macWebT to RustBucket overlap.

- The Hacker News. "UNC1069 Social Engineering of Axios Maintainer Led to npm Supply
  Chain Attack." April 2026.
  https://thehackernews.com/2026/04/unc1069-social-engineering-of-axios.html
  The maintainer's own account of the social engineering approach.

- Cloud Security Alliance research note. "UNC1069 Axios Supply Chain Attack, AI
  Vendor Code Signing at Risk." April 2026.
  https://labs.cloudsecurityalliance.org/research/csa-research-note-unc1069-ai-vendor-npm-codesigning-supply-c/
  Downstream OpenAI code signing impact, and the roughly 1,700 package estimate
  across npm, PyPI, Go, and Rust since January 2025.

## Broader pattern, Contagious Interview / Famous Chollima

- MITRE ATT&CK. Group G1052, Contagious Interview.
  https://attack.mitre.org/groups/G1052/
  Canonical group profile and alias list (DeceptiveDevelopment, Gwisin Gang,
  Tenacious Pungsan, DEV#POPPER, PurpleBravo, TAG-121).

- Unit 42. "Contagious Interview, DPRK Threat Actors Lure Tech Industry Job Seekers
  to Install New Variants of BeaverTail and InvisibleFerret Malware." October 2024.
  https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/
  Original BeaverTail and InvisibleFerret naming and analysis.

- AhnLab ASEC. "April 2026 Threat Trend Report on APT Groups" and "May 2026 Threat
  Trend Report on APT Groups." https://asec.ahnlab.com/en/
  Monthly tracking. Source for the git hook and Jenkins CI/CD abuse detail, and for
  the Famous Chollima naming. Published in English, but check the Korean language
  originals directly where possible, that's the differentiator worth keeping.

- The Hacker News. "North Korean Hackers Publish 108 Malicious Packages and
  Extensions in PolinRider Campaign." July 2026.
  https://thehackernews.com/2026/07/north-korean-hackers-publish-108.html

- TechTimes. "North Korea's Lazarus Group Hid a Full RAT in Six Rollup Polyfill npm
  Packages." July 2026.
  https://www.techtimes.com/articles/319672/20260704/north-koreas-lazarus-group-hid-full-rat-six-rollup-polyfill-npm-packages.htm
  Require time execution evading npm v12's install time script blocking default.

- lazarus.day. Aggregated North Korea threat reporting tracker.
  https://lazarus.day/reports/2026/

## Adjacent pattern, DPRK IT workers and insider access

- Google Cloud. "Cloud Threat Horizons Report H1 2026."
  https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h1-2026
  Source for the UNC5267 / DPRK IT Workers cluster naming.

- Google Cloud Blog. "The Ultimate Insider Threat, North Korean IT Workers."
  https://cloud.google.com/transform/ultimate-insider-threat-north-korean-it-workers

## How to use this list in the writeup

Cite GTIG and Tenable directly for the anchor incident, they're the primary sources.
Cite at least one ASEC report directly rather than only outlets quoting it, that's
the differentiator worth keeping visible rather than folding into a generic
"industry reporting" line.
