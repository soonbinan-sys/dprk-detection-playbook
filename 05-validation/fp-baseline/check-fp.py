#!/usr/bin/env python3
# Checks ausearch output against the two Sigma rule conditions.
# Usage: python3 check-fp.py fp-session.log

import sys
import re
from pathlib import Path

LOG = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "fp-session.log"

# Rule 1: suspicious_child_process_from_npm.yml
# Parent is npm/node/yarn/pnpm, child is a shell or interpreter
PARENT_MATCH = ("npm", "node", "yarn", "pnpm")
CHILD_MATCH  = ("sh", "bash", "zsh", "curl", "wget", "python", "perl", "ruby")

# Rule 2: process_execution_from_git_hooks.yml
HOOK_STRINGS = (".git/hooks",)

rule1_hits = []
rule2_hits = []

# Parse ausearch blocks — each block separated by ----
current = {}
blocks = []

with open(LOG) as f:
    for line in f:
        line = line.strip()
        if line == "----":
            if current:
                blocks.append(current)
            current = {}
            continue
        if line.startswith("time->"):
            current["time"] = line[6:]
        elif "type=EXECVE" in line:
            args = re.findall(r'a\d+="([^"]+)"', line)
            current["execve"] = " ".join(args)
        elif "type=SYSCALL" in line:
            m = re.search(r'ppid=(\d+).*pid=(\d+).*comm="([^"]+)".*exe="([^"]+)"', line)
            if m:
                current["ppid"] = m.group(1)
                current["pid"]  = m.group(2)
                current["comm"] = m.group(3)
                current["exe"]  = m.group(4)
        elif "type=CWD" in line:
            m = re.search(r'cwd="([^"]+)"', line)
            if m:
                current["cwd"] = m.group(1)

if current:
    blocks.append(current)

# Build pid->exe map for parent lookup
pid_exe = {b["pid"]: b["exe"] for b in blocks if "pid" in b and "exe" in b}

for b in blocks:
    if "exe" not in b or "execve" not in b:
        continue

    exe    = b["exe"].lower()
    execve = b["execve"].lower()
    ppid   = b.get("ppid", "")
    parent_exe = pid_exe.get(ppid, "").lower()

    # Rule 1 check
    if any(p in parent_exe for p in PARENT_MATCH):
        if any(c in exe for c in CHILD_MATCH):
            rule1_hits.append(b)

    # Rule 2 check
    if any(h in execve for h in HOOK_STRINGS):
        rule2_hits.append(b)

print(f"\n=== Rule 1: suspicious_child_process_from_npm — {len(rule1_hits)} hits ===")
for h in rule1_hits:
    print(f"  {h.get('time','')}  parent={pid_exe.get(h.get('ppid',''), '?')}  child={h.get('exe','?')}")
    print(f"    cmd: {h.get('execve','')[:120]}")

print(f"\n=== Rule 2: process_execution_from_git_hooks — {len(rule2_hits)} hits ===")
for h in rule2_hits:
    print(f"  {h.get('time','')}  exe={h.get('exe','?')}")
    print(f"    cmd: {h.get('execve','')[:120]}")

print()
