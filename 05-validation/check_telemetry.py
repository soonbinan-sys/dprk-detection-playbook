#!/usr/bin/env python3
"""
check_telemetry.py

Turns raw `ausearch -k proc_exec ... -i` output into a readable table and
flags lines that match this project's Sigma rules.

Usage:
  sudo ausearch -k proc_exec -ts recent -i | python3 check_telemetry.py
  python3 check_telemetry.py captured.log
  python3 check_telemetry.py --all captured.log

By default, failed exec attempts (PATH search misses, mostly noise) are
hidden. --all shows everything.

Currently checks against:
  - process_execution_from_git_hooks.yml, command line contains .git/hooks
    or .git\\hooks

Does not check suspicious_child_process_from_npm.yml yet, that rule needs
parent to child correlation across events, not built here, tracked as a
gap in 05-validation/coverage-matrix.md rather than half implemented.

Deliberately does not print auid, uid, tty, or ses, keeps the identity
fields that would otherwise expose the machine this ran on out of
anything you'd paste into a writeup.
"""

import re
import sys

GIT_HOOKS_PATTERNS = ('.git/hooks', '.git\\hooks')


def parse_events(text):
    """Group audit lines by serial number into one dict per event, in order seen."""
    events = {}
    order = []
    for line in text.splitlines():
        m = re.match(r'type=(\S+)\s+msg=audit\(([\d/]+\s[\d:.]+):(\d+)\)\s*:\s*(.*)', line)
        if not m:
            continue
        rec_type, timestamp, serial, rest = m.groups()
        if serial not in events:
            events[serial] = {'serial': serial, 'time': timestamp}
            order.append(serial)
        ev = events[serial]

        if rec_type == 'SYSCALL':
            for field in ('success', 'comm', 'exe', 'ppid', 'pid'):
                fm = re.search(rf'\b{field}=(\S+)', rest)
                if fm:
                    ev[field] = fm.group(1)
        elif rec_type == 'EXECVE':
            argc_m = re.search(r'\bargc=(\d+)', rest)
            if argc_m:
                argc = int(argc_m.group(1))
                args = []
                for i in range(argc):
                    end = rf'\s+a{i + 1}=' if i + 1 < argc else r'$'
                    am = re.search(rf'\ba{i}=(.*?)(?:{end})', rest)
                    args.append(am.group(1).strip() if am else '?')
                ev['command'] = ' '.join(args)
        elif rec_type == 'CWD':
            cm = re.search(r'\bcwd=(\S+)', rest)
            if cm:
                ev['cwd'] = cm.group(1)
        elif rec_type == 'PROCTITLE':
            pm = re.search(r'proctitle=(.*)', rest)
            if pm:
                ev['proctitle'] = pm.group(1).strip()

    return [events[s] for s in order]


def matches_git_hooks_rule(ev):
    text = ev.get('command') or ev.get('proctitle') or ''
    return any(p in text for p in GIT_HOOKS_PATTERNS)


def main(argv):
    show_all = '--all' in argv
    argv = [a for a in argv if a != '--all']

    text = open(argv[1]).read() if len(argv) > 1 else sys.stdin.read()
    events = parse_events(text)

    col = '{:<13} {:<8} {:<8} {:<7} {:<6} {}'
    print(col.format('TIME', 'PID', 'PPID', 'STATUS', 'RULE', 'COMMAND'))
    print('-' * 100)

    shown = 0
    hidden = 0
    for ev in events:
        failed = ev.get('success') == 'no'
        if failed and not show_all:
            hidden += 1
            continue
        shown += 1
        display = ev.get('command') or ev.get('proctitle') or ev.get('comm', '?')
        status = 'failed' if failed else 'ok'
        rule_hit = 'MATCH' if matches_git_hooks_rule(ev) else ''
        time_short = ev['time'].split(' ')[1] if ' ' in ev['time'] else ev['time']
        print(col.format(time_short, ev.get('pid', '?'), ev.get('ppid', '?'), status, rule_hit, display))

    if hidden:
        print(f"\n{hidden} failed exec attempt(s) hidden, mostly PATH search noise. Use --all to see them.")
    if shown == 0:
        print("no events parsed, check the input is raw ausearch -i output")


if __name__ == '__main__':
    main(sys.argv)
