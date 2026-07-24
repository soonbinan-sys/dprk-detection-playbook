#!/bin/bash
# Logs parent/child process relationships relevant to the two Sigma rules.
# Polls every 2 seconds. Run during normal dev activity, stop with Ctrl+C.
# Output: process-log.tsv

OUTFILE="$(dirname "$0")/process-log.tsv"
echo -e "timestamp\tpid\tppid\timage\tparent_image\tcommand" > "$OUTFILE"

while true; do
    ps -eo pid,ppid,comm,command | tail -n +2 | while read pid ppid comm command; do
        parent_comm=$(ps -p "$ppid" -o comm= 2>/dev/null)
        echo -e "$(date '+%Y-%m-%dT%H:%M:%S')\t$pid\t$ppid\t$comm\t$parent_comm\t$command"
    done >> "$OUTFILE"
    sleep 2
done
