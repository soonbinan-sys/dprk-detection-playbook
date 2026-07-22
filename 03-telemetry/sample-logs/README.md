# Sample logs

This folder holds telemetry captured from your own simulation runs
(`02-simulation/`), not real incident data. Nothing in this project touches real
North Korea linked malware, so nothing here is real attack traffic either.

## Expected shape

Once you're capturing process creation and network events (see
`02-simulation/setup.md`), the fields the Sigma rules in `04-detections/sigma/`
expect are the standard Sysmon style set.

- `ParentImage`, `Image`, `CommandLine`
- `DestinationIp`, `DestinationPort`
- `User`, `UtcTime`

If your logging tool uses different field names, auditd's raw format does, either
normalize on ingest or adjust the Sigma `logsource` and field names to match.
Whichever you did, note it here.

## Example entry

Synthetic, shows the target shape, not a captured log. Replace with your own output
once you've run the simulators.

```json
{
  "UtcTime": "2026-07-17T14:02:11Z",
  "ParentImage": "C:\\Program Files\\nodejs\\node.exe",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c node postinstall-callback-simulator.js",
  "DestinationIp": "127.0.0.1",
  "DestinationPort": 8787,
  "User": "DEV-WS\\ned"
}
```

## Status

No logs captured yet. Run the simulators in `02-simulation/`, capture with the tool
you chose, and drop the real output here.
