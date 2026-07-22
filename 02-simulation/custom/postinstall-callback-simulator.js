/*
 * postinstall-callback-simulator.js
 *
 * Benign stand in for a malicious npm lifecycle script. Does not read
 * real credentials or files. Logs what a real postinstall stealer
 * would have targeted, then makes one HTTP request to a local test
 * listener so a network callback shows up in your telemetry the same
 * way it would in a real incident.
 *
 * Start a local listener first:
 *   python3 local-test-listener.py
 *
 * Then run this the way npm would run a postinstall script:
 *   node postinstall-callback-simulator.js
 */

const http = require('http');
const { spawn } = require('child_process');

const wouldHaveTargeted = [
  'environment variables (cloud credentials, tokens)',
  '~/.aws/credentials',
  '~/.config/gcloud',
  'browser extension local storage (crypto wallets)',
];

console.log('[simulator] a malicious postinstall script would target:');
wouldHaveTargeted.forEach((item) => console.log('  - ' + item));

// The network call below alone will not trigger
// suspicious_child_process_from_npm.yml, that rule looks for npm or node
// spawning a shell as a child process, which is what the real SILKBELL
// dropper did to run its next stage. This spawns a harmless echo through
// the platform shell so the process tree actually matches what the rule
// is built to catch.
const shell = process.platform === 'win32'
  ? spawn('cmd.exe', ['/c', 'echo simulator spawned this, no real action taken'])
  : spawn('sh', ['-c', 'echo simulator spawned this, no real action taken']);
shell.stdout.on('data', (d) => console.log('[simulator child]', d.toString().trim()));

const payload = JSON.stringify({ simulated: true, host: require('os').hostname() });

const req = http.request(
  {
    hostname: '127.0.0.1',
    port: 8787,
    path: '/callback',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    },
  },
  (res) => {
    console.log('[simulator] callback response status ' + res.statusCode);
  }
);

req.on('error', () => {
  console.log('[simulator] callback failed, start a listener first: python3 -m http.server 8787');
});

req.write(payload);
req.end();
