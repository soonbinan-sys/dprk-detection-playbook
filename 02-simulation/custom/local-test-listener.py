#!/usr/bin/env python3
"""
local-test-listener.py

Minimal HTTP listener that accepts POST, for testing the simulator
scripts in this folder. Python's built in http.server only serves GET
by default and returns 501 for POST, which is enough to prove a
network callback happened but won't show you the payload. This does.

Usage:
  python3 local-test-listener.py
"""

from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        print(f"[listener] received from {self.client_address[0]}: {body}")
        self.send_response(200)
        self.end_headers()


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8787), Handler).serve_forever()
