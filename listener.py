#!/usr/bin/env python3
"""
listener.py — A local capture server for YOUR OWN isolated lab VM.

PURPOSE
    When you test add-ons in an isolated Tally VM (no internet, host-only
    network), point any test traffic at this server so you can *see* what an
    add-on would have sent. It simply logs method, path, headers and body to
    the console and to capture.log. It sends nothing anywhere.

    This is the "microscope", not the "specimen". It lets you observe behaviour
    in a sealed lab so your scanner's findings can be confirmed against reality.

SAFETY / SCOPE
    - Bind to localhost or a host-only address ONLY. Do not expose this to a
      real network. It intentionally accepts anything so you can inspect it.
    - Use it exclusively with add-ons YOU own/control on a VM YOU own.

RUN
    pip install flask
    python listener.py            # binds 127.0.0.1:8899 by default
    python listener.py --host 127.0.0.1 --port 8899
"""

from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path

try:
    from flask import Flask, request, Response
except ImportError:  # pragma: no cover
    raise SystemExit("Flask is required: pip install flask")


app = Flask(__name__)
LOG_PATH = Path("capture.log")


def _now() -> str:
    # Wall-clock timestamp for human-readable logs.
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _record(kind: str, detail: dict) -> None:
    line = json.dumps({"ts": _now(), "kind": kind, **detail}, ensure_ascii=False)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


@app.route("/", defaults={"path": ""},
           methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@app.route("/<path:path>",
           methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def capture(path: str) -> Response:
    body = request.get_data(as_text=True)
    detail = {
        "method": request.method,
        "path": "/" + path,
        "query": request.query_string.decode("utf-8", "replace"),
        "remote": request.remote_addr,
        "headers": dict(request.headers),
        "body": body[:5000],  # cap huge bodies in the console view
        "body_len": len(body),
    }

    print("\n" + "=" * 60)
    print(f"[{_now()}] {detail['method']} {detail['path']}"
          + (f"?{detail['query']}" if detail["query"] else ""))
    print(f"  from   : {detail['remote']}")
    print(f"  agent  : {detail['headers'].get('User-Agent', '-')}")
    if body:
        print(f"  body   : ({detail['body_len']} bytes)")
        print("  " + body[:1000].replace("\n", "\n  "))
    print("=" * 60)

    _record("request", detail)
    # Reply with something innocuous so the client's request completes cleanly.
    return Response("OK\n", status=200, mimetype="text/plain")


@app.route("/__health", methods=["GET"])
def health() -> Response:
    return Response("listener up\n", status=200, mimetype="text/plain")


def main() -> int:
    ap = argparse.ArgumentParser(description="Local lab capture server.")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address. Keep it localhost/host-only. Default 127.0.0.1")
    ap.add_argument("--port", type=int, default=8899)
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost") and not args.host.startswith(("10.", "192.168.", "172.")):
        print("WARNING: binding to a non-local address. Keep this off real networks.")

    print(f"Lab capture listener on http://{args.host}:{args.port}")
    print(f"Logging to {LOG_PATH.resolve()}")
    print("Health check: /__health   |   Ctrl+C to stop")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
