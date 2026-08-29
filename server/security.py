"""
security.py

Security primitives for the ITC digital twin.

The twin models two independent, separately-keyed channels between the
central AI orchestration layer and each field intersection, mirroring
how ITC's real product is described publicly (a retrofit layer that
connects to *existing* cameras and *existing* traffic-light hardware
rather than replacing it):

  * the COMMAND channel: carries phase decisions from the AI
    orchestrator (or an attacker) to a field controller.
  * the TELEMETRY channel: carries detection events from the camera/
    sensor layer (or an attacker) to the orchestrator.

Separate keys enforce least privilege: a party who compromises one
channel cannot forge traffic on the other. A spoofed "camera" can lie
about vehicle counts but cannot directly command a signal, and a
compromised command path can't fabricate sensor history. This is a
standard security-architecture argument, not anything specific to
traffic control.

Also implemented here:

  * ConflictMonitor: an independent safety check modeled on the
    physical Malfunction Management Unit (MMU) hardware real traffic
    cabinets use. It is consulted regardless of how a command got this
    far and does not trust the command layer at all.
  * plausibility validation for telemetry: catches values a real
    camera could never report in one detection event, independent of
    whether the message carries a valid signature.
  * ThreatTracker: blocks a source after repeated unauthorized
    attempts, shared across both channels.

None of this is theoretical. In 2014, University of Michigan researchers
("Green Lights Forever: Analyzing the Security of Traffic Infrastructure")
found real production traffic controllers reachable over unencrypted,
unauthenticated radio links: the weakness the "legacy" mode models.
Preemption spoofing (forging an emergency-vehicle signal to jump a
queue) is a separately documented weakness class in real emergency-
vehicle-preemption (EVP) hardware, and is what "spoof-emergency" models.

A signature alone is not the same as freshness. Both signing functions
below fold a timestamp into the signed payload (not just alongside it),
and both verify functions reject anything outside a short validity
window even when the signature itself checks out mathematically. This
is what defeats a replay attack: capturing a real, validly-signed
message off a channel that, in a real deployment, is a physically
sniffable radio or wired link, and resending it later. MITRE ATT&CK for
ICS files this under T0831 (Manipulation of Control), which lists
replaying captured valid packets as one of its documented methods.
https://attack.mitre.org/techniques/T0831/ MITRE's own real-world
example for T0831 is a 2008 incident in Łódź, Poland, where a
14-year-old built a modified TV remote that could directly trigger a
city tram network's track-switch signals, derailing four trams; worth
citing honestly rather than overstating: reporting on the incident
describes him reverse-engineering and directly issuing switch commands,
closer to unauthorized command spoofing than a literal capture-and-
resend replay, even though MITRE groups both under the same technique.

This freshness check runs unconditionally on every command and
telemetry event, not behind a demo toggle: it is real hardening against
a real message-capture-and-resend scenario, independent of whether
anything in this project's UI specifically walks through demonstrating
it.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

# Two independent signing keys, one per channel. In a real deployment
# each would live in a hardware security module or managed secret store
# per device, with rotation; read from the environment here instead of a
# bare literal, because this project's source is meant to be publicly
# readable (it's a security demo on GitHub) -- a literal key sitting in
# committed source would mean anyone reading the repo could forge a
# "validly signed" request directly, defeating Secure mode's whole
# guarantee for any public deployment of it, not just the local demo.
# Set ITC_COMMAND_SIGNING_KEY / ITC_TELEMETRY_SIGNING_KEY in Render's
# Environment Variables dashboard (or any real deployment's secret
# store) for that deployment's actual keys; they are never written to a
# file in this repo. The literal fallback below only applies when the
# variable is unset, which is the normal, zero-setup local-dev case
# (`uvicorn main:app --reload` with nothing extra configured) -- it is
# deliberately labelled LOCAL-DEV-ONLY rather than looking like a real
# key that happens to also work, so it can't be mistaken for one.
COMMAND_SIGNING_KEY = os.environ.get(
    "ITC_COMMAND_SIGNING_KEY", "itc-orchestrator-command-channel-key-LOCAL-DEV-ONLY"
).encode("utf-8")
TELEMETRY_SIGNING_KEY = os.environ.get(
    "ITC_TELEMETRY_SIGNING_KEY", "itc-camera-telemetry-channel-key-LOCAL-DEV-ONLY"
).encode("utf-8")

# The undocumented maintenance override the legacy baseline's command
# channel accepts from anyone: stands in for a real debug/maintenance
# backdoor, a recurring class of bug in industrial control systems.
DANGEROUS_OVERRIDE_PHASE = "FORCE_ALL_GREEN"

# How long a signed message stays acceptable after being issued. Chosen
# deliberately generous rather than tight: real command/telemetry
# updates only go out when something actually changes (see
# orchestrator.py's `if desired_phase != intersection.phase` gate), so
# a captured signature is very often already close to this age by the
# time anyone could realistically replay it, and a window long enough
# to occasionally still let a fast replay through (rather than always
# silently blocking it) is a more honest demonstration of what a
# freshness window actually buys you: a bounded, not zero, exposure
# window, same as it would be for a real deployment.
COMMAND_FRESHNESS_WINDOW_SECONDS = 8.0
TELEMETRY_FRESHNESS_WINDOW_SECONDS = 8.0

# A single telemetry report models one detection event (typically one
# road user). Anything claiming more than this in a single report isn't
# a plausible camera reading: it's the signature of a forged "dump a
# fake queue" report used to poison the orchestrator's input data.
MAX_PLAUSIBLE_EVENT_COUNT = 5

# How many unauthorized attempts a single source may make (on either
# channel) before it is auto-blocked. Kept low on purpose: a legitimate
# orchestrator or camera never sends an unsigned or badly-signed message,
# so even one failure is suspicious.
MAX_FAILED_ATTEMPTS = 3

# How long a source stays blocked after tripping MAX_FAILED_ATTEMPTS.
# The block expires on its own, the same way an isolated intersection
# recovers on its own (see orchestrator.py's ISOLATION_SECONDS): a demo
# console has no separate operator identity to prove itself with, so
# requiring some other manual action to lift the block would just be a
# second thing to explain, not a more realistic model of anything.
BLOCK_DURATION_SECONDS = 30.0

# How many commands one junction may have ACCEPTED within
# COMMAND_RATE_LIMIT_WINDOW_SECONDS before the next one, however validly
# signed, is throttled anyway. This is a genuinely separate layer from
# MAX_FAILED_ATTEMPTS above, closing a real gap the freshness window on
# its own leaves open: ThreatTracker only counts FAILED attempts, so a
# captured signature replayed rapidly, each replay still succeeding
# because it is still inside its freshness window, never fails a single
# check and so never trips the auto-block at all.
#
# The threshold is deliberately calculated, not guessed, to guarantee
# it can never false-positive on real orchestrator traffic: the fastest
# two legitimate commands can ever land back to back is
# orchestrator.py's own ORCHESTRATOR_TICK_SECONDS (2s), since a new
# decision can only be made once per tick in the first place, and that
# floor holds even under gap-out's most aggressive early termination
# (GAP_OUT_MIN_GREEN_SECONDS is also 2s). So COMMAND_RATE_LIMIT_MAX
# commands need at least (COMMAND_RATE_LIMIT_MAX - 1) * 2 seconds even
# in the most extreme legitimate case; keeping that comfortably above
# COMMAND_RATE_LIMIT_WINDOW_SECONDS (4 * 2 = 8s > 5s here) is what makes
# this a real anomaly signal rather than a risk of throttling the AI
# orchestrator's own genuinely busy traffic.
COMMAND_RATE_LIMIT_MAX = 5
COMMAND_RATE_LIMIT_WINDOW_SECONDS = 5.0

# How many distinct `source` identities any per-source tracking structure
# in this project holds onto at once (this module's own ThreatTracker.
# failed_attempts below, and network.py's Intersection.recent_accepted_
# commands_by_source). `source` is an attacker-controlled string (see
# main.py's CommandRequest/TelemetryRequest: bounded to 64 characters,
# not to any particular set of values), so without a cap, an attacker who
# sends every request with a fresh, never-repeated source string grows
# either structure forever -- a real unbounded-memory DoS surface once
# this runs as a long-lived public deployment instead of a local demo
# restarted every session, distinct from and not covered by any of this
# project's deliberately-modeled attack classes (found reviewing the
# code before a public deploy, not from any live incident). Sized
# generously above how many real, legitimate sources this demo ever
# actually has open at once (itc-orchestrator, itc-camera-network, one
# simulated console attacker address, attacker.py's default source -- a
# handful), so real traffic is in no realistic danger of evicting itself.
MAX_TRACKED_SOURCES = 200


def touch_bounded_source(tracker: OrderedDict, source: str) -> None:
    """Marks `source` as just-used in `tracker` (an OrderedDict whose
    entry for `source` the caller has already inserted or updated),
    moving it to the most-recently-used end, then evicts the least-
    recently-used entry if `tracker` now holds more than
    MAX_TRACKED_SOURCES distinct keys.

    Shared by ThreatTracker.record_failure below and main.py's
    apply_command, the two places that track state per attacker-
    controlled source: a source in real, ongoing use is never the one
    evicted, since using it moves it to the safe end of the eviction
    queue every time; only a source that stopped being used a while ago
    -- exactly what a disposable, one-shot attacker identity looks like
    -- is ever actually dropped.
    """
    tracker.move_to_end(source)
    while len(tracker) > MAX_TRACKED_SOURCES:
        tracker.popitem(last=False)


def _sign(key: bytes, payload: str) -> str:
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_command(phase: str, timestamp: float) -> str:
    """Signature a legitimate orchestrator attaches to a phase command.
    The timestamp is folded into the signed payload, not just carried
    alongside it: an attacker who captures a valid (phase, signature)
    pair can't just attach a newer, forged timestamp to make it look
    fresh again, since that would no longer match the signature.
    """
    return _sign(COMMAND_SIGNING_KEY, f"{phase}:{timestamp}")


def verify_command_signature(phase: str, timestamp: Optional[float], signature: Optional[str]) -> bool:
    """Constant-time signature check, plus a freshness check. Using `==`
    for the signature comparison would leak timing information about
    how many leading bytes matched, letting an attacker recover a valid
    signature one byte at a time.

    The freshness check runs first and is what actually stops a replay:
    a captured signature that is still mathematically valid is still
    rejected once it is older than COMMAND_FRESHNESS_WINDOW_SECONDS.
    """
    if not signature or timestamp is None:
        return False
    if abs(time.time() - timestamp) > COMMAND_FRESHNESS_WINDOW_SECONDS:
        return False
    return hmac.compare_digest(signature, sign_command(phase, timestamp))


def sign_telemetry(
    intersection_id: str, approach: str, road_user_type: str, count: int, timestamp: float
) -> str:
    """Signature a legitimate camera node attaches to a detection event.
    Every field, including the timestamp, is folded into the signed
    payload so a captured signature can't be replayed against a
    different approach, intersection, road-user type, count, or time
    than the one it was actually issued for.
    """
    payload = f"{intersection_id}:{approach}:{road_user_type}:{count}:{timestamp}"
    return _sign(TELEMETRY_SIGNING_KEY, payload)


def verify_telemetry_signature(
    intersection_id: str,
    approach: str,
    road_user_type: str,
    count: int,
    timestamp: Optional[float],
    signature: Optional[str],
) -> bool:
    if not signature or timestamp is None:
        return False
    if abs(time.time() - timestamp) > TELEMETRY_FRESHNESS_WINDOW_SECONDS:
        return False
    expected = sign_telemetry(intersection_id, approach, road_user_type, count, timestamp)
    return hmac.compare_digest(signature, expected)


def is_plausible_telemetry(count: int) -> bool:
    """A real camera reports individual detections, not bulk counts.
    This catches the "claim 40 vehicles in one report" shape of a
    data-poisoning attack independent of whether the report is signed:
    a second, orthogonal check, not a replacement for authentication.
    """
    return 0 < count <= MAX_PLAUSIBLE_EVENT_COUNT


def is_rate_limited(recent_accepted_command_times, now: float) -> bool:
    """True once a junction has already had COMMAND_RATE_LIMIT_MAX
    commands accepted within COMMAND_RATE_LIMIT_WINDOW_SECONDS, meaning
    the next one should be throttled regardless of how validly it is
    signed. `recent_accepted_command_times` is a fixed-size deque
    (maxlen=COMMAND_RATE_LIMIT_MAX, see network.py's Intersection) of
    the timestamps of the most recent commands actually applied to that
    junction, oldest first: once it is full, its oldest entry tells you
    exactly how long ago the COMMAND_RATE_LIMIT_MAX-th-most-recent
    command landed.
    """
    if len(recent_accepted_command_times) < COMMAND_RATE_LIMIT_MAX:
        return False
    oldest_of_recent = recent_accepted_command_times[0]
    return (now - oldest_of_recent) < COMMAND_RATE_LIMIT_WINDOW_SECONDS


class ConflictMonitor:
    """Software stand-in for a hardware Malfunction Management Unit (MMU).

    Real traffic cabinets include a physical MMU wired between the
    controller and the signal lamps. Even if the controller software is
    fully compromised, the MMU independently vetoes any output that would
    show conflicting greens and forces the intersection into flashing red
    instead. It does not trust the command layer at all; that is what
    makes it a genuine second line of defense rather than another copy of
    the same check.

    Consulted after authentication, so even a validly-signed dangerous
    command would still be caught here: defense in depth, not a single
    point of failure.
    """

    def is_safe(self, requested_phase: str) -> bool:
        return requested_phase != DANGEROUS_OVERRIDE_PHASE


@dataclass
class ThreatTracker:
    """Tracks failed-authentication counts per source and blocks repeat
    offenders. A simplified stand-in for a real intrusion detection /
    prevention system (IDS/IPS), shared across the command and telemetry
    channels: a source misbehaving on either is worth blocking on both.

    A block expires on its own after BLOCK_DURATION_SECONDS, the same
    recover-automatically shape as an isolated intersection. Nothing
    else in this demo (no operator login, no per-source identity) could
    meaningfully "prove" a source safe again to justify a manual unblock
    action, so time is the only signal available, same as it would be
    for a real IDS/IPS's temporary ban.
    """

    # OrderedDict, not a plain dict, so touch_bounded_source (see its own
    # docstring above) can track and evict by least-recently-used order.
    failed_attempts: OrderedDict = field(default_factory=OrderedDict)
    # source -> epoch time its block expires. A dict rather than a set
    # so each source's block can expire independently. Not itself capped
    # by touch_bounded_source, unlike failed_attempts: every entry here
    # is swept out the moment it expires by blocked_sources below, which
    # scans the *entire* dict (not just one looked-up key) and runs on
    # essentially every network snapshot, roughly every 2 real seconds,
    # regardless of whether that specific source is ever seen again. So
    # this dict's size is already naturally bounded by (rate new blocks
    # are created) x BLOCK_DURATION_SECONDS, not by an unbounded backlog
    # of entries nobody ever revisits, which is exactly the gap
    # touch_bounded_source closes for failed_attempts (only cleaned up
    # lazily, when-and-if that same source is looked up again).
    _blocked_until: dict = field(default_factory=dict)

    def is_blocked(self, source: str) -> bool:
        expiry = self._blocked_until.get(source)
        if expiry is None:
            return False
        if time.time() >= expiry:
            del self._blocked_until[source]
            # A clean slate on expiry, not just an unblock: every other
            # recovery in this project (an isolated intersection, see
            # orchestrator.py's isolated_until handling) resets fully
            # rather than resuming with a head start toward the next
            # trip. Without this, failed_attempts[source] stays at
            # MAX_FAILED_ATTEMPTS forever, so a single subsequent
            # failure re-blocks the source immediately instead of
            # needing MAX_FAILED_ATTEMPTS new ones -- a real behavioral
            # inconsistency found by reading this class next to
            # orchestrator.py's, not by testing.
            self.failed_attempts.pop(source, None)
            return False
        return True

    def record_failure(self, source: str) -> bool:
        """Record a failed/unauthorized attempt from `source`.

        Returns True if this failure just caused the source to become
        newly blocked, so the caller can log/react to that transition
        exactly once instead of on every subsequent attempt.
        """
        self.failed_attempts[source] = self.failed_attempts.get(source, 0) + 1
        touch_bounded_source(self.failed_attempts, source)
        if self.failed_attempts[source] >= MAX_FAILED_ATTEMPTS and source not in self._blocked_until:
            self._blocked_until[source] = time.time() + BLOCK_DURATION_SECONDS
            return True
        return False

    @property
    def blocked_sources(self) -> set:
        """Sources currently blocked, for display (the security event
        feed, the dashboard's blocked_sources list). Expired entries are
        pruned as a side effect of checking, same as is_blocked does.
        """
        now = time.time()
        expired = [source for source, expiry in self._blocked_until.items() if now >= expiry]
        for source in expired:
            del self._blocked_until[source]
        return set(self._blocked_until.keys())

    def reset(self) -> None:
        self.failed_attempts.clear()
        self._blocked_until.clear()
