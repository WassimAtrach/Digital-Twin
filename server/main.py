"""
main.py

FastAPI application for the ITC digital-twin demo.

Serves:
  * a WebSocket (`/ws`) that pushes live network state to the dashboard,
  * the command channel (`/api/command`): phase decisions, from the AI
    orchestrator or an attacker,
  * the telemetry channel (`/api/telemetry`): detection events, from
    the simulated camera network or an attacker,
  * mode/reset controls and a full-state snapshot endpoint,
  * the static dashboard files under `web/`.

Run from inside this `server/` directory with:
    ../.venv/Scripts/python.exe -m uvicorn main:app --reload
(see the project README for full setup)
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from detection import ARRIVAL_PROBABILITY, detection_loop
from forecast import forecast_congestion
from network import APPROACHES, MAX_QUEUE_PER_APPROACH, VALID_PHASES, network
from orchestrator import ISOLATION_SECONDS, RECOVERY_HOLD_SECONDS, orchestrator_loop
from security import (
    COMMAND_RATE_LIMIT_MAX,
    COMMAND_RATE_LIMIT_WINDOW_SECONDS,
    ConflictMonitor,
    is_plausible_telemetry,
    is_rate_limited,
    verify_command_signature,
    verify_telemetry_signature,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("itc-digital-twin")

conflict_monitor = ConflictMonitor()


# Request models
#
# Pydantic validates these before any of our own code runs: wrong types
# or missing required fields are rejected with an automatic 422, and the
# max_length/ge/le bounds stop an attacker from sending pathological
# payloads. This closes off a whole class of malformed-input bugs for
# free, on top of the application-level checks below.

class CommandRequest(BaseModel):
    intersection_id: str = Field(..., max_length=64)
    phase: str = Field(..., max_length=64)
    # When present alongside a signature, this is the timestamp that was
    # folded into it (see security.py's sign_command); required for a
    # signature to verify at all now, since verify_command_signature
    # checks it was issued recently, not just that it was ever valid.
    # Optional here (not required) so the unsigned attacks (Command
    # Injection, and any legacy-mode traffic) don't need to send one:
    # verify_command_signature already rejects a missing signature
    # before it would even look at this field.
    timestamp: Optional[float] = Field(default=None)
    signature: Optional[str] = Field(default=None, max_length=128)
    # Logical source identifier. In a real deployment this would be
    # derived from the network connection itself (an mTLS client cert,
    # or the source IP on a private control VLAN) rather than trusted
    # from the request body: it's a body field here only so this local
    # demo can *display* a believable attacker identity without needing
    # real network segmentation to prove the point.
    source: str = Field(default="unknown", max_length=64)


class TelemetryRequest(BaseModel):
    intersection_id: str = Field(..., max_length=64)
    approach: str = Field(..., max_length=8)
    road_user_type: str = Field(default="car", max_length=32)
    count: int = Field(default=1, ge=1, le=100_000)
    timestamp: Optional[float] = Field(default=None)
    signature: Optional[str] = Field(default=None, max_length=128)
    source: str = Field(default="unknown", max_length=64)


class ModeRequest(BaseModel):
    mode: str  # "legacy" | "secure"


class ResetRequest(BaseModel):
    intersection_id: Optional[str] = Field(default=None, max_length=64)


class PlaybookRequest(BaseModel):
    # Optional: "restore_all" is network-wide and names no single
    # junction, the same shape ResetRequest already uses for a
    # whole-network reset.
    intersection_id: Optional[str] = Field(default=None, max_length=64)
    action: str  # "failsafe_flash" | "isolate_node" | "restore" | "restore_all"


class HourRequest(BaseModel):
    hour: int = Field(..., ge=0, le=23)


class ForecastRequest(BaseModel):
    intersection_id: str = Field(..., max_length=64)
    hour: int = Field(..., ge=0, le=23)


# WebSocket broadcast

async def broadcast() -> None:
    payload = {"type": "update", "network": network.snapshot()}
    dead_connections = []
    for ws in network.connections:
        try:
            await ws.send_json(payload)
        except Exception:
            # The client disconnected between our loop starting and this
            # send; not an error worth logging, just clean it up below.
            dead_connections.append(ws)
    for ws in dead_connections:
        network.connections.remove(ws)


# Shared application logic
#
# Both the public HTTP endpoints AND the legitimate background tasks
# (detection.py's camera simulation, orchestrator.py's AI control loop)
# call these same two functions. There is no separate "trusted internal"
# code path: a legitimate call simply carries a valid signature, and an
# attacker's does not. That symmetry is the point of the demo.

def _isolate(intersection, reason: str) -> None:
    intersection.isolated_until = time.time() + ISOLATION_SECONDS
    intersection.phase = "ALL_RED"
    intersection.alarm = "FAILSAFE"
    intersection.phase_since = time.time()


async def apply_command(
    intersection_id: str,
    phase: str,
    timestamp: Optional[float],
    signature: Optional[str],
    source: str,
    broadcast_result: bool = True,
) -> dict:
    """Submit a phase command to one intersection's field controller.

    Behavior depends entirely on `network.mode`, which is the whole
    point of the demo:

      * "legacy": no authentication at all. Anyone who can reach this
        endpoint can request any phase, including the dangerous
        maintenance override. Models a real, historically-documented
        weakness in traffic-control hardware (unauthenticated command
        channels).

      * "secure": every command must carry a valid HMAC signature that
        only the legitimate orchestrator can produce. Unsigned or
        incorrectly-signed commands are rejected and the source is
        tracked; repeat offenders are auto-blocked and their target
        intersection is isolated. Even a validly-signed dangerous
        override would still be vetoed by the independent conflict
        monitor afterwards: defense in depth, not a single point of
        failure.
    """
    network.record_request("command")
    intersection = network.intersections.get(intersection_id)
    if intersection is None:
        return {"ok": False, "reason": "unknown intersection"}

    # A real, previously-missing check: isolated_until used to only ever
    # be SET (here and in orchestrator.py's own isolation-expiry
    # handling), never CHECKED against incoming requests. That meant
    # "Isolate Node" stopped the legitimate AI orchestrator from
    # fighting over the channel (orchestrator_loop already skips an
    # isolated junction) but did nothing to actually block an attacker
    # from continuing to hit /api/command directly -- despite the
    # button's own tooltip promising exactly that ("cuts this junction
    # off from incoming commands and telemetry"). Confirmed live before
    # this fix: isolate a junction, then attack it again immediately --
    # the attack still landed every time. Checked before the source-
    # block check below on purpose: while a junction is isolated, NO
    # command should reach it, regardless of who sent it or whether
    # that source happens to also be blocked network-wide.
    if intersection.is_isolated():
        network.log_security(
            "serious",
            intersection_id,
            "rejected_isolated",
            f"Command from '{source}' at {intersection.name} rejected: junction is isolated and cannot accept commands",
        )
        if broadcast_result:
            await broadcast()
        return {"ok": False, "reason": "isolated"}

    if network.threats.is_blocked(source):
        network.log_security(
            "serious",
            intersection_id,
            "blocked_source",
            f"Rejected command from already-blocked source '{source}' at {intersection.name} (requested: {phase})",
        )
        if broadcast_result:
            await broadcast()
        return {"ok": False, "reason": "source blocked"}

    if network.mode == "secure" and not verify_command_signature(phase, timestamp, signature):
        just_blocked = network.threats.record_failure(source)
        network.log_security(
            "warning",
            intersection_id,
            "unauthorized_command",
            f"Unauthorized command from '{source}' at {intersection.name}: '{phase}' rejected, invalid or missing signature",
        )
        if just_blocked:
            _isolate(intersection, reason="repeated unauthorized commands")
            network.log_security(
                "serious",
                intersection_id,
                "source_blocked",
                f"Source '{source}' auto-blocked after repeated unauthorized attempts. {intersection.name} isolated for {int(ISOLATION_SECONDS)}s",
            )
        if broadcast_result:
            await broadcast()
        return {"ok": False, "reason": "unauthorized"}

    if not conflict_monitor.is_safe(phase):
        if network.mode == "legacy":
            # No independent safety layer in the legacy baseline: the
            # dangerous command is applied directly. This is the
            # "before" moment of the demo: the intersection is now
            # genuinely unsafe.
            intersection.phase = "CONFLICT"
            intersection.alarm = "COLLISION_RISK"
            intersection.phase_since = time.time()
            network.log_security(
                "critical",
                intersection_id,
                "collision_risk",
                f"MAINTENANCE OVERRIDE accepted from '{source}' at {intersection.name}, forcing ALL GREEN. No authentication, no independent safety interlock.",
            )
        else:
            # Defense in depth: veto the dangerous request and force a
            # safe state, independent of the (already-verified) signature.
            intersection.phase = "ALL_RED"
            intersection.alarm = "FAILSAFE"
            intersection.phase_since = time.time()
            network.log_security(
                "warning",
                intersection_id,
                "conflict_vetoed",
                f"Conflict Monitor vetoed FORCE_ALL_GREEN from '{source}' at {intersection.name}, fail-safe engaged",
            )
        if broadcast_result:
            await broadcast()
        return {"ok": True, "phase": intersection.phase, "alarm": intersection.alarm}

    if phase not in VALID_PHASES:
        if broadcast_result:
            await broadcast()
        return {"ok": False, "reason": "unknown phase"}

    # Rate limiting: a genuinely separate defense from the freshness
    # window above, in Secure mode only (Legacy has no command
    # authentication to layer this on top of; it would just be an
    # inconsistent partial protection there). Closes a real gap: a
    # captured signature replayed rapidly, each replay still inside its
    # freshness window and therefore still verifying, never fails a
    # single check, so ThreatTracker (which only counts FAILURES) would
    # never trip on its own. This does not require the request to be
    # invalid to throttle it, only anomalously frequent, which a real
    # orchestrator's own MIN_GREEN_SECONDS pacing already rules out.
    #
    # Scoped per (junction, source), not per junction alone: an earlier
    # version shared one budget across every source, so a flooding
    # attacker could also exhaust the real AI orchestrator's own budget
    # for that junction, a self-inflicted collateral denial of service.
    # Found by testing this exact scenario, not by inspection.
    source_command_times = intersection.recent_accepted_commands_by_source.setdefault(
        source, deque(maxlen=COMMAND_RATE_LIMIT_MAX)
    )
    if network.mode == "secure" and is_rate_limited(source_command_times, time.time()):
        just_blocked = network.threats.record_failure(source)
        network.log_security(
            "warning",
            intersection_id,
            "rate_limited",
            f"Command from '{source}' at {intersection.name} throttled: {COMMAND_RATE_LIMIT_MAX} commands already accepted in the last {int(COMMAND_RATE_LIMIT_WINDOW_SECONDS)}s (possible rapid replay)",
        )
        if just_blocked:
            _isolate(intersection, reason="rate limit exceeded")
            network.log_security(
                "serious",
                intersection_id,
                "source_blocked",
                f"Source '{source}' auto-blocked after repeated unauthorized attempts. {intersection.name} isolated for {int(ISOLATION_SECONDS)}s",
            )
        if broadcast_result:
            await broadcast()
        return {"ok": False, "reason": "rate limited"}

    source_command_times.append(time.time())
    intersection.phase = phase
    intersection.alarm = None
    intersection.phase_since = time.time()
    if broadcast_result:
        await broadcast()
    return {"ok": True, "phase": phase}


async def apply_telemetry(
    intersection_id: str,
    approach: str,
    road_user_type: str,
    count: int,
    timestamp: Optional[float],
    signature: Optional[str],
    source: str,
    broadcast_result: bool = True,
) -> dict:
    """Submit a detection event to one intersection's telemetry pipeline.

    Same shape of behavior as apply_command, but this is the input side
    of the AI orchestrator rather than the output side: in "legacy" mode
    any claimed count from any source is trusted outright and folded
    straight into the queue estimate the orchestrator times signals
    against, a data-poisoning attack surface, not just a command-
    injection one. "secure" mode requires a valid signature AND a
    plausible count (see security.is_plausible_telemetry).
    """
    network.record_request("telemetry")
    intersection = network.intersections.get(intersection_id)
    if intersection is None or approach not in APPROACHES:
        return {"ok": False, "reason": "unknown intersection or approach"}

    # See apply_command's identical check for the full story: isolation
    # used to only stop the AI orchestrator, never actually block
    # incoming traffic. Blocks organic (legitimate) telemetry here too,
    # not just attacker telemetry, on purpose: a real quarantined sensor
    # channel isn't selectively trusted for "the real-looking reports,"
    # every report from it is untrusted until an operator clears the
    # isolation, which is also exactly what the tooltip already claims
    # this button does.
    if intersection.is_isolated():
        network.log_security(
            "serious",
            intersection_id,
            "rejected_isolated",
            f"Telemetry from '{source}' at {intersection.name} rejected: junction is isolated and cannot accept telemetry",
        )
        if broadcast_result:
            await broadcast()
        return {"ok": False, "reason": "isolated"}

    if network.threats.is_blocked(source):
        network.log_security(
            "serious",
            intersection_id,
            "blocked_source",
            f"Rejected telemetry from already-blocked source '{source}' at {intersection.name}",
        )
        if broadcast_result:
            await broadcast()
        return {"ok": False, "reason": "source blocked"}

    if network.mode == "secure":
        if not verify_telemetry_signature(intersection_id, approach, road_user_type, count, timestamp, signature):
            just_blocked = network.threats.record_failure(source)
            network.log_security(
                "warning",
                intersection_id,
                "unauthorized_telemetry",
                f"Unauthorized telemetry from '{source}' at {intersection.name} rejected, invalid or missing signature",
            )
            if just_blocked:
                _isolate(intersection, reason="repeated unauthorized telemetry")
                network.log_security(
                    "serious",
                    intersection_id,
                    "source_blocked",
                    f"Source '{source}' auto-blocked after repeated unauthorized attempts. {intersection.name} isolated for {int(ISOLATION_SECONDS)}s",
                )
            if broadcast_result:
                await broadcast()
            return {"ok": False, "reason": "unauthorized"}

        if not is_plausible_telemetry(count):
            network.log_security(
                "warning",
                intersection_id,
                "implausible_telemetry",
                f"Implausible telemetry from '{source}' at {intersection.name} rejected: a single sensor report claimed {count} vehicles",
            )
            if broadcast_result:
                await broadcast()
            return {"ok": False, "reason": "implausible"}

    if road_user_type == "emergency":
        intersection.last_preemption = time.time()
        intersection.preemption_phase = "NS_GREEN" if approach in ("N", "S") else "EW_GREEN"
        if network.mode == "secure":
            network.log_security(
                "good",
                intersection_id,
                "preemption_granted",
                f"Emergency-vehicle preemption granted at {intersection.name} ({approach}), authenticated request",
            )
        else:
            # Reachable here in legacy mode even for a fully forged
            # claim: exactly the vulnerability spoof-emergency
            # demonstrates. Legacy mode cannot tell a real ambulance
            # from an attacker asking for the same priority.
            network.log_security(
                "warning",
                intersection_id,
                "preemption_granted",
                f"Emergency-vehicle preemption granted at {intersection.name} ({approach}), legacy mode, request was NOT authenticated",
                technique="T0856 - Spoof Reporting Message",
            )
    else:
        # Capped, not just added: a spoof-congestion report (or several
        # stacked) would otherwise leave a fake backlog that takes many
        # minutes of real service time to drain. Still a clear, visible
        # spike below the cap, just not an effectively-permanent one.
        updated = intersection.queues.get(approach, 0.0) + count
        intersection.queues[approach] = min(updated, MAX_QUEUE_PER_APPROACH)
        # Uncapped, unlike the queue above: this feeds the ML arrival
        # predictor's training data (see detection.py's harvest step and
        # ml_predictor.py), which should learn the true claimed demand,
        # not an artifact of the display cap. It accumulates every
        # accepted count this tick, legitimate detections and any
        # attacker telemetry alike, through this same shared code path;
        # see network.py's pending_tick_arrivals docstring for why that
        # is a deliberate security detail.
        intersection.pending_tick_arrivals[approach] = intersection.pending_tick_arrivals.get(approach, 0.0) + count

    if broadcast_result:
        await broadcast()
    return {"ok": True}


# Background tasks + app lifespan

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Starts the simulated camera network and the AI orchestrator
    alongside the app, and cancels them on shutdown. The lifespan context
    manager (rather than the deprecated `@app.on_event`) avoids
    deprecation-warning noise in the console during a live demo.

    Also warms up the shared ML arrival predictor here, before either
    background task starts: see ml_predictor.py's warm_up() docstring
    for why (sane starting weights instead of predicting zero for
    everything until real traffic accumulates).
    """
    network.arrival_predictor.warm_up(ARRIVAL_PROBABILITY)
    detection_task = asyncio.create_task(detection_loop(network, apply_telemetry, broadcast))
    orchestrator_task = asyncio.create_task(orchestrator_loop(network, apply_command, broadcast))
    yield
    detection_task.cancel()
    orchestrator_task.cancel()


app = FastAPI(title="ITC Digital Twin - Attack & Defense Demo", lifespan=lifespan)


@app.middleware("http")
async def no_cache_static_files(request, call_next):
    """Forces every response to revalidate with the server instead of
    silently being served from the browser's own cache.

    StaticFiles ships ETag/Last-Modified but no Cache-Control header at
    all, which leaves the browser free to apply its own heuristic
    freshness window and skip even asking the server whether a file
    changed. During a live demo, this project's web/*.js and web/*.html
    get edited and the server restarted constantly; a plain refresh
    (not a hard refresh) repeatedly kept showing behavior from before
    the latest fix, misread several times over as the fix itself being
    wrong or reverted, when the actual code being served (verified
    directly against this same server) was correct the whole time.
    `no-cache` (not `no-store`) still allows a fast 304 when nothing
    actually changed -- this forces the revalidation round-trip to
    happen at all, not that every load re-downloads full content.
    """
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response


# WebSocket endpoint

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    network.connections.append(websocket)
    await websocket.send_json({"type": "snapshot", "network": network.snapshot()})
    try:
        while True:
            # The browser never sends anything on this socket; this just
            # blocks until the connection closes, so we can detect it.
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in network.connections:
            network.connections.remove(websocket)


# REST API

@app.get("/api/network")
async def get_network():
    """Full network snapshot: used for the dashboard's initial page
    load, before its WebSocket connection is established.
    """
    return network.snapshot()


@app.post("/api/command")
async def submit_command(req: CommandRequest):
    return await apply_command(
        req.intersection_id, req.phase, req.timestamp, req.signature, req.source or "unknown"
    )


@app.post("/api/telemetry")
async def submit_telemetry(req: TelemetryRequest):
    return await apply_telemetry(
        req.intersection_id,
        req.approach,
        req.road_user_type,
        req.count,
        req.timestamp,
        req.signature,
        req.source or "unknown",
    )


@app.post("/api/mode")
async def set_mode(req: ModeRequest):
    """Switch between the legacy retrofit baseline and ITC Secure
    Integration. Also resets every intersection to a known-good state,
    so each half of the demo starts from the same clean slate.
    """
    if req.mode not in ("legacy", "secure"):
        return {"ok": False, "reason": "mode must be 'legacy' or 'secure'"}
    network.reset_all(mode=req.mode)
    label = "ITC SECURE INTEGRATION" if req.mode == "secure" else "LEGACY RETROFIT (unauthenticated)"
    network.log_ops(f"Deployment configuration switched to {label}")
    await broadcast()
    return {"ok": True, "mode": network.mode}


@app.post("/api/reset")
async def reset(req: ResetRequest):
    """Manual operator recovery. With an intersection_id, resets just
    that one (e.g. clearing a legacy-mode collision that needs a human
    to acknowledge); without one, resets the whole network.
    """
    if req.intersection_id:
        ok = network.reset_intersection(req.intersection_id)
        if not ok:
            return {"ok": False, "reason": "unknown intersection"}
        intersection = network.intersections[req.intersection_id]
        network.log_ops(f"Operator reset {intersection.name}, resuming normal automatic operation")
    else:
        network.reset_all()
        network.log_ops("Operator reset the whole network, resuming normal automatic operation")
    await broadcast()
    return {"ok": True}


@app.post("/api/playbook")
async def run_playbook(req: PlaybookRequest):
    """Incident-response playbook actions: the manual counterparts to
    what the security layer does automatically, for an operator watching
    the dashboard who doesn't want to wait out an automatic threshold or
    a fixed cooldown:

      * failsafe_flash: immediately force flashing-red fail-safe,
        regardless of current state. The manual equivalent of what the
        conflict monitor does automatically in secure mode, useful in
        legacy mode, where nothing stops a collision-risk state on its
        own.
      * isolate_node: immediately cut the intersection off from the
        AI orchestrator for the standard cooldown, without waiting for
        the automatic 3-strike threshold. A manual kill switch for a
        node under suspicion.
      * restore: clear any alarm/isolation AND zero queued traffic,
        handing control back to the AI orchestrator immediately with a
        genuinely clean slate. Correct for one junction's Restore
        button: the whole point there is discarding whatever fabricated
        data an attack (typically Sensor Spoofing) already got accepted
        into that junction's queues, and a forged number isn't real
        traffic that deserves to be served out gradually.
      * restore_all: network-wide (no intersection_id), and
        deliberately NOT the same "zero everything instantly" recovery
        restore uses. Clears alarm/isolation and forces ALL_RED on
        every junction immediately, but leaves queues untouched,
        handing every junction back to the AI orchestrator to drain
        them the same way it always does: real service, at
        orchestrator.py's real SERVICE_RATE_PER_TICK, alternating
        NS/EW every MIN_GREEN_SECONDS. Deliberate: after a Coordinated
        attack across 5 junctions, an instant network-wide zero-out
        read as an unrealistic "poof, fixed" snap; this instead
        answers "attack contained, now watch the AI actually clear it"
        over roughly the real time that takes, the same physics that
        governs every other queue in this simulation, not a scripted
        countdown.

    Logged into the security event feed (not the ops log) so the
    dashboard's incident timeline shows the full story: attack, then
    response, in one place.
    """
    if req.action == "restore_all":
        now = time.time()
        for intersection in network.intersections.values():
            intersection.phase = "ALL_RED"
            intersection.alarm = None
            intersection.isolated_until = None
            # Guarantees the ALL_RED state above is actually visible for
            # a real few seconds (see orchestrator.py's
            # RECOVERY_HOLD_SECONDS) instead of leaving how long it
            # lasts to chance based on when the next orchestrator tick
            # happens to land.
            intersection.recovery_hold_until = now + RECOVERY_HOLD_SECONDS
            intersection.phase_since = now
        network.log_security(
            "good",
            None,
            "operator_restore_all",
            "Operator initiated network-wide recovery: every junction handed back to AI-orchestrated "
            "control; queued traffic drains through normal service, not zeroed instantly",
        )
        await broadcast()
        return {"ok": True}

    intersection = network.intersections.get(req.intersection_id)
    if intersection is None:
        return {"ok": False, "reason": "unknown intersection"}

    if req.action == "failsafe_flash":
        intersection.phase = "ALL_RED"
        intersection.alarm = "FAILSAFE"
        intersection.phase_since = time.time()
        network.log_security(
            "good",
            req.intersection_id,
            "operator_failsafe",
            f"Operator forced {intersection.name} into fail-safe flashing red",
        )
    elif req.action == "isolate_node":
        _isolate(intersection, reason="operator-initiated")
        network.log_security(
            "good",
            req.intersection_id,
            "operator_isolate",
            f"Operator manually isolated {intersection.name} for {int(ISOLATION_SECONDS)}s",
        )
    elif req.action == "restore":
        network.reset_intersection(req.intersection_id)
        network.log_security(
            "good",
            req.intersection_id,
            "operator_restore",
            f"Operator restored {intersection.name} to normal AI-orchestrated control",
        )
    else:
        return {"ok": False, "reason": "unknown action"}

    await broadcast()
    return {"ok": True}


@app.post("/api/hour")
async def set_hour(req: HourRequest):
    """Time of day control: sets which hour (0-23) the simulation
    currently models, scaling detection.py's arrival probability by
    tel_aviv_data.py's HOURLY_TRAFFIC_MULTIPLIER for that hour. This
    replaced the old three-level Light/Normal/Rush Hour control with a
    strict superset of it (any of the 24 hours, backed by a real,
    documented urban traffic curve, rather than three fixed presets),
    so the dashboard can show the network handling anything from a
    3 AM lull to an 8 AM or 5 PM peak, independently of any attack.
    """
    network.set_simulated_hour(req.hour)
    network.log_ops(f"Time of day set to {req.hour:02d}:00")
    await broadcast()
    return {"ok": True, "hour": req.hour, "arrival_multiplier": network.arrival_multiplier}


@app.post("/api/forecast")
async def forecast(req: ForecastRequest):
    """ML-driven what-if forecast: "if it were this hour right now,
    what would this junction's traffic look like?" Answered by fast-
    forwarding a disposable copy of the junction through the same
    trained ArrivalPredictor and the same phase-decision/serving logic
    the live orchestrator uses (see forecast.py), so the answer comes
    from genuinely the same model and control rule running the live
    network, not a separate formula invented for this endpoint. Reads
    network state but never writes it: the live simulation is
    completely unaffected by running a forecast.
    """
    result = forecast_congestion(network, req.intersection_id, req.hour)
    if result is None:
        return {"ok": False, "reason": "unknown intersection"}
    return {"ok": True, **result}


# Static dashboard files
#
# Mounted last so it doesn't shadow the /api/* and /ws routes above:
# StaticFiles would otherwise happily 404 on those paths itself.

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="dashboard")
