"""
detection.py

Simulates the camera/sensor layer: the part of a real AI-retrofit
deployment that watches an intersection's approaches and reports what it
sees. Real detection would be computer vision over camera feeds; this
generates statistically plausible arrival events instead, so the rest of
the system (the AI orchestrator, the dashboard, the attacks) has
something real to react to rather than canned numbers.

Every legitimate event this module produces is submitted through
`apply_telemetry_fn`: the exact same signed-telemetry code path an
attacker has to forge (see main.py). The only difference between this
background task and attacker.py's spoof commands is whether the message
is actually signed with the real key.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time

from security import sign_telemetry

logger = logging.getLogger(__name__)

DETECTION_TICK_SECONDS = 2.0
# Chance of a new detection, per approach, per tick. Sized so that total
# network demand sits comfortably below the orchestrator's service
# capacity (see orchestrator.py's SERVICE_RATE_PER_TICK): each approach
# only gets served roughly half the time (it alternates with the cross
# street), so arrival rate has to clear a real margin under half the
# service rate or every queue grows without bound regardless of attacks.
ARRIVAL_PROBABILITY = 0.35

# Road-user mix a real intersection camera would plausibly see. Weights
# don't need to sum to exactly 1.0; _pick_road_user_type treats them as
# relative and falls back to "car" if none is hit due to rounding.
ROAD_USER_WEIGHTS = (
    ("car", 0.80),
    ("bus", 0.06),
    ("cyclist", 0.08),
    ("pedestrian", 0.05),
    ("emergency", 0.01),
)

# The legitimate camera network's identity on the telemetry channel,
# distinct from any attacker source string, so the security event feed
# and dashboard can tell real traffic from an attack at a glance.
CAMERA_NETWORK_SOURCE = "traffic-control-camera-network"


def _pick_road_user_type() -> str:
    roll = random.random()
    cumulative = 0.0
    for name, weight in ROAD_USER_WEIGHTS:
        cumulative += weight
        if roll <= cumulative:
            return name
    return "car"


async def _process_intersection_detection(network, intersection, apply_telemetry_fn) -> bool:
    """One junction's worth of detection_loop's per-tick work, pulled
    out into its own function so detection_loop can wrap a single call
    in try/except (see its own comment for why) instead of a large
    reindent of this logic. Returns whether any event was generated for
    this junction this tick.
    """
    # The Time of Day control (see /api/hour and tel_aviv_data.py's
    # HOURLY_TRAFFIC_MULTIPLIER) scales the base arrival
    # probability, and so does this junction's own real-world
    # calibration factor (see
    # tel_aviv_data.py): Kaplan-Begin and Namir-Einstein, both
    # genuinely busy real intersections, organically run hotter
    # than the other three. Clamped to 1.0 because a single roll
    # per approach per tick can only ever produce at most one
    # arrival; without the platoon boost below, demand would top
    # out at "guaranteed arrival every tick" and could never
    # actually exceed the orchestrator's service capacity, only
    # approach it.
    effective_probability = min(
        1.0,
        ARRIVAL_PROBABILITY * network.arrival_multiplier * intersection.real_world_volume_factor,
    )

    any_event = False
    for approach in ("N", "S", "E", "W"):
        # Predict before this tick's outcome is generated, from
        # only the history available up to the previous tick, so
        # the forecast orchestrator.py reads is genuinely
        # forward-looking rather than peeking at what is about
        # to happen this same tick.
        intersection.predicted_arrivals[approach] = network.arrival_predictor.predict(
            list(intersection.recent_arrivals[approach]),
            network.arrival_multiplier,
            intersection.real_world_volume_factor,
        )

        if random.random() <= effective_probability:
            road_user_type = _pick_road_user_type()
            # At heavy load, cars realistically arrive in platoons
            # (released together by an upstream signal) rather than
            # strictly one at a time. This is what lets rush-hour
            # demand genuinely exceed service capacity instead of
            # only ever approaching it.
            count = 1
            if road_user_type == "car" and network.arrival_multiplier > 1.5 and random.random() < 0.5:
                count = 2
            timestamp = time.time()
            signature = sign_telemetry(intersection.id, approach, road_user_type, count, timestamp)
            await apply_telemetry_fn(
                intersection_id=intersection.id,
                approach=approach,
                road_user_type=road_user_type,
                count=count,
                timestamp=timestamp,
                signature=signature,
                source=CAMERA_NETWORK_SOURCE,
                broadcast_result=False,
            )
            any_event = True

        # Harvest this tick's actual outcome, whatever apply_
        # telemetry_fn accepted into pending_tick_arrivals this
        # tick (0.0 if nothing arrived; see that field's
        # docstring in network.py for why this also picks up any
        # attacker telemetry that landed in the same window),
        # train the predictor on it, then roll it into the
        # history window ready for next tick's prediction.
        actual = intersection.pending_tick_arrivals[approach]
        network.arrival_predictor.partial_fit(
            list(intersection.recent_arrivals[approach]),
            network.arrival_multiplier,
            intersection.real_world_volume_factor,
            actual,
        )
        intersection.recent_arrivals[approach].append(actual)
        intersection.pending_tick_arrivals[approach] = 0.0

    return any_event


async def detection_loop(network, apply_telemetry_fn, broadcast_fn) -> None:
    """Runs forever, generating arrival events for every approach of
    every intersection. Individual events are applied without
    broadcasting (`broadcast=False`) so a tick's worth of small updates
    doesn't flood the dashboard with a WebSocket message per vehicle;
    one broadcast covers the whole tick.
    """
    while True:
        await asyncio.sleep(DETECTION_TICK_SECONDS)

        any_event = False
        for intersection in network.intersections.values():
            try:
                if await _process_intersection_detection(network, intersection, apply_telemetry_fn):
                    any_event = True
            except Exception:
                # See orchestrator_loop's identical guard for the full
                # reasoning: an unguarded `while True` loop dies
                # permanently and silently the instant anything inside
                # it raises, leaving the rest of the server (API,
                # WebSocket, dashboard) responding completely normally
                # while the camera simulation has actually stopped
                # forever, with no crash and no visible signal anything
                # is wrong. One junction's unexpected failure is logged
                # and skipped for this tick; every other junction, and
                # every future tick, keeps running.
                logger.exception(
                    "detection_loop: unexpected error processing %s, skipping this tick for it",
                    intersection.id,
                )

        if any_event:
            await broadcast_fn()
