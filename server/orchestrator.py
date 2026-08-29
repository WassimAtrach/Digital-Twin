"""
orchestrator.py

The "AI" congestion-responsive signal controller: the orchestration
behavior ITC's VisionInsight/VisionFlow products are described as
providing: read live conditions, predict what's coming, decide signal
timing, apply it.

The decision rule compares queue length across the two phase groups and
switches when one side is clearly worse off, with a minimum green time
so it doesn't flap, same as before, but "queue length" here means
current backlog plus a genuine trained model's forecast of near-term
arrivals (see ml_predictor.py), not just the current snapshot. That
model keeps learning online from the live simulated traffic the whole
time the server runs; this is a real, live computation over the
detection layer's data (not a canned animation), and is exactly the
kind of logic a data-poisoning attack (see attacker.py's
spoof-congestion) is aimed at corrupting, now on two fronts: the
instant queue estimate, and what the model has learned to expect.

The minimum-green rule also has an exception grounded in real actuated-
signal-control practice: "gap-out" early termination, which cuts a
green phase short (down to a safety floor, never below it) when
detection shows nothing is actually arriving on that side and the other
side has real waiting demand, instead of holding a fixed minimum
regardless of what's happening. See _decide_phase's gap-out branch.

Every legitimate decision is applied through `apply_command_fn`, the
same signed-command path an attacker has to forge (see main.py).
"""

from __future__ import annotations

import asyncio
import logging
import random
import time

from detection import ARRIVAL_PROBABILITY
from network import APPROACHES, MAX_ORGANIC_QUEUE_PER_APPROACH, MAX_QUEUE_PER_APPROACH
from security import sign_command

logger = logging.getLogger(__name__)

ORCHESTRATOR_TICK_SECONDS = 2.0
MIN_GREEN_SECONDS = 6.0
# One side's score must exceed the other's by this much to switch, once
# past MIN_GREEN_SECONDS (gap-out, above, is the only thing that can
# still switch a phase before then). 1.5 was never revisited as the
# rest of the simulation's queue scale got tuned down through this
# project's work (SERVICE_RATE_PER_TICK, ARRIVAL_PROBABILITY, per-
# junction calibration factors): observed queues at ordinary, non-
# attack traffic mostly sit in the 0-3 range, so a real, sustained,
# one-sided imbalance of a single vehicle (e.g. one side idle at 0
# while the other has 1 car waiting) never cleared a 1.5 margin, and a
# junction could sit on one phase indefinitely even with clear waiting
# demand on the other side -- not attack-caused, just a stale constant.
# 0.75 still filters pure sub-vehicle noise from the ML predictor's
# fractional forecast contribution (typically ~0.1-0.4 combined), while
# reliably catching a genuine, whole-vehicle imbalance. MIN_GREEN_
# SECONDS already caps how often a switch can happen at all, so a
# lower margin doesn't introduce flapping, only makes a real, sustained
# imbalance switch instead of stalling.
SWITCH_MARGIN = 0.75

# Gap-out: a real actuated-signal-control technique (see _decide_phase's
# gap-out branch for the citation and full reasoning). GAP_OUT_MIN_
# GREEN_SECONDS is an absolute floor even a genuine gap can't cut below
# (a light that can turn green for under 2 seconds is a safety problem,
# not an efficiency win); GAP_OUT_QUEUE_THRESHOLD is how small a score
# has to be to count as "nothing waiting" rather than a real queue.
GAP_OUT_MIN_GREEN_SECONDS = 2.0
GAP_OUT_QUEUE_THRESHOLD = 0.5
# Vehicles a green approach clears per tick. Each approach is only green
# roughly half the time (NS and EW alternate), so this needs enough
# headroom over the arrival rate (detection.py's ARRIVAL_PROBABILITY)
# that the *averaged* service rate still clears demand: otherwise the
# network is oversaturated by construction and queues grow even with no
# attack running, which muddies the demo (nothing should look "under
# attack" until something actually attacks it).
#
# Was 1.5, which only ever had real headroom against roughly the
# 1.0-1.2x band of tel_aviv_data.py's HOURLY_TRAFFIC_MULTIPLIER, not the
# full 24-hour curve's actual range up to 3.0x (17:00, the real evening
# peak) -- reported live and reproduced from a clean reset with zero
# attacks running: hour 16 (only 1.9x, not even the peak) climbed
# multiple junctions to 100% within 30 real seconds and stayed there,
# purely from organic traffic. The math behind why: at 1.5, average
# service rate per approach is only ~0.375 vehicles/sec (1.5 x 0.5
# green-time fraction / ORCHESTRATOR_TICK_SECONDS), which real arrival
# rate already matches or exceeds above roughly a 2x multiplier -- and
# because congestion_index() reads the single worst approach, not an
# average, ordinary random variance in normal traffic is enough to tip
# one approach into that regime well before the network-wide average
# would suggest trouble, exactly what a live 15-second-interval sample
# confirmed (100% network congestion by t=30s, sustained through t=90s).
# 4.0 targets real headroom even at the genuine worst case (17:00's 3.0x
# multiplier, on Kaplan-Begin's 1.3x real-world calibration factor,
# where arrival probability is already clamped to 1.0 -- guaranteed
# demand every tick): that works out to needing at least ~1.0 vehicles/
# sec of average service capacity per approach to keep real headroom,
# which requires SERVICE_RATE_PER_TICK >= 4.0. Verified live afterward
# across the actual hours that matter (a normal hour, 16:00, and 17:00,
# the real peak), not just by this arithmetic alone.
SERVICE_RATE_PER_TICK = 4.0

# How long a granted emergency preemption holds its phase, and how often
# a fresh preemption can be granted at all; bounding both limits the
# damage a single spoofed (or real) preemption claim can do.
PREEMPTION_WINDOW_SECONDS = 8.0

# How long an intersection stays isolated (ignored by the orchestrator,
# held at a safe default) after its attacker gets auto-blocked.
ISOLATION_SECONDS = 25.0

# How long /api/playbook's restore_all holds a junction at ALL_RED
# before the AI resumes picking phases, guaranteeing "turn everything
# red" is actually visible instead of leaving it to chance whether the
# next orchestrator tick happens to land soon after the click or nearly
# a full ORCHESTRATOR_TICK_SECONDS later. Short on purpose: this is a
# visual confirmation beat, not a safety measure the way ISOLATION_
# SECONDS is, so it doesn't need to be long, just long enough (several
# real seconds) to register as "something happened" before the real,
# gradual congestion-draining recovery takes over.
RECOVERY_HOLD_SECONDS = 3.0


def _decide_phase(intersection, now: float) -> str:
    """Pure decision logic, kept separate from the apply/broadcast side
    effects below so the control rule can be read (and reasoned about)
    on its own.
    """
    if (
        intersection.last_preemption is not None
        and now - intersection.last_preemption < PREEMPTION_WINDOW_SECONDS
    ):
        return intersection.preemption_phase

    ns_queue = intersection.queues["N"] + intersection.queues["S"]
    ew_queue = intersection.queues["E"] + intersection.queues["W"]

    # Anticipated near-term load: current backlog plus what
    # ml_predictor.ArrivalPredictor expects to arrive in roughly the
    # next tick (see detection.py, which refreshes this every tick from
    # each approach's recent real history). This is what makes the
    # decision below anticipatory instead of purely reactive: a side
    # that is about to get busy can start being favored before it is
    # visibly backed up, not only after.
    ns_score = ns_queue + intersection.predicted_arrivals["N"] + intersection.predicted_arrivals["S"]
    ew_score = ew_queue + intersection.predicted_arrivals["E"] + intersection.predicted_arrivals["W"]

    if intersection.phase not in ("NS_GREEN", "EW_GREEN"):
        # Recovering from ALL_RED/CONFLICT (a fresh start, or coming back
        # from a fail-safe/isolation): pick fresh based on current demand
        # rather than falling into the switch-comparison branches below,
        # which only handle alternating between the two green phases.
        return "NS_GREEN" if ns_score >= ew_score else "EW_GREEN"

    if now - intersection.phase_since < MIN_GREEN_SECONDS:
        # Gap-out: real actuated traffic signals don't just hold a fixed
        # minimum green regardless of what's actually happening. They
        # run "vehicle extension" logic, green is extended only as long
        # as vehicles keep arriving, and terminate the phase early once
        # detection shows a genuine gap in arrivals, freeing that time
        # for a side that actually has demand instead of serving an
        # empty street on principle. Modeled here with the same current-
        # queue-plus-ML-forecast score already used for the ordinary
        # switch decision below: if the green side's score is
        # negligible AND the red side actually has waiting demand, cut
        # the phase short (never below GAP_OUT_MIN_GREEN_SECONDS, a
        # safety floor, not an efficiency knob).
        if now - intersection.phase_since >= GAP_OUT_MIN_GREEN_SECONDS:
            green_score = ns_score if intersection.phase == "NS_GREEN" else ew_score
            waiting_score = ew_score if intersection.phase == "NS_GREEN" else ns_score
            if green_score < GAP_OUT_QUEUE_THRESHOLD and waiting_score >= GAP_OUT_QUEUE_THRESHOLD:
                return "EW_GREEN" if intersection.phase == "NS_GREEN" else "NS_GREEN"
        return intersection.phase

    if intersection.phase == "NS_GREEN" and ew_score > ns_score + SWITCH_MARGIN:
        return "EW_GREEN"
    if intersection.phase == "EW_GREEN" and ns_score > ew_score + SWITCH_MARGIN:
        return "NS_GREEN"
    return intersection.phase


def _serve_green_approaches(intersection) -> dict:
    """Simulates vehicles clearing the intersection on their green,
    shrinking those approaches' queues. Returns {approach: amount
    served} rather than recording it anywhere itself, so this same
    queue-draining logic can be shared safely between the live
    orchestrator loop below (which does want to record it, into the
    real network's throughput measurement) and forecast.py's
    disposable what-if simulations (which must not: they run on a
    throwaway copy of one junction and must never touch live network
    state).
    """
    if intersection.phase == "NS_GREEN":
        green_approaches = ("N", "S")
    elif intersection.phase == "EW_GREEN":
        green_approaches = ("E", "W")
    else:
        green_approaches = ()

    served = {}
    for approach in green_approaches:
        before = intersection.queues[approach]
        amount = min(before, SERVICE_RATE_PER_TICK)
        intersection.queues[approach] = before - amount
        served[approach] = amount
    return served


def _accumulate_ground_truth_arrivals(network, intersection) -> None:
    """Real vehicles keep physically arriving at a junction whether or
    not its telemetry channel is currently trusted. Isolation (see
    main.py's apply_telemetry) blocks what the SYSTEM is TOLD about a
    junction, not the physical world the telemetry channel is supposed
    to be reporting on -- a real quarantined sensor doesn't cause real
    traffic to stop existing, it just means the operator is flying
    blind on that approach until it's cleared.

    Applied directly to queues, bypassing apply_telemetry's signed/
    plausibility pipeline entirely, on purpose: this models ground
    truth, not a reported message, so (a) an attacker can't manipulate
    it the size or shape of a real spoof-congestion report the way
    telemetry can, and (b) it isn't blocked by isolation the way
    telemetry now correctly is either -- those are two different, both
    intentional, properties.

    Reuses detection.py's own ARRIVAL_PROBABILITY (at the same 2-second
    tick cadence: ORCHESTRATOR_TICK_SECONDS == DETECTION_TICK_SECONDS)
    so an isolated junction's congestion grows at roughly the same real
    rate a Fail-Safe'd-but-not-isolated junction's already does from
    ordinary organic telemetry, instead of silently holding flat while
    isolated specifically. Before this, isolating a junction correctly
    stopped an attacker from adding MORE forged congestion, but also
    made the dashboard's number stop moving entirely, which read as
    "the congestion index doesn't go up... it needs to go up because
    traffic stops [being served]" -- an accurate description of a real
    modeling gap between "no one is being served" (true) and "no more
    cars exist" (what a frozen number implied).
    """
    effective_probability = min(
        1.0,
        ARRIVAL_PROBABILITY * network.arrival_multiplier * intersection.real_world_volume_factor,
    )
    for approach in APPROACHES:
        if random.random() <= effective_probability:
            updated = intersection.queues[approach] + 1.0
            # MAX_ORGANIC_QUEUE_PER_APPROACH, not MAX_QUEUE_PER_APPROACH:
            # this function only ever models real, non-attack traffic
            # (see its own docstring), so it gets the same lower organic
            # ceiling main.py's apply_telemetry applies to the real
            # camera network's own reports -- see network.py's constant
            # for the full reasoning.
            intersection.queues[approach] = min(updated, MAX_ORGANIC_QUEUE_PER_APPROACH)


async def _process_intersection(network, intersection, now: float, apply_command_fn) -> None:
    """One junction's worth of orchestrator_loop's per-tick work,
    pulled out into its own function so orchestrator_loop can wrap a
    single call in try/except (see its own comment for why) instead of
    a large reindent of this logic.
    """
    if intersection.isolated_until is not None:
        if now < intersection.isolated_until:
            # Still isolated: no signal decision this tick, but
            # real traffic doesn't stop existing just because
            # the sensor feed is untrusted -- see
            # _accumulate_ground_truth_arrivals's own docstring.
            _accumulate_ground_truth_arrivals(network, intersection)
            return
        # Cooldown just expired: recover and fall through to a
        # normal decision below, starting from a clean ALL_RED.
        intersection.isolated_until = None
        intersection.alarm = None
        intersection.phase = "ALL_RED"
        intersection.phase_since = now
        network.log_security(
            "good",
            intersection.id,
            "recovered",
            f"{intersection.name} recovered from isolation: resuming normal AI-orchestrated control",
        )

    if intersection.alarm in ("COLLISION_RISK", "FAILSAFE"):
        # Both need a human decision, not the AI quietly
        # resuming control: COLLISION_RISK is an unresolved
        # legacy-mode attack (same as a real conflict-monitor
        # trip). FAILSAFE covers two different real situations
        # that happen to share one flag -- an auto-isolated
        # junction (isolated_until also set, already held by the
        # check above, so reaching here means the isolation
        # cooldown just ended and recovery already ran this same
        # tick) and an operator's manual Fail-Safe Flash
        # (isolated_until never set for that one at all, only
        # alarm). Before this check existed, a manual Fail-Safe
        # Flash was silently overwritten by the very next
        # orchestrator tick: _decide_phase() sees ALL_RED, which
        # isn't NS_GREEN/EW_GREEN, and picks a fresh green phase
        # for it exactly as if the junction had just been reset,
        # clearing the alarm and undoing the operator's action
        # within ~2 seconds -- confirmed live (phase/alarm
        # checked immediately after the click, then 3 seconds
        # later) before this fix, not assumed. A held FAILSAFE
        # still recovers exactly once its actual cause clears:
        # either the isolation cooldown expires and the block
        # above runs, or an operator clicks Restore, which
        # resets alarm to None and hands control back.
        return

    if intersection.recovery_hold_until is not None:
        if now < intersection.recovery_hold_until:
            # Guaranteed ALL_RED window after restore_all (see
            # RECOVERY_HOLD_SECONDS): alarm/isolation are
            # already cleared by the time this runs, so without
            # this check _decide_phase would treat ALL_RED as
            # "fresh start, pick a phase now" on whichever tick
            # happens to land next -- anywhere from ~0 to
            # ORCHESTRATOR_TICK_SECONDS after the click, purely
            # by chance, making "turn everything red" sometimes
            # barely visible. Real congestion still keeps
            # accumulating normally here (queues are untouched
            # by restore_all on purpose), this only holds the
            # PHASE decision, not traffic itself.
            return
        intersection.recovery_hold_until = None

    desired_phase = _decide_phase(intersection, now)
    if desired_phase != intersection.phase:
        signature = sign_command(desired_phase, now)
        await apply_command_fn(
            intersection_id=intersection.id,
            phase=desired_phase,
            timestamp=now,
            signature=signature,
            source="itc-orchestrator",
            broadcast_result=False,
        )

    served = _serve_green_approaches(intersection)
    for amount in served.values():
        network.record_served(amount)


async def orchestrator_loop(network, apply_command_fn, broadcast_fn) -> None:
    while True:
        await asyncio.sleep(ORCHESTRATOR_TICK_SECONDS)
        now = time.time()

        for intersection in network.intersections.values():
            try:
                await _process_intersection(network, intersection, now, apply_command_fn)
            except Exception:
                # A bare `while True` loop with no guard around its body
                # dies permanently the instant anything inside it raises:
                # asyncio just logs "Task exception was never retrieved"
                # and the task quietly ends, no crash, no restart, the
                # rest of the server (the API, the WebSocket, the
                # dashboard) keeps responding completely normally while
                # the AI silently stops making any decisions at all,
                # forever, with nothing surfacing that anything is wrong
                # -- found reviewing this file end to end before a public
                # deploy, not from a specific known bug in the body
                # below, but a public, always-on deployment (unlike a
                # local demo restarted every session) can't rely on
                # never hitting an edge case this hasn't already been
                # tested against. One junction's unexpected failure is
                # logged and skipped for this tick; every other
                # junction, and every future tick, keeps running.
                logger.exception(
                    "orchestrator_loop: unexpected error processing %s, skipping this tick for it",
                    intersection.id,
                )

        network.sample_congestion(now)
        await broadcast_fn()
