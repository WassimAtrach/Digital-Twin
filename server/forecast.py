"""
forecast.py

On-demand "what if" traffic forecasting: answers "if it were this hour
right now, what would this junction's traffic look like?" by fast-
forwarding a disposable copy of one junction through many simulated
detection ticks, using the exact same trained ML predictor and the
exact same phase-decision/serving logic that runs the live network
(see ml_predictor.py and orchestrator.py), just fed the chosen hour's
real-world traffic intensity (see tel_aviv_data.py's
HOURLY_TRAFFIC_MULTIPLIER) instead of the live network's current
setting.

Deliberately reuses orchestrator.py's `_decide_phase` and
`_serve_green_approaches` rather than reimplementing the control rule:
the whole point of "using ML to forecast" is that the answer comes from
genuinely the same model and control logic running the live network,
not a second, separately-tuned approximation of it that could quietly
drift out of sync with the real thing.

Reads network state (the shared ArrivalPredictor, a junction's real-
world calibration factor) but never writes it: every call here works
on its own disposable Intersection copy, so running a forecast has
zero effect on the live simulation, and can safely be called as often
as the dashboard likes.

The result includes the full per-tick trajectory (`ticks`), not just
where the junction ends up: the Live Network Monitor's ML Forecast
animation steps a junction's car-simulation canvas through it, so a
forecast is something you watch play out, not just a number. It runs a
silent WARM_UP_TICKS period first, not included in `ticks`: every
forecast starts its disposable junction from a genuinely empty, ALL_RED
slate (see forecast_congestion's own comment for why), so without a
warm-up the recorded/played-back window would start with empty roads
that only gradually fill in -- correct given where the simulation
starts, but not what "the traffic of this hour" is supposed to look
like from frame one.
"""

from __future__ import annotations

from statistics import mean
from typing import Optional

import tel_aviv_data
from network import APPROACHES, MAX_ORGANIC_QUEUE_PER_APPROACH, Intersection
from orchestrator import _decide_phase, _serve_green_approaches

# How many simulated detection ticks to actually record and hand back
# for playback. At 2 simulated seconds per tick (matching detection.py's
# real DETECTION_TICK_SECONDS), 30 ticks is 1 simulated minute.
#
# Was 90 (3 simulated minutes). Requested down to a firm ~20-second total
# watch time -- but phases legitimately flip every 3 ticks minimum under
# heavy demand (MIN_GREEN_SECONDS / SIMULATED_TICK_SECONDS, see
# orchestrator.py), which is exactly what made 90 ticks unable to hit 20
# seconds without each tick's own playback time dropping low enough to
# reintroduce the flickering-lights bug fixed twice already this project
# (see monitor.js's FORECAST_TICK_PLAYBACK_MS comment for the two prior,
# too-fast failures). Shortening the number of ticks played back, rather
# than compressing each one further, is what keeps both properties true
# at once: a firm ~20s total, and every phase still on screen long enough
# to actually read. The warm-up period below (which this doesn't touch)
# already means even a shorter recorded window starts from a realistic,
# already-busy state, not an empty one still ramping up.
FORECAST_TICKS = 30
SIMULATED_TICK_SECONDS = 2.0

# Run this many ticks first, silently (not recorded into `ticks`, not
# counted in avg_congestion_over_forecast or the throughput figure),
# before recording anything. A junction starts every forecast from a
# genuinely empty, ALL_RED slate (see below for why), which means the
# FIRST several real seconds of the recorded playback would otherwise
# show empty roads and only the signal heads changing -- correct given
# where the simulation actually starts, but not what "the traffic of
# this hour" is supposed to look like, and exactly what got reported as
# "all that happens is lights switching" when the recorded window
# started mid-ramp-up. Warming up first means the recorded 90 ticks
# start from a state the queues would actually be in a couple of
# minutes into that hour, not from a cold start every single time.
WARM_UP_TICKS = 40


def forecast_congestion(network, intersection_id: str, hour: int) -> Optional[dict]:
    """Fast-forwards a disposable copy of one junction through
    FORECAST_TICKS simulated ticks at `hour`'s real-world traffic
    intensity, and returns the resulting state. Returns None if
    intersection_id does not name a real junction.
    """
    source = network.intersections.get(intersection_id)
    if source is None:
        return None

    hourly_multiplier = tel_aviv_data.hourly_traffic_multiplier(hour)
    volume_factor = source.real_world_volume_factor

    # A disposable copy, never added to network.intersections and never
    # broadcast anywhere: this is the whole reason running a forecast
    # cannot affect the live simulation. Starts from a genuinely clean
    # slate (ALL_RED, zero queues, matching what
    # network.reset_intersection() calls clean) rather than the live
    # junction's current, possibly mid-incident state, so the forecast
    # answers "what does this hour typically look like here," not
    # "what happens next given whatever is happening right now."
    sim = Intersection(
        id=source.id,
        name=source.name,
        x=source.x,
        y=source.y,
        real_world_volume_factor=volume_factor,
    )
    sim.phase = "ALL_RED"
    sim.phase_since = 0.0  # simulated time starts at 0, not wall-clock time

    congestion_samples = []
    served_total = 0.0
    # One entry per simulated tick, queues + phase right after that
    # tick's arrivals/serving: what the dashboard's ML Forecast
    # animation steps through to actually drive a junction's car-sim
    # canvas through the forecast, tick by tick, instead of only
    # reporting where it ends up. Small (a handful of floats and a
    # phase string per tick), so sending all of them is trivial.
    ticks = []

    total_ticks = WARM_UP_TICKS + FORECAST_TICKS
    for tick in range(total_ticks):
        now = tick * SIMULATED_TICK_SECONDS
        recording = tick >= WARM_UP_TICKS

        # Same predict-then-apply order detection.py uses live: the
        # forecast for this tick comes from history available up to the
        # previous tick, then that history rolls forward once this
        # tick's predicted arrival is known.
        for approach in APPROACHES:
            predicted = network.arrival_predictor.predict(
                list(sim.recent_arrivals[approach]), hourly_multiplier, volume_factor
            )
            updated = sim.queues[approach] + predicted
            sim.queues[approach] = min(updated, MAX_ORGANIC_QUEUE_PER_APPROACH)
            sim.recent_arrivals[approach].append(predicted)

        desired_phase = _decide_phase(sim, now)
        if desired_phase != sim.phase:
            sim.phase = desired_phase
            sim.phase_since = now

        served = _serve_green_approaches(sim)

        if not recording:
            continue

        served_total += sum(served.values())

        tick_congestion = sim.congestion_index()
        congestion_samples.append(tick_congestion)
        ticks.append(
            {
                "phase": sim.phase,
                "queues": {approach: round(value, 1) for approach, value in sim.queues.items()},
                "congestion_index": tick_congestion,
            }
        )

    final_predicted_arrivals = {
        approach: round(
            network.arrival_predictor.predict(list(sim.recent_arrivals[approach]), hourly_multiplier, volume_factor),
            2,
        )
        for approach in APPROACHES
    }

    forecast_seconds = FORECAST_TICKS * SIMULATED_TICK_SECONDS
    return {
        "hour": hour,
        "congestion_index": sim.congestion_index(),
        "avg_congestion_over_forecast": round(mean(congestion_samples), 1),
        "predicted_arrivals": final_predicted_arrivals,
        "queues": {approach: round(value, 1) for approach, value in sim.queues.items()},
        "forecast_throughput_per_hour": round(served_total * (3600.0 / forecast_seconds)),
        "ticks": ticks,
    }
