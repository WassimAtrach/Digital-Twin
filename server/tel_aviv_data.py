"""
tel_aviv_data.py

Real-world grounding for the five intersections the digital twin models.
Every fact in REAL_WORLD_CONTEXT below is a genuine, checkable, cited
detail found by researching the actual streets, not an invented
statistic dressed up to look researched. Two of the five have a real
published daily-vehicle-count; the other three do not appear to have
one publicly available, and are labeled as qualitative rather than
having a number invented for them, on purpose. Overclaiming precision
here would undermine the same "genuinely correct, not just simulated"
standard the rest of this project holds itself to.

Sources (fetched and read directly, not taken from a search snippet):
  * Kaplan Interchange (Kaplan Street x Begin Road): "the intersection
    averages more than 100,000 vehicles passing through each day"
    before its 2003 upgrade, and 150,000 daily afterward, per
    Wikipedia's Kaplan Interchange article, citing Israeli Ministry of
    Transport figures. https://en.wikipedia.org/wiki/Kaplan_Interchange
  * Einstein-Namir: a real intersection ITC (Intelligent Traffic
    Control, the company this whole project is modeled on) actually
    manages. ITC's own head of product told ynet: "one intersection
    ITC manages in particular is Einstein-Namir where tens of
    thousands of vehicles pass through every day," and that ITC's
    technology overall "manages more than 100,000 cars on the road
    daily" across its Tel Aviv deployments.
    https://www.ynetnews.com/environment/article/sjvw2tsjt

This module's only real job is to turn those facts into a small,
honest calibration: which of the five modeled junctions should
organically run busier than the others in the simulation, so the
digital twin's relative traffic pattern echoes the real corridor
instead of treating all five as identical. It intentionally does not
try to reproduce exact real vehicle counts (the simulation's absolute
scale is set elsewhere, by ORCHESTRATOR_TICK_SECONDS/SERVICE_RATE_PER_TICK/
ARRIVAL_PROBABILITY, tuned for a readable live demo); this only sets
each junction's volume RELATIVE to the others.

Also here: HOURLY_TRAFFIC_MULTIPLIER, a 24-hour urban traffic curve
backing the dashboard's Time of Day control. See that constant's own
docstring for an important distinction from REAL_WORLD_CONTEXT above:
the per-junction facts are specific, cited numbers; the hourly curve
follows a well-documented general shape but its exact values are not
a measured Tel Aviv statistic, and are labeled that way.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RealWorldContext:
    """One intersection's real-world grounding: a short, honest summary
    a viewer can independently verify, its source, and the calibration
    factor derived from it.
    """

    summary: str
    source: str
    # Multiplies this junction's individual arrival probability in
    # detection.py, on top of the network-wide Light/Normal/Rush Hour
    # setting. Kept in a modest 1.0-1.3 band: the point is relative
    # differentiation between the five junctions, not a rescaling of
    # the whole simulation's tuned demand/capacity balance.
    relative_volume_factor: float


REAL_WORLD_CONTEXT: dict = {
    "kaplan_begin": RealWorldContext(
        summary=(
            "Kaplan Interchange (Kaplan St x Begin Rd) is one of Tel Aviv's "
            "busiest junctions: Israeli Ministry of Transport figures put it "
            "at roughly 150,000 vehicles a day since its 2003 upgrade, up "
            "from about 100,000 before."
        ),
        source="https://en.wikipedia.org/wiki/Kaplan_Interchange",
        relative_volume_factor=1.3,
    ),
    "namir_einstein": RealWorldContext(
        summary=(
            "Einstein-Namir is a real intersection ITC (the company this "
            "project is modeled on) actually manages, carrying, in ITC's "
            "own words, \"tens of thousands of vehicles\" every day."
        ),
        source="https://www.ynetnews.com/environment/article/sjvw2tsjt",
        relative_volume_factor=1.15,
    ),
    # No independently-published daily-vehicle-count turned up for these
    # three during research, only their well-documented reputation as
    # busy central Tel Aviv corridors. Given a real number for two of
    # the five junctions and none for the rest, a modest, clearly
    # qualitative factor is the honest choice here, not a guessed one
    # dressed up as researched.
    "ibn_gabirol_arlozorov": RealWorldContext(
        summary=(
            "Ibn Gabirol x Arlozorov sits in one of Tel Aviv's densest "
            "commercial and transit corridors (Arlozorov is also a major "
            "light-rail and rail interchange point), though no independently "
            "published daily-vehicle-count for this specific junction turned "
            "up during research."
        ),
        source="https://en.wikipedia.org/wiki/Ibn_Gabirol_Street",
        relative_volume_factor=1.05,
    ),
    "begin_hashalom": RealWorldContext(
        summary=(
            "Begin Road x HaShalom sits by the HaShalom Interchange and "
            "Azrieli area, a well-known Tel Aviv landmark cluster, though "
            "no independently published daily-vehicle-count for this "
            "specific junction turned up during research."
        ),
        source="https://en.wikipedia.org/wiki/Begin_Road",
        relative_volume_factor=1.1,
    ),
    "rokach_yehudit": RealWorldContext(
        summary=(
            "Rokach Boulevard is a real, major arterial road along north "
            "Tel Aviv, though it is the least-documented pairing in this "
            "corridor: no independently published daily-vehicle-count for "
            "this specific junction turned up during research, so it is "
            "treated as this corridor's baseline rather than scaled up."
        ),
        source="https://www.wikidata.org/wiki/Q12411547",
        relative_volume_factor=1.0,
    ),
}


def relative_volume_factor(intersection_id: str) -> float:
    """Looks up one junction's calibration factor, defaulting to 1.0
    (no adjustment) for any id this module doesn't have grounding data
    for, so a future added junction degrades gracefully instead of
    raising.
    """
    context = REAL_WORLD_CONTEXT.get(intersection_id)
    return context.relative_volume_factor if context else 1.0


# A standard urban weekday commute pattern (hour of day 0-23 ->
# relative traffic-volume multiplier), on the same 0.5-3.0 scale the
# old fixed Light/Normal/Rush Hour control already used, and already
# tuned against: 0.5 was Light, 1.0 Normal, 3.0 Rush Hour.
#
# Different from REAL_WORLD_CONTEXT above in an important way, worth
# being explicit about: those are specific, cited numbers for specific
# real streets. This is not that. No source found during research gave
# an exact hour-by-hour percentage breakdown for Tel Aviv or anywhere
# else (searched FHWA's congestion report and industry traffic-planning
# sources; both describe the shape, not a numeric table). What those
# sources DID establish, consistently, is the general shape every
# source agreed on: a low overnight trough, a morning peak around
# 07:00-09:00, a midday dip with a small lunch bump, and a larger,
# longer evening peak around 16:00-18:00, matching the classic bimodal
# urban commute pattern. The specific numbers below follow that
# well-documented shape; they are a reasonable modeling choice, not a
# measured Tel Aviv statistic, and are labeled that way here rather
# than presented with false precision.
#
# Sources for the shape (not the exact numbers):
#   https://ops.fhwa.dot.gov/congestion_report_04/chapter3.htm
#   https://www.urbansdk.com/resources/traffic-volume-by-time-of-day-peak-hour-patterns-planning-insights
HOURLY_TRAFFIC_MULTIPLIER = (
    0.15,  # 00:00
    0.12,  # 01:00
    0.10,  # 02:00
    0.10,  # 03:00
    0.12,  # 04:00
    0.20,  # 05:00
    0.45,  # 06:00
    1.40,  # 07:00
    2.90,  # 08:00 morning peak
    2.20,  # 09:00
    1.30,  # 10:00
    1.10,  # 11:00
    1.20,  # 12:00 midday lunch bump
    1.15,  # 13:00
    1.05,  # 14:00
    1.20,  # 15:00
    1.90,  # 16:00
    3.00,  # 17:00 evening peak
    2.70,  # 18:00
    1.80,  # 19:00
    1.20,  # 20:00
    0.80,  # 21:00
    0.50,  # 22:00
    0.25,  # 23:00
)


def hourly_traffic_multiplier(hour: int) -> float:
    """Looks up the relative traffic-volume multiplier for one hour of
    the day (0-23). Out-of-range hours clamp to the nearest valid one
    rather than raising, since this is fed user-chosen input (the
    dashboard's Time of Day control) that Pydantic already bounds, but
    defending here too costs nothing and avoids a crash if this
    function is ever called from somewhere that does not.
    """
    clamped_hour = max(0, min(23, hour))
    return HOURLY_TRAFFIC_MULTIPLIER[clamped_hour]
