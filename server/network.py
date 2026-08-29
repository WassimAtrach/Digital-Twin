"""
network.py

The digital twin's domain model: a small network of simulated
intersections (a "corridor" of five junctions with real Tel Aviv street
names; the pairings and topology are illustrative, not real ITC
deployment data, but two of the five carry a genuine, cited real-world
traffic-volume grounding, see tel_aviv_data.py), the security
bookkeeping shared across the network, and the KPI math shown on the
dashboard.

There is deliberately no database: state resets on server restart,
which is fine (convenient, even) for a demo that gets run repeatedly.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from zoneinfo import ZoneInfo

import ml_predictor
import tel_aviv_data
from security import ThreatTracker

APPROACHES = ("N", "S", "E", "W")
VALID_PHASES = {"NS_GREEN", "EW_GREEN", "ALL_RED"}

# Hard ceiling on any one approach's queue estimate, and (see
# Intersection.congestion_index()) directly the "100% congested"
# reference point too: a busiest-approach queue at this cap reads as
# exactly 100%. Without a cap at all, a spoof-congestion attack (or
# several, stacked) would leave a fake backlog that can take many
# minutes of real service time to drain: clearly disruptive, but the
# demo reads as "broken" rather than "attacked" once nobody remembers
# where the number came from. A real detection pipeline would have some
# physical/framing limit on what one camera can even report, too; this
# stands in for that.
#
# Small enough that a genuinely gridlocked approach (this cap, hit
# organically during sustained Rush Hour on top of an active attack, or
# just very heavy real demand) drains back under 100% within a
# reasonable number of real seconds once the load is removed, at
# SERVICE_RATE_PER_TICK (see orchestrator.py) per real tick, rather than
# staying visibly pinned at 100% for a long time after "Restore" or a
# switch back to lighter traffic. A cap many times larger (30 was tried
# once) turned recovery into a minute-plus of the number looking
# completely frozen.
MAX_QUEUE_PER_APPROACH = 8.0

# A second, LOWER ceiling that applies only to organic traffic (the real
# camera network's own reports, and orchestrator.py's ground-truth
# arrivals while a junction is isolated -- both model real, non-attack
# traffic) -- requested directly, so that a junction actually reaching
# 100% (MAX_QUEUE_PER_APPROACH above) becomes a reliable signal that
# something other than ordinary traffic caused it, not something heavy
# organic rush-hour demand could also produce on its own now that
# SERVICE_RATE_PER_TICK has real headroom even at the busiest hour (see
# orchestrator.py's comment on that constant). An attack's own telemetry
# is not capped by this at all, still able to reach the full
# MAX_QUEUE_PER_APPROACH: see main.py's apply_telemetry, which applies
# this ceiling only when a report's source is genuinely
# detection.py's CAMERA_NETWORK_SOURCE. This can't be gamed by an
# attacker claiming that same source string instead of their own,
# since doing so only gets them the LOWER ceiling, never the higher
# one -- and in Secure mode it's moot regardless, since only the real
# camera network can produce a validly-signed report with that source
# at all. 7.0 (87.5% of MAX_QUEUE_PER_APPROACH) sits in the middle of
# the requested "80-90% at worst" range.
MAX_ORGANIC_QUEUE_PER_APPROACH = 7.0

# Hard ceiling on Intersection.pending_tick_arrivals -- the ML predictor's
# training TARGET for one tick, applied at the point of accumulation in
# main.py's apply_telemetry, separate from (and much larger than)
# MAX_QUEUE_PER_APPROACH above. This field was deliberately left fully
# uncapped for a real reason (see its own field docstring: it should
# learn the true claimed demand, not an artifact of the display cap),
# but "uncapped" turned out to mean exactly that: a single Legacy-mode
# telemetry report at the maximum count Pydantic allows (100,000, see
# main.py's TelemetryRequest) fed directly into
# ml_predictor.ArrivalPredictor.partial_fit as the actual-outcome target,
# and because that model is SHARED across every junction and approach,
# one such report corrupted predicted_arrivals for all five junctions at
# once, confirmed live: every junction's predicted arrivals jumped into
# the thousands after a single request, not just the attacked one, and
# large enough single updates can drive weights to float overflow (inf/
# nan) with no way back short of a server restart, since nan poisons
# every arithmetic operation it touches from then on. Ordinary gradient
# descent has no built-in resistance to one extreme outlier; nothing
# about learning_rate or WEIGHT_DECAY (see ml_predictor.py) bounds a
# single update's size, only how fast repeated ones accumulate.
#
# This cap keeps the original intent intact -- the model still learns
# "this was reported as an extreme, anomalous spike," clearly
# distinguishable from real traffic (which essentially never exceeds a
# couple of vehicles in one tick, even a platooned rush-hour one, see
# detection.py's ARRIVAL_PROBABILITY and platoon logic) -- without
# feeding gradient descent a value four to five orders of magnitude
# larger than anything its learning rate was ever tuned against.
MAX_TRAINING_ARRIVAL_COUNT = 50.0

SECURITY_EVENT_HISTORY_LIMIT = 200
OPS_LOG_HISTORY_LIMIT = 100
CONGESTION_HISTORY_LIMIT = 60
SERVED_LOG_WINDOW_SECONDS = 120.0
REQUEST_LOG_WINDOW_SECONDS = 60.0

# MITRE ATT&CK for ICS technique references, cited on the security events
# they apply to. Verified against attack.mitre.org, not guessed:
#   https://attack.mitre.org/techniques/T0855/  Unauthorized Command Message
#   https://attack.mitre.org/techniques/T0856/  Spoof Reporting Message
#   https://attack.mitre.org/techniques/T0814/  Denial of Service
ATTACK_TECHNIQUE_BY_EVENT_TYPE = {
    "collision_risk": "T0855 - Unauthorized Command Message",
    "unauthorized_command": "T0855 - Unauthorized Command Message",
    "conflict_vetoed": "T0855 - Unauthorized Command Message",
    "unauthorized_telemetry": "T0856 - Spoof Reporting Message",
    "implausible_telemetry": "T0856 - Spoof Reporting Message",
    "source_blocked": "T0814 - Denial of Service",
    "rate_limited": "T0831 - Manipulation of Control",
}


@dataclass
class Intersection:
    """One simulated signalized junction."""

    id: str
    name: str
    x: float  # topology-map position, 0-100 normalized
    y: float

    phase: str = "NS_GREEN"
    alarm: Optional[str] = None  # None | "COLLISION_RISK" | "FAILSAFE"
    phase_since: float = field(default_factory=time.time)

    queues: dict = field(default_factory=lambda: {a: 0.0 for a in APPROACHES})

    # None when not isolated; otherwise the epoch time isolation ends.
    # Set when this intersection's attacker gets auto-blocked, so the
    # orchestrator leaves it alone (safe, static) for a cooldown instead
    # of continuing to negotiate with a channel under active attack.
    isolated_until: Optional[float] = None

    # None normally; set briefly by /api/playbook's restore_all (see
    # main.py and orchestrator.py's RECOVERY_HOLD_SECONDS) so a
    # network-wide recovery has a guaranteed, visible ALL_RED moment
    # before the AI starts picking phases again, instead of leaving how
    # long that lasts to chance -- without this, whether the very next
    # orchestrator tick happened to land 50ms or 1900ms after the click
    # (ORCHESTRATOR_TICK_SECONDS is on its own clock, not synchronized
    # to when an operator clicks anything) decided whether "turn
    # everything red" was clearly visible or barely there at all.
    recovery_hold_until: Optional[float] = None

    # Emergency-vehicle preemption state: when a plausible/authenticated
    # emergency telemetry event was last accepted, and which phase it
    # requested. Preemption is honored for a short window (see
    # orchestrator.py) so a single legitimate pass-through can't be
    # replayed into a standing green.
    last_preemption: Optional[float] = None
    preemption_phase: Optional[str] = None

    # This junction's calibration factor from tel_aviv_data.py: how much
    # busier (or not) real research suggests it should run relative to
    # the other four, applied in detection.py on top of the network-wide
    # Light/Normal/Rush Hour setting.
    real_world_volume_factor: float = 1.0

    # Rolling per-approach arrival-count history feeding
    # ml_predictor.ArrivalPredictor: one entry per detection tick
    # (server/detection.py), including ticks where nothing arrived (0.0),
    # so the window reflects the true recent pattern rather than only
    # the ticks that happened to have an event.
    recent_arrivals: dict = field(
        default_factory=lambda: {
            approach: deque([0.0] * ml_predictor.HISTORY_WINDOW, maxlen=ml_predictor.HISTORY_WINDOW)
            for approach in APPROACHES
        }
    )
    # Accumulates this tick's accepted telemetry counts per approach
    # before detection.py harvests them into recent_arrivals at the end
    # of the tick. Incremented in main.py's apply_telemetry for every
    # accepted event, legitimate or forged, the same "no special
    # trusted path" telemetry the queue estimate itself trusts: see
    # ml_predictor.py's module docstring for why that is a deliberate
    # security detail, not an oversight.
    pending_tick_arrivals: dict = field(default_factory=lambda: {a: 0.0 for a in APPROACHES})
    # The predictor's most recent forecast per approach, made from data
    # available before this tick's actual outcome, so it is genuinely
    # forward-looking. orchestrator.py reads this when deciding phases.
    predicted_arrivals: dict = field(default_factory=lambda: {a: 0.0 for a in APPROACHES})

    # Timestamps of the most recent commands actually applied to this
    # junction, per source (oldest first within each), feeding
    # security.py's is_rate_limited: a genuinely separate defense from
    # security.py's freshness window, since it catches a rapid-fire
    # resend where every individual request is still fresh enough to
    # pass on its own. Keyed by source, not shared across all of them: an
    # earlier version tracked one shared deque per junction regardless
    # of who sent what, which meant a flooding attacker could also
    # exhaust the real AI orchestrator's own budget for that junction, a
    # self-inflicted collateral denial of service that defeated the
    # point, caught by testing this against real orchestrator traffic
    # immediately after a simulated flood, not by inspection.
    #
    # OrderedDict, not a plain dict: `source` is attacker-controlled and
    # only bounded to 64 characters (see main.py's CommandRequest), not
    # to any particular set of values, so without eviction an attacker
    # sending a fresh, never-repeated source on every request grows this
    # forever, one orphaned entry per request, for as long as the server
    # runs -- a real unbounded-memory DoS surface on a public deployment,
    # found reviewing the code before one, not from a live incident. See
    # security.py's touch_bounded_source, which main.py's apply_command
    # calls on every insert/update here to evict the least-recently-used
    # source once this holds more than MAX_TRACKED_SOURCES distinct ones.
    recent_accepted_commands_by_source: OrderedDict = field(default_factory=OrderedDict)

    def is_isolated(self) -> bool:
        return self.isolated_until is not None and time.time() < self.isolated_until

    def health(self) -> str:
        """One of "good" | "warning" | "serious" | "critical". Drives
        the status badge on the dashboard. Mirrors the dataviz status
        scale: reserved meaning, always shown with an icon + label, never
        color alone.
        """
        if self.alarm == "COLLISION_RISK":
            return "critical"
        if self.is_isolated():
            return "serious"
        if self.alarm == "FAILSAFE":
            return "warning"
        return "good"

    def congestion_index(self) -> float:
        """This one junction's own congestion percentage, on the same
        scale and reference point as the network-wide KPI. Shown next to
        the live view so the number the reader is looking at always
        matches the junction they are watching, instead of a network
        average that a single attacked junction can barely move.

        Based on the single busiest approach's own queue relative to its
        own hard cap (MAX_QUEUE_PER_APPROACH), not the total across all
        four approaches relative to a separate network-wide reference.
        This is also standard traffic-engineering practice, not just a
        demo convenience: an intersection's level of service is normally
        rated by its worst/critical movement, not an average across
        every approach. It also directly ties "100% congested" to "the
        single busiest approach is saturated," which is exactly the
        condition one successful spoof-congestion attack produces on its
        own (that attack caps one approach's queue at exactly
        MAX_QUEUE_PER_APPROACH) -- a real, security-relevant attack
        should read as fully alarming without needing a second attack on
        a second approach just to clear an unrelated network-wide
        threshold.

        An earlier version summed all four approaches against a
        separate CONGESTION_REFERENCE_QUEUE instead. Trade-off, made
        deliberately: genuinely gridlocked traffic (all four approaches
        busy at once, no single one attacked) now reads as merely
        "moderate" by only looking at the worst approach, where the old
        version would have read it as fully saturated. Accepted because
        this is a security dashboard answering "is anything actively
        wrong right now," not a capacity-planning tool answering "is
        this intersection near its aggregate throughput limit" -- and
        because "one severe, real attack reads as severe" is the
        property this project's own testing kept surfacing as missing.
        """
        busiest_approach_queue = max(self.queues.values())
        return round(min(100.0, (busiest_approach_queue / MAX_QUEUE_PER_APPROACH) * 100.0), 1)

    def snapshot(self) -> dict:
        context = tel_aviv_data.REAL_WORLD_CONTEXT.get(self.id)
        return {
            "id": self.id,
            "name": self.name,
            "x": self.x,
            "y": self.y,
            "phase": self.phase,
            "alarm": self.alarm,
            "queues": {approach: round(value, 1) for approach, value in self.queues.items()},
            "predicted_arrivals": {
                approach: round(value, 2) for approach, value in self.predicted_arrivals.items()
            },
            "isolated": self.is_isolated(),
            "health": self.health(),
            "congestion_index": self.congestion_index(),
            "real_world_context": (
                {"summary": context.summary, "source": context.source} if context else None
            ),
        }


@dataclass
class SecurityEvent:
    """One row in the SOC-style security event feed, distinct from the
    routine operations log below. Only things a security reviewer would
    care about land here: rejected/unauthorized traffic, conflict-monitor
    vetoes, auto-blocks, isolation and recovery, and preemption grants
    (powerful enough to always be worth surfacing).
    """

    ts: float
    severity: str  # "good" | "warning" | "serious" | "critical"
    intersection_id: Optional[str]
    event_type: str
    message: str
    technique: Optional[str] = None  # MITRE ATT&CK for ICS reference, when applicable

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "severity": self.severity,
            "intersection_id": self.intersection_id,
            "event_type": self.event_type,
            "message": self.message,
            "technique": self.technique,
        }


@dataclass
class OpsLogEntry:
    """A routine, non-security operational line (mode switches, resets).
    Kept separate from SecurityEvent so the security feed stays focused
    on things worth a reviewer's attention.
    """

    ts: float
    message: str

    def to_dict(self) -> dict:
        return {"ts": self.ts, "message": self.message}


def _build_intersections() -> dict:
    """Five junctions in a small hub-and-spoke corridor. Names combine
    real Tel Aviv streets (illustrative pairings, not real deployment
    data). Namir-Einstein specifically echoes ITC's real, publicly
    reported pilot location, as a grounding detail.
    """
    layout = [
        ("begin_hashalom", "Begin - HaShalom", 50, 50),
        ("namir_einstein", "Namir - Einstein", 18, 18),
        ("ibn_gabirol_arlozorov", "Ibn Gabirol - Arlozorov", 82, 18),
        ("rokach_yehudit", "Rokach - Yehudit", 18, 82),
        ("kaplan_begin", "Kaplan - Menachem Begin", 82, 82),
    ]
    return {
        intersection_id: Intersection(
            id=intersection_id,
            name=name,
            x=x,
            y=y,
            real_world_volume_factor=tel_aviv_data.relative_volume_factor(intersection_id),
        )
        for intersection_id, name, x, y in layout
    }


class Network:
    """The whole digital twin: every intersection, the shared security
    state, and the live metrics/event feeds the dashboard renders.
    """

    def __init__(self) -> None:
        # Boots into the hardened mode, not the unauthenticated one.
        # There is deliberately no database here (see this module's own
        # docstring): state, including this field, resets on every
        # server restart. On a public deployment that isn't just "run
        # once and demo it," a restart isn't a rare event, a free host's
        # instance spins down after inactivity and cold-starts fresh on
        # the next request, so "legacy" as the default meant the FIRST
        # thing any visitor after an idle period actually saw was the
        # fully unauthenticated mode, before anyone had deliberately
        # chosen to demonstrate it. An operator running the live demo
        # script (see README.md) still switches into Legacy Retrofit
        # deliberately, on purpose, to show the vulnerable state; a
        # visitor who just opens the link no longer lands there by
        # default.
        self.mode: str = "secure"  # "legacy" | "secure"
        self.intersections: dict = _build_intersections()
        # Star topology: the hub connects to each of the other four.
        self.edges: list = [
            ("begin_hashalom", "namir_einstein"),
            ("begin_hashalom", "ibn_gabirol_arlozorov"),
            ("begin_hashalom", "rokach_yehudit"),
            ("begin_hashalom", "kaplan_begin"),
        ]
        self.threats = ThreatTracker()
        self.security_events: deque = deque(maxlen=SECURITY_EVENT_HISTORY_LIMIT)
        self.ops_log: deque = deque(maxlen=OPS_LOG_HISTORY_LIMIT)
        self.congestion_history: deque = deque(maxlen=CONGESTION_HISTORY_LIMIT)
        # (timestamp, vehicles_served) pairs for the rolling throughput
        # estimate; see throughput_per_hour().
        self.served_log: deque = deque(maxlen=1000)
        # (timestamp, channel) pairs for every request that reaches
        # apply_command/apply_telemetry, successful or not. This is
        # what makes a flood/DoS attack visible as *load* on the
        # dashboard, not just as a series of rejections. Capped high
        # since a real flood can arrive faster than the KPI window drains.
        self.request_log: deque = deque(maxlen=5000)
        # Time-of-day control (see tel_aviv_data.py's HOURLY_TRAFFIC_
        # MULTIPLIER): which hour of the day, 0-23, the simulation
        # currently models. Defaults to the real current hour in Tel
        # Aviv specifically (Asia/Jerusalem, which zoneinfo resolves
        # correctly across DST changes on its own), not
        # datetime.now()'s bare, timezone-naive reading of whatever
        # timezone the machine actually running this process happens to
        # be set to. That distinction didn't matter for local
        # development (the same machine as whoever's watching), but
        # does once this runs on a real host: a free tier's server is
        # commonly UTC by default, so a viewer in Israel (UTC+3 in
        # summer) was seeing the dashboard open 3 hours behind their own
        # actual local time, reported directly and reproduced exactly
        # (dashboard read 16:00 against an actual local time of 19:00).
        # Pinned specifically to Tel Aviv rather than reading the
        # viewer's own timezone (this server has no per-visitor
        # timezone to read anyway, see the single-shared-network
        # architecture note elsewhere in this project) because that's
        # what the whole simulation already models: nothing else here
        # depends on wall-clock time, and this is just a starting point,
        # freely changeable via /api/hour regardless.
        self.simulated_hour: int = datetime.now(ZoneInfo("Asia/Jerusalem")).hour
        # Derived from simulated_hour, and scales detection.py's arrival
        # probability the same way the old fixed Light/Normal/Rush Hour
        # control used to. Cached rather than recomputed on every read;
        # set_simulated_hour() keeps the two in sync.
        self.arrival_multiplier: float = tel_aviv_data.hourly_traffic_multiplier(self.simulated_hour)
        self.connections: list = []  # active WebSocket connections
        # One shared, continuously-learning predictor across every
        # intersection and approach (see ml_predictor.py). Left unwarmed
        # here; main.py's startup calls warm_up() once, alongside
        # starting the background tasks that keep training it live.
        self.arrival_predictor = ml_predictor.ArrivalPredictor()

    # Logging

    def log_security(
        self,
        severity: str,
        intersection_id: Optional[str],
        event_type: str,
        message: str,
        technique: Optional[str] = None,
    ) -> SecurityEvent:
        # An explicit `technique` always wins (needed for event types like
        # "preemption_granted" that cover both a legitimate, authenticated
        # grant and a spoofed one; only the latter is an ATT&CK-mapped
        # attack). Otherwise fall back to the type-level default table.
        resolved_technique = technique or ATTACK_TECHNIQUE_BY_EVENT_TYPE.get(event_type)
        entry = SecurityEvent(
            ts=time.time(),
            severity=severity,
            intersection_id=intersection_id,
            event_type=event_type,
            message=message,
            technique=resolved_technique,
        )
        self.security_events.append(entry)
        return entry

    def log_ops(self, message: str) -> OpsLogEntry:
        entry = OpsLogEntry(ts=time.time(), message=message)
        self.ops_log.append(entry)
        return entry

    # Throughput / KPIs

    def record_served(self, amount: float) -> None:
        if amount > 0:
            self.served_log.append((time.time(), amount))

    def record_request(self, channel: str) -> None:
        """Logs one request to the command or telemetry channel,
        regardless of whether it was ultimately accepted or rejected.
        Volume itself is the signal a flood/DoS attack produces.
        """
        self.request_log.append((time.time(), channel))

    def channel_load(self) -> dict:
        """Requests/minute on each channel over the last
        REQUEST_LOG_WINDOW_SECONDS: what a "Flood / DoS" attack makes
        visibly spike on the dashboard, on top of (and even before) any
        individual request getting rejected or a source getting blocked.
        """
        now = time.time()
        recent = [channel for ts, channel in self.request_log if now - ts <= REQUEST_LOG_WINDOW_SECONDS]
        scale = 60.0 / REQUEST_LOG_WINDOW_SECONDS
        return {
            "command_per_min": round(sum(1 for c in recent if c == "command") * scale),
            "telemetry_per_min": round(sum(1 for c in recent if c == "telemetry") * scale),
        }

    def throughput_per_hour(self) -> float:
        """Vehicles/hour, extrapolated from what was actually served in
        the last SERVED_LOG_WINDOW_SECONDS: a real rolling measurement
        of the simulation, not a fabricated number.
        """
        now = time.time()
        recent_total = sum(
            amount for ts, amount in self.served_log if now - ts <= SERVED_LOG_WINDOW_SECONDS
        )
        return recent_total * (3600.0 / SERVED_LOG_WINDOW_SECONDS)

    def avg_queue_length(self) -> float:
        totals = [sum(intersection.queues.values()) for intersection in self.intersections.values()]
        return sum(totals) / len(totals) if totals else 0.0

    def kpis(self) -> dict:
        throughput = self.throughput_per_hour()
        avg_queue = self.avg_queue_length()

        # Little's Law (L = lambda * W => W = L / lambda): average wait
        # time from average queue length and the current arrival/service
        # rate. A real, named approximation applied to simplified data,
        # not a claimed measurement of any real system.
        arrival_rate_per_second = throughput / 3600.0
        avg_wait_seconds = (avg_queue / arrival_rate_per_second) if arrival_rate_per_second > 0.01 else 0.0

        # The WORST junction's own congestion_index() (already capped
        # 0-100), not an average across all five, and not recomputed
        # from raw avg_queue above. Same "worst-first" principle the
        # status banner already uses (see SEVERITY_RANK in app.js): a
        # severe, real attack on one junction is a severe, real incident
        # for the network, and averaging it against four calm junctions
        # buried that signal under a diluted ~20-point bump instead of
        # showing it. This is also what makes "goes up to 100% under
        # attack, comes back down once restored" true: the single
        # attacked junction's own capped number already reaches exactly
        # 100% at MAX_QUEUE_PER_APPROACH-per-approach saturation (see
        # Intersection.congestion_index()), so the network figure now
        # tracks it directly instead of diluting it. An earlier version
        # of this DID average, deliberately, to fix a different bug (the
        # network figure and one attacked junction's own number
        # disagreeing because the average was built from raw, uncapped
        # queue totals instead of each junction's own capped number) --
        # that fix is preserved here: this still reads from each
        # junction's own capped congestion_index(), just takes the max
        # of them instead of the mean, so both properties hold at once.
        congestion_index = max((i.congestion_index() for i in self.intersections.values()), default=0.0)

        active_incidents = sum(
            1
            for intersection in self.intersections.values()
            if intersection.alarm is not None or intersection.is_isolated()
        )

        return {
            "throughput_per_hour": round(throughput),
            "avg_wait_seconds": round(avg_wait_seconds, 1),
            "congestion_index": round(congestion_index, 1),
            "active_incidents": active_incidents,
        }

    def sample_congestion(self, now: Optional[float] = None) -> None:
        self.congestion_history.append(
            {"ts": now if now is not None else time.time(), "value": self.kpis()["congestion_index"]}
        )

    # Time of day

    def set_simulated_hour(self, hour: int) -> None:
        """Updates the Time of Day control and its derived arrival
        multiplier together, so the two can never drift out of sync.
        """
        self.simulated_hour = hour
        self.arrival_multiplier = tel_aviv_data.hourly_traffic_multiplier(hour)

    # Mode / reset

    def reset_intersection(self, intersection_id: str) -> bool:
        """Returns one junction to a genuinely clean slate, not just
        clearing the alarm flag. Queues are reset too: otherwise a
        spoof-congestion attack leaves a fake backlog that outlives the
        "incident" by many minutes of real service time, which reads as
        the demo being broken rather than as the attack having happened.
        """
        intersection = self.intersections.get(intersection_id)
        if intersection is None:
            return False
        intersection.phase = "ALL_RED"
        intersection.alarm = None
        intersection.isolated_until = None
        intersection.recovery_hold_until = None
        intersection.phase_since = time.time()
        intersection.queues = {approach: 0.0 for approach in APPROACHES}
        intersection.last_preemption = None
        intersection.preemption_phase = None
        intersection.recent_arrivals = {
            approach: deque([0.0] * ml_predictor.HISTORY_WINDOW, maxlen=ml_predictor.HISTORY_WINDOW)
            for approach in APPROACHES
        }
        intersection.pending_tick_arrivals = {approach: 0.0 for approach in APPROACHES}
        intersection.predicted_arrivals = {approach: 0.0 for approach in APPROACHES}
        # OrderedDict, not {}: touch_bounded_source (security.py) calls
        # .move_to_end() on this, which a plain dict doesn't have.
        intersection.recent_accepted_commands_by_source = OrderedDict()
        return True

    def reset_all(self, mode: Optional[str] = None) -> None:
        if mode is not None:
            self.mode = mode
        for intersection_id in self.intersections:
            self.reset_intersection(intersection_id)
        self.threats.reset()

    # Serialization

    def snapshot(self) -> dict:
        return {
            "mode": self.mode,
            "intersections": [i.snapshot() for i in self.intersections.values()],
            "edges": self.edges,
            "kpis": self.kpis(),
            "channel_load": self.channel_load(),
            "simulated_hour": self.simulated_hour,
            "arrival_multiplier": self.arrival_multiplier,
            "congestion_history": list(self.congestion_history),
            "security_events": [e.to_dict() for e in self.security_events],
            "ops_log": [e.to_dict() for e in self.ops_log],
            "blocked_sources": sorted(self.threats.blocked_sources),
        }


# Single shared instance, fine for a single-process demo server.
network = Network()
