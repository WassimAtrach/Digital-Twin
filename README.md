# ITC Digital Twin — Traffic Network Security Operations

A live digital twin of a five-junction ITC-style traffic network: real AI-driven
signal orchestration, backed by a genuinely-trained ML model that predicts
near-term traffic and is calibrated with real, cited Tel Aviv traffic data,
running over simulated camera telemetry; an attack console modeling four
distinct, realistic attack classes with a live preview of the exact request
payload each one sends; a second, standalone Live Network Monitor page showing
all five junctions animating at once; and a SOC-style monitoring + incident-
response dashboard that reacts to all of it in real time.

## Why this is grounded in reality, not invented

**The company.** ITC — Intelligent Traffic Control is a real Israeli startup
(founded 2019, Series A funded). Its public product pages describe an AI-driven
signal-orchestration platform (VisionInsight/VisionFlow) plus an analytics
dashboard (VisionTwin) that is explicitly **hardware-agnostic**: it connects to
*existing* cameras and *existing* traffic-light infrastructure rather than
replacing it, and is deployed with Netivei Israel (the national road operator),
piloted at a real Tel Aviv junction (Namir–Einstein). No non-public details about
ITC's actual system were available or used — everything here (the protocol, the
phase model, the specific junction names beyond Namir-Einstein) is a simplified,
self-contained model built for this demo.

That "retrofit onto existing infrastructure" model is also the realistic attack
surface this demo focuses on: a modern AI layer bridged onto field hardware that,
historically, has not required authentication to talk to.

**The five junctions.** Real Tel Aviv street names, and two of them carry a
genuine, independently-checkable traffic-volume grounding, found by researching
the actual streets rather than invented to look researched:

- **Kaplan – Menachem Begin**, modeling the real Kaplan Interchange, one of Tel
  Aviv's busiest junctions: Israeli Ministry of Transport figures put it at
  roughly 150,000 vehicles a day since a 2003 upgrade, up from about 100,000
  before. ([Wikipedia](https://en.wikipedia.org/wiki/Kaplan_Interchange))
- **Namir – Einstein** is a real intersection ITC actually manages, carrying, in
  ITC's own words to ynet, "tens of thousands of vehicles" every day, out of
  more than 100,000 cars/day ITC's technology manages across its Tel Aviv
  deployments overall. ([ynetnews](https://www.ynetnews.com/environment/article/sjvw2tsjt))

The other three (Ibn Gabirol–Arlozorov, Begin–HaShalom, Rokach–Yehudit) are real,
well-documented busy corridors, but no independently published daily-vehicle-
count for those specific junctions turned up during research — see
`server/tel_aviv_data.py` for the full citations, including for those three,
which are deliberately left qualitative rather than having a number invented for
them. These facts calibrate each junction's relative simulated traffic volume
(see "The ML predictor" below); they are not a claim that ITC actually manages
all five, or that the exact pairings/topology reflect a real deployment.

**The vulnerability classes.** In 2014, University of Michigan researchers
("Green Lights Forever: Analyzing the Security of Traffic Infrastructure") found
real production traffic controllers reachable over unencrypted, unauthenticated
radio links. Preemption spoofing — forging an emergency-vehicle signal to jump a
queue — is a separately documented weakness class in real emergency-vehicle-
preemption (EVP) hardware. Both are modeled here as what "Legacy Retrofit" mode
allows.

**The attack taxonomy.** Each attack is labeled with its real MITRE ATT&CK for
ICS technique, verified against attack.mitre.org (not guessed):
[T0855 – Unauthorized Command Message](https://attack.mitre.org/techniques/T0855/),
[T0856 – Spoof Reporting Message](https://attack.mitre.org/techniques/T0856/),
[T0814 – Denial of Service](https://attack.mitre.org/techniques/T0814/).

## Architecture

```
Browser dashboard  <--WebSocket + REST-->  FastAPI server  <-- attacker.py (CLI)
   (web/*)                                  (server/*)         uses the same
        |                                        |              REST API
        |                            +-----------+-----------+
        |                            |                       |
  same public API              detection.py            orchestrator.py
  as an attacker             (simulated camera        (the "AI": reads
  would use                   network, signed          queues + ML forecast,
                               telemetry)               decides phases,
                                        \                signed commands)
                                         \                    /
                                          v                  v
                                       ml_predictor.py (shared, online-
                                       trained model) + tel_aviv_data.py
                                       (real-world calibration per junction)
```

- **`server/security.py`** — two independently-keyed HMAC channels (command vs.
  telemetry), each with a freshness window (a timestamp folded into the signed
  payload, rejected once stale) that defeats replay, a `ConflictMonitor`
  modeling a hardware safety interlock (a real Malfunction Management Unit),
  telemetry plausibility bounds, and a `ThreatTracker` that auto-blocks repeat
  offenders.
- **`server/network.py`** — the digital twin's domain model: five intersections
  in a small hub-and-spoke network, KPI math (throughput, wait time via Little's
  Law, a congestion index), the security-event and ops-log feeds, and channel
  request-rate tracking (what makes a flood/DoS attack visible as *load*, not
  just as rejections).
- **`server/detection.py`** — simulates the camera/sensor layer: realistic
  arrival events (weighted by road-user type, calibrated per junction by
  `tel_aviv_data.py`) submitted through the exact same signed telemetry path an
  attacker has to forge, and drives the ML predictor's predict/train cycle every
  tick.
- **`server/ml_predictor.py`** — a small, hand-rolled online linear regression
  model (no third-party ML library: scikit-learn's native dependencies are
  blocked by this machine's Windows Application Control policy) that predicts
  each approach's near-term arrivals and keeps learning from live simulated
  traffic for as long as the server runs. See "The ML predictor" below.
- **`server/tel_aviv_data.py`** — the real, cited Tel Aviv research described
  above, turned into a per-junction calibration factor.
- **`server/orchestrator.py`** — the "AI": a real (if simplified) queue-
  comparison control rule that decides signal phases from live telemetry plus
  the ML predictor's forecast, applied through the same signed command path an
  attacker has to forge, plus emergency-preemption handling and automatic
  isolation/recovery of a node under sustained attack.
- **`server/main.py`** — FastAPI app: the command and telemetry channels, mode
  switching, manual incident-response playbook actions, the `/api/hour`
  traffic-load control, the forecast endpoint, and the WebSocket that keeps
  the dashboard live.
- **`server/forecast.py`** — the ML Forecast tool's engine: fast-forwards a
  disposable copy of one junction through simulated ticks using the live
  trained predictor and the real orchestrator decision/serving logic, without
  touching live state. See "Time of day and the ML Forecast tool" below —
  the main dashboard doesn't surface this tool directly (see next bullet),
  but the Live Network Monitor does, once per junction.
- **`attacker.py`** — a standalone CLI attacker with no signing key, for any
  channel — `inject`, `spoof-congestion`, `spoof-emergency`, or `flood` (which
  can flood any of the other three).
- **`web/`** — plain HTML/CSS/JS with no build step, following a validated
  dark-mode data-visualization system (fixed status/categorical color scales, a
  real hover tooltip on the trend chart, direct-labeled queue bars):
  - `index.html` / `app.js` — the SOC dashboard: attack console, incident-
    response playbook, live junction canvas, Light/Normal/Rush Hour traffic
    load control.
  - `monitor.html` / `monitor.js` — the Live Network Monitor: all five
    junctions animating at once, purely observational, no attack console, plus
    a per-junction ML Forecast tool that plays a forecast out on that
    junction's own canvas.
  - `car-sim.js` — the car-simulation renderer (lane math, signal rendering,
    animation) shared unchanged by both pages above, so each junction's canvas
    behaves identically wherever it's shown.
  - `style.css` — shared by all pages.

## Attack classes and their defenses

| Attack | Channel | What it does | Legacy mode | ITC Secure Integration |
|---|---|---|---|---|
| **Command Injection** (T0855) | Command | Unsigned `FORCE_ALL_GREEN` to a target junction | Applied directly — real collision-risk state | Rejected: invalid signature. Even a hypothetically-signed one would still be vetoed by the independent conflict monitor |
| **Sensor Spoofing — Congestion** (T0856) | Telemetry | Reports an implausible fake queue on one approach | Trusted outright, poisons the AI orchestrator's timing decisions | Rejected: invalid signature (and, independently, fails a plausibility bound even if signed) |
| **Sensor Spoofing — Preemption** (T0856) | Telemetry | Fakes an emergency vehicle to force an unearned green | Granted — legacy mode can't tell a real ambulance from a forged claim | Rejected: invalid signature |
| **Flood / DoS** (T0814) | Either | Repeats any of the above rapidly from one source | Every attempt succeeds independently | First 3 attempts logged and rejected; the source is then auto-blocked and its target junction isolated (held safe, ignored by the AI orchestrator) for a cooldown, then automatically recovers |
| **Coordinated** *(modifier, not its own row)* | Either | Fires any one attack above at all 5 junctions at once instead of a single target, combinable with Flood | Every junction compromised simultaneously | Same per-junction defenses as above, applied independently at each of the 5 |

Two independent signing keys (one per channel) mean compromising one doesn't
grant the other — a forged "camera" can lie about vehicle counts but can't
directly command a signal.

## Message freshness: a real gap this review found, and fixed

A signature proves a message was genuine once. It doesn't prove the message is
current. Before this pass, `security.py`'s HMAC signatures covered only the
phase being commanded, nothing about when, so a real, validly-signed command,
if captured off the channel, would have verified successfully **forever**, no
matter how long ago it was actually issued. That's a real, general weakness
class, not specific to traffic control: MITRE ATT&CK for ICS files it under
[T0831 – Manipulation of Control](https://attack.mitre.org/techniques/T0831/),
which explicitly lists replaying captured valid packets as one of its methods.

**The fix.** Both signing functions in `security.py` now fold a timestamp
into the signed payload itself (not just alongside it, so a captured
signature can't be paired with a forged, newer timestamp), and both verify
functions reject anything older than `COMMAND_FRESHNESS_WINDOW_SECONDS` /
`TELEMETRY_FRESHNESS_WINDOW_SECONDS` (8 seconds), even when the signature is
still mathematically valid. This runs unconditionally on both channels, for
every command and telemetry event, not behind a demo toggle — real hardening
against a real message-capture-and-resend scenario. (An earlier version of
this project demonstrated the gap and the fix with a dedicated "Replay
Attack" console option and CLI subcommand; removed since as UI it was more
confusing than illustrative, but the underlying freshness check it was
exercising is unchanged and still runs on every request.)

**A second bug this same testing pass caught, in `attacker.py` itself.**
While verifying the (since-removed) replay demonstration, a second, unrelated
bug turned up: the `flood` subcommand's own `--attack` flag shared the same
argparse `dest` ("attack") as the top-level subcommand selector, so parsing
`flood --attack inject` silently overwrote which subcommand had been chosen,
and `main()` ended up dispatching straight to a single one-shot
`send_inject()` call instead of `run_flood()`. **Every flood command, for
every attack type, had been sending exactly one request, silently ignoring
`--repeat` and `--delay` entirely.** Fixed by giving that argument an
explicit, non-colliding `dest="flood_type"`; verified with a real
`flood --attack inject --repeat 4` run showing all 4 requested attempts,
including the 3-strike auto-block on the 4th.

## Command rate limiting: closing a gap the freshness window leaves open

The freshness window stops an *old* replay, but `ThreatTracker` only counts
*failed* attempts, and a replay inside the freshness window succeeds. Nothing
stopped the same still-fresh captured signature from being resent rapidly,
over and over, without ever failing a single check. `security.is_rate_limited`
closes that: once a junction has accepted `COMMAND_RATE_LIMIT_MAX` (5) commands
within `COMMAND_RATE_LIMIT_WINDOW_SECONDS` (5s), the next one is throttled
regardless of how validly it's signed, in Secure mode only.

The threshold is derived, not guessed: the fastest two legitimate commands can
ever land back to back is `ORCHESTRATOR_TICK_SECONDS` (2s, a new decision can
only be made once per tick), a floor that holds even under gap-out's most
aggressive early termination. Five commands need at least 8 seconds even in
that extreme legitimate case, comfortably above the 5-second window, so this
can never throttle the AI orchestrator's own genuinely busy traffic.

**Verified, and fixed once already while verifying it.** The first version
scoped this per junction only, not per (junction, source): a flooding
attacker's requests and the real orchestrator's requests shared the same
budget, so an attack could also throttle legitimate traffic to that same
junction, a self-inflicted collateral denial of service that defeated the
point. Caught by testing a flood *and then immediately watching real
orchestrator traffic to the same junction* — 0 false positives over 15 seconds
of live operation after the fix, while the attacker still gets throttled on
request 6 of a rapid-fire replay.

## Recommended responses that actually match what each attack breaks

The Incident Response Playbook's three actions do genuinely different things
(see their tooltips):

- **Command Injection** leaves a live physical hazard (`COLLISION_RISK`, both
  directions green). **Isolate Node** is the recommendation — it forces
  `phase = ALL_RED` exactly as immediately as Fail-Safe Flash does (both call
  the same `_isolate()`/equivalent phase change in `main.py`), and
  additionally rejects further commands and telemetry for 25 seconds, from
  anyone, not just the original attacker.

  **This was wrong in an earlier pass, corrected after live testing exposed
  it, not by re-reading the code first.** The original reasoning was "Isolate
  Node alone doesn't touch the current phase" — flatly false, contradicted by
  `main.py`'s own `_isolate()`, which sets `phase = "ALL_RED"` exactly like
  Fail-Safe Flash. Worse, Fail-Safe Flash *alone* (no isolation) leaves a
  junction accepting organic telemetry with nothing served (`ALL_RED` serves
  no approach), so its queues climb with nothing draining them: confirmed
  live, congestion 25% → 100% in 8 seconds sitting in Fail-Safe with nothing
  else happening. The identical attack, isolated instead, held flat at 25%
  for the full 10-second window, because isolation also rejects incoming
  telemetry (see the isolation-enforcement fix below). Reported as
  "congestion goes up and nothing fixes the system, after pressing fail-safe
  flash" — an entirely accurate description of a real gap between the two
  buttons that the original recommendation had backwards.
- **Both Sensor Spoofing attacks** leave corrupted *state* behind (a fake
  queue number, or a standing fake preemption) that isolating never cleans
  up — isolation blocks *future* traffic but never touches `queues` or
  `last_preemption`. **Restore Normal Operation** is what actually clears
  the fabricated data already accepted. This part was correct from the
  start and is unchanged.
- **Flood, of any of the above** — checked before the per-type rules above.
  A single request landing once needs whatever it leaves broken fixed
  directly; a channel hit repeatedly needs the repetition stopped first,
  since Restore alone would just get immediately re-broken by the next
  request in the same flood. **Isolate Node** addresses that, and now
  coincides with Injection's own single-attack recommendation above rather
  than overriding it — Sensor Spoofing floods are where this still actually
  changes the recommendation from the single-attack case.

**A real bug this recommendation logic exposed, in Fail-Safe Flash itself.**
Clicking it set `phase = ALL_RED` and `alarm = FAILSAFE` but never set
`isolated_until` — only the automatic 3-strike auto-block path does that. The
orchestrator loop only skips a junction it finds isolated or in
`COLLISION_RISK`; nothing told it to leave an `ALL_RED` junction with no
isolation alone, so `_decide_phase()` treated it exactly like a junction
freshly recovering from isolation and picked a fresh green phase for it
immediately. Confirmed live: phase and alarm checked immediately after the
click, then again after 3 seconds — `ALL_RED`/`FAILSAFE` had already been
silently overwritten with a real green phase and a cleared alarm. **A manual
"force safe state now" button was undoing itself within about 2 seconds**,
before an operator watching the dashboard could even confirm it had worked.
Fixed by holding any junction with `alarm in (COLLISION_RISK, FAILSAFE)`,
not just `COLLISION_RISK`; a currently-isolated junction is still held by
the existing isolation check first, so this only changes behavior for the
two paths that set `FAILSAFE` without isolating (Fail-Safe Flash, and the
secure-mode conflict-monitor veto in `main.py`, likely unreachable via the
actual attack surface today but the same latent bug either way). Verified
live over a 10-second window post-fix: `ALL_RED`/`FAILSAFE` held the entire
time, and clicking Restore still correctly hands control back.

## Restore All Junctions: fixing a Coordinated attack shouldn't be 5x slower than causing one

Coordinated fires one attack at all 5 junctions in a single click. Fixing it
required selecting each of the 5 in turn and clicking Restore Normal
Operation five separate times — the actual bottleneck behind "coordinated
attack takes too long till everything is fixed," not the attack itself.
`server/main.py` already had a whole-network reset (`POST /api/reset` with
no `intersection_id`, calling `network.reset_all()`); nothing in the
frontend had ever called it. Added **Restore All Junctions**, a fourth
playbook button, network-wide rather than tied to the selected junction
like the other three, that hits that same endpoint once.

**A bug in the fix itself, caught by testing the actual flow, not by
inspection.** The button's disabled state first checked
`active_incidents === 0` (the same signal the KPI tile uses) — but a
successful spoof-congestion attack sets neither `alarm` nor `isolated`, it
only inflates queues, so `active_incidents` stays 0 even with the network
at 100% congested. The button was disabled exactly when it was most needed,
and a disabled button never fires a click at all, so the fix would have
been silently inert for the attack type it matters most for. Fixed to check
for any non-zero queue too, not just alarm/isolation. Verified live, full
Coordinated cycle: baseline → coordinated spoof-congestion (congestion
100%) → one click on Restore All Junctions (816ms) → congestion 12.5%
(genuine fresh organic traffic in the sub-second gap, not a bug) → every
queue at 0 except the one busiest real-world-calibrated junction's own
single new car.

## Isolation never actually isolated anything — the most significant bug this project has shipped with

Reported as "Fail-Safe Flash turns everything red but the attack doesn't
resolve, what about Isolate Node." The Fail-Safe half turned out to be
working exactly as designed (see "Recommended responses" above — it's a
containment action, Restore is the recovery action) plus one real wording
bug in the status banner (below). Isolate Node was a different story.

`isolated_until` (see `Intersection` in `network.py`) was only ever *set*:
by `_isolate()` in `main.py`, and read by `orchestrator.py`'s loop to stop
the legitimate AI from fighting over a junction under suspicion. It was
never *checked* against incoming requests in `apply_command` or
`apply_telemetry` at all. So "Isolate Node," despite its own tooltip's
explicit promise — *"Cuts this junction off from incoming commands and
telemetry for 25 seconds"* — did nothing of the kind: it only asked the AI
to back off. An attacker (or attacker.py, or the CLI, or anyone with the
URL) could isolate a junction and then keep attacking the exact same
junction, every request landing exactly as before, isolated or not.

Confirmed live before fixing anything: isolated a junction, immediately
attacked it again — the attack succeeded, queue changed, no rejection at
all. That's precisely why the report was "the attack doesn't resolve":
clicking Isolate Node produced a UI state that said "isolated," a security
event that said "isolated," and a health badge that said "Isolated" — while
changing nothing about whether the junction could still be attacked.

**The fix**: both `apply_command` and `apply_telemetry` now check
`intersection.is_isolated()` immediately after the intersection lookup,
before even the source-block check, and reject anything targeting an
isolated junction — logged as its own `rejected_isolated` security event.
Applied to *all* traffic, not just attacker traffic: `detection.py`'s
organic camera telemetry gets rejected the same way while a junction is
isolated, which is also the more realistic behavior (a real quarantined
sensor channel isn't selectively trusted for the reports that happen to
look legitimate — nothing from it is trusted until an operator clears the
isolation).

Verified live, full cycle: isolate a junction → attack it → `{"ok": false,
"reason": "isolated"}`, queue unchanged. A *different*, non-isolated
junction attacked in the same moment still lands normally (queue 0 → 8),
confirming this isn't an accidental global block. The event log shows both
an attacker source and `itc-camera-network` itself being rejected while
isolated. Restore clears it and the junction accepts traffic again
immediately afterward.

**Also fixed alongside this**: the status banner's fail-safe message said
"Flashing red as a precaution while it recovers" — true for an isolated
junction (which really does auto-recover), false for a manually-triggered
Fail-Safe Flash, which (see the FAILSAFE-hold fix above) has no
auto-recovery timer at all and holds until a human clicks Restore. Reworded
to say what actually needs to happen next instead of implying it'll sort
itself out.

## The guided recommendation ignored Coordinated entirely

Reported directly: run a Coordinated attack (every junction hit at once),
and the glowing "recommended" button still only fixed whichever ONE junction
happened to be selected before the attack — clicking it left the other four
exactly as attacked. `recommendedActionFor` checked `isFlood` (repetition)
but never checked whether the attack had actually been Coordinated (scope):
a genuine account of a bug, not a report that turned out to be stale cache
or user error like several before it.

Fixed by checking scope first: `floodSummary.targetCount > 1` now overrides
both the per-type table and the Flood-specific override, recommending
**Restore All Junctions** — the one existing action whose scope actually
matches a Coordinated attack — regardless of whether Flood is also checked
(explicitly requested to cover that combination too, not just Coordinated
alone). Verified live, three ways: Coordinated alone recommends Restore All
Junctions with the correct button glowing; Coordinated + Flood together
still does, not falling back to Isolate Node; and clicking the glowing
button actually clears all 5 junctions' alarms in one request (5 → 0),
not just the one that was selected beforehand.

## Restore All Junctions: a real recovery, not an instant snap to zero

Requested directly: turn everything red first, then let congestion actually
calm down over roughly 30 seconds, rather than the network-wide instant
zero-out `/api/reset` gave every junction at once. Two separate mechanisms,
both real:

**Turn everything red — guaranteed, not a timing coincidence.** `/api/
playbook`'s new `restore_all` action clears every junction's alarm and
isolation and forces `ALL_RED` immediately, but the very next
`orchestrator_loop` tick would otherwise see `ALL_RED` and treat it as "fresh
start, pick a phase now" -- whenever that tick happened to land, anywhere
from milliseconds to a full `ORCHESTRATOR_TICK_SECONDS` (2s) later, purely by
chance, since the orchestrator's clock isn't synchronized to when an operator
clicks anything. Confirmed live before adding a fix: sampled phase every
300ms after clicking, `ALL_RED` held for as little as ~600-900ms in one run --
visible, but not reliably so. Added `Intersection.recovery_hold_until` and
`orchestrator.py`'s `RECOVERY_HOLD_SECONDS` (3.0s): the orchestrator now
explicitly holds `ALL_RED` for a guaranteed window before resuming phase
decisions. Verified live: phase sampled every 300ms for 15 samples straight
showed `ALL_RED` the entire ~3.7s before flipping — a real, dependable
"something happened" moment now, not a coin flip.

**Then calm down over roughly 15 seconds — real service, not a scripted
countdown.** `restore_all` deliberately does not touch `queues` at all. Once
the hold above expires, the AI orchestrator resumes completely normal
control: `_decide_phase` picks a phase from the still-elevated queues, and
`_serve_green_approaches` drains them at the same `SERVICE_RATE_PER_TICK`
that governs every other queue in this simulation, alternating NS/EW every
`MIN_GREEN_SECONDS`. No new congestion-decay mechanism was built — the
existing physics does this on its own once nothing is artificially blocking
it.

`SERVICE_RATE_PER_TICK` itself changed after this section was first written
(1.5 → 4.0, see orchestrator.py's own comment on that constant for the full
story: a real deployment left running past a normal-traffic hour organically
gridlocked multiple junctions to 100% with zero attacks running, because 1.5
only ever had headroom against roughly a 1.0-1.2x traffic multiplier, not the
full 24-hour curve's real range up to 3.0x). Re-verified live after that fix,
spiking three junctions to 100% first: congestion held at 100% through the
guaranteed `RECOVERY_HOLD_SECONDS` window, dropped to 62.5% by t=6-9s, 25% by
t=12s, and settled into a calm, still-naturally-fluctuating 12.5-37.5% range
from t=15s onward — a clear, substantial, watchable decline, meaningfully
faster than the original ~30-second figure this section used to cite,
because the underlying service rate that drains every queue in this
simulation, not just restore_all's, is now itself different.

## Ground-truth arrivals: isolation blocks the channel, not reality

A direct follow-on from the Isolate Node fix above, and reported just as
directly: *"the congestion index doesn't go up when pressing isolate node
and it doesn't make sense, it needs to go up because traffic stops [being
served]."* Correct. Isolation blocking incoming telemetry (the previous fix)
correctly stopped an attacker from adding *more* forged congestion to an
isolated junction — but it also meant `queues` could only ever be changed by
telemetry, so an isolated junction's congestion held perfectly flat for as
long as it stayed isolated. That's not what happens at a real quarantined
sensor: the camera being untrusted doesn't make real cars stop arriving, it
just means the operator loses visibility into them until it's cleared.

`orchestrator.py` now has `_accumulate_ground_truth_arrivals`, applied only
while a junction is still isolated (not to a merely Fail-Safe'd one, which
already grows normally via ordinary organic telemetry — adding this there
too would double-count it). It reuses `detection.py`'s own
`ARRIVAL_PROBABILITY` at the same tick cadence, so an isolated junction's
congestion climbs at roughly the real rate a non-isolated Fail-Safe'd one
already does. Applied directly to `queues`, deliberately bypassing
`apply_telemetry`'s signed/plausibility pipeline entirely: this models
ground truth, not a reported message, so it's immune to being manipulated
by an attacker the size or shape of a real spoof-congestion report, and
isn't blocked by isolation the way telemetry correctly now is either — two
different, both intentional, properties of the same mechanism.

Verified live: isolate a junction mid-attack, watch congestion climb
steadily (37.5% → 100% over 10 seconds) purely from this mechanism while
isolated, correctly plateau once every approach hits its own cap, then
Restore still clears it to 0% and hands it back to normal control exactly
as before.

## Ambient traffic: an empty queue isn't an empty road

`queues[approach]` tracks backlog — vehicles waiting to be served — not
"is a car currently visible here." At light traffic (most of a calm hour,
or most approaches most of the time even at moderate traffic), that value
is frequently a fraction under 0.5, and `car-sim.js`'s renderer used to
convert queue length straight to car count via `Math.round()` — so any
queue under 0.5 rendered as zero cars. Real light traffic still has
occasional cars passing straight through without ever backing up, which a
queue-only count can't represent at all; reported as "some junctions show
no traffic during low congestion times, there must be some cars."

Fixed in `car-sim.js`'s `reconcile()`: an approach with real backlog
(`queue > 0`) still renders exactly `Math.round(queue)` cars as before —
this part was already correct. An approach at exactly zero backlog now has
a small chance, evaluated once per reconcile, of spawning one ambient car —
but only when it's already empty, and never forced away early on a later
miss, so a spawned car always clears through normally (stops on red, drives
through on green, exits) instead of visibly vanishing mid-wait. Verified
live at hour 3 (deep night, every junction's queues confirmed genuinely
0.0 via the API): the canvas still shows 1-2 cars correctly stopped at red
lights, persisting correctly across multiple real-time frames without the
queue bars ever leaving zero. A flat, hand-tuned spawn rate, not scaled by
the real hourly multiplier or a junction's calibration factor — a
deliberate simplification, not a claim that it reflects real relative
traffic volume the way the queue-driven car counts and congestion index do.

## Keyboard accessibility: a real gap across the whole dashboard

Found during a full pass over the codebase, not reported: the topology map's
five junction nodes (`app.js`'s `renderTopology`) were plain SVG `<g>`
elements with a click listener and nothing else — no `tabindex`, no `role`,
no keyboard handler, so there was no way to reach or activate them from a
keyboard at all. Worse, the `<svg>` they live inside carried `role="img"`,
which tells assistive tech to treat everything inside as one flat, described
picture and hide the children's own semantics — exactly backwards for an
SVG whose entire point is five independently operable controls, not a
static image. Fixed both: each node now has `tabindex="0"`,
`role="button"`, and an `aria-label` naming the junction, plus a `keydown`
handler for Enter/Space; the parent `<svg>` is `role="group"` instead.
Verified live: focusing the second node and dispatching a real
`KeyboardEvent("keydown", {key: "Enter"})` at it changed `selectedIntersectionId`
exactly as a click would.

That fix also surfaced a second, page-wide gap: nothing anywhere in
`style.css` styled `:focus` at all, so even elements that *were* already
keyboard-operable (every real `<button>` and `<select>` on both pages) gave
no visible indication of where keyboard focus actually was — reachable, but
effectively invisible. One global `:focus-visible` rule (not plain
`:focus`, so it doesn't show up on a mouse click, matching how a mouse
user already gets other feedback a ring would be redundant for) fixes this
for every interactive element on both pages at once, not just the topology
map. Verified with a screenshot after focusing a node: a clear ring around
it, visually distinct from the thinner border the *selected* (not merely
focused) node already had.

## The ML predictor: efficiency and security together

`server/ml_predictor.py` is a genuinely-trained model, not a label attached to
existing logic. What it does: predicts how many vehicles will arrive at one
approach in the next detection tick (~2 seconds), from that approach's recent
arrival history, the current traffic-load setting, and its junction's real-world
calibration factor (see above). `orchestrator.py` adds that forecast to the
current queue when deciding whether to switch a phase, so the signal can start
favoring a side slightly before it's visibly backed up, not only after — closer
to how ITC's own product is described publicly (predicting and adapting to
demand, not just reacting to it).

**How it's trained.** A single linear regression model, shared across every
intersection and approach, trained online via gradient descent from real
simulated traffic for as long as the server runs — every tick is both a
prediction and a training example. It's hand-rolled rather than built on
scikit-learn: that library's native dependency (scipy) is blocked by this
machine's Windows Application Control policy, and a from-scratch implementation
keeps the model as transparent as everything else in this project. It's warm-
started at server startup with a short offline training pass sampled from the
same arrival distribution the live simulator uses, so predictions are sane
immediately rather than needing several minutes of live data to become useful.

**A security implication that falls directly out of the architecture, not
bolted on afterward:** the model trains on every accepted telemetry event,
legitimate or forged, through the same `apply_telemetry()` path described above
(no special trusted path, by design). A successful Sensor Spoofing — Congestion
attack doesn't just distort the instant queue estimate the way it always did —
it also nudges what the predictor has learned, meaning a sustained poisoning
campaign leaves a trace in the model's behavior even after the individual fake
reports are gone. This is a real, general property of any system that learns
from telemetry it also has to defend, not specific to traffic control.

**Verified while building it, not assumed:** a naive version of this model's
warm-up training measurably failed to reliably learn that Tel Aviv's genuinely
busier junctions (Kaplan-Begin, Namir-Einstein) should predict more traffic —
tested across 15 different random seeds, it got the direction of that
relationship wrong nearly as often as right, because the training data's
features were collinear enough that the model could explain outcomes without
using the real-world calibration factor at all. Fixed with a dedicated
calibration pass trained on the known expected value for each scenario instead
of a noisy sample of it (see `ml_predictor.py`'s `_calibrate_volume_factor` for
the full reasoning); re-verified across 30 seeds and a live 3-minute sample of
the running network, both confirming Kaplan-Begin and Namir-Einstein — the two
junctions with an independently-published real vehicle count — consistently ran
busiest.

## Congestion logic: gap-out early termination

Before this pass, every green phase held for a fixed `MIN_GREEN_SECONDS`
(6 seconds) no matter what was actually happening on that approach, real
demand or none. `orchestrator.py` now models a standard, real technique from
actuated traffic-signal control: **gap-out**. Real actuated controllers run
"vehicle extension" logic, a green phase is extended only as long as vehicles
keep arriving, and terminates early, before its nominal minimum, once
detection shows a genuine gap. `_decide_phase` now does the same thing using
the exact same current-queue-plus-ML-forecast score already used for the
ordinary switch decision: if the green side's score is negligible and the red
side actually has waiting demand, the phase ends early, down to a
`GAP_OUT_MIN_GREEN_SECONDS` safety floor (2 seconds), never below it. This
directly makes the network more efficient under light or asymmetric load,
exactly the "congestion logic efficiency" a live network is supposed to
demonstrate, not just a security feature.

**A real bug this surfaced, found by testing, not inspection:** once past
`MIN_GREEN_SECONDS`, the only thing that can still switch a phase is
`SWITCH_MARGIN` (one side's score must beat the other's by this much). It was
`1.5`, sized before the rest of the simulation's queue scale got tuned down
through this project's work; live testing showed real, sustained one-sided
queues (one side idle, the other with a car waiting — a ~1.0 imbalance) never
cleared that bar, so a junction could sit on one phase indefinitely with clear
waiting demand on the other side. Confirmed live: `begin_hashalom` stuck on
`EW_GREEN` for 12+ seconds with `NS` queue at 1.0 and `EW` at 0.0. Lowered to
`0.75` — high enough to still ignore sub-vehicle prediction noise, low enough
to reliably act on a genuine imbalance. Verified over 30 seconds live: all
five junctions now switch roughly every 6-7.5 seconds (matching the minimum-
green floor, not flapping every tick).

## Congestion index: worst junction, worst approach, not an average

Two layers of the same problem, fixed in two passes once testing showed the
first pass wasn't enough on its own.

**Network-wide.** The "Congestion index" KPI used to average all five
junctions' own `congestion_index()` values. That average was itself a
deliberate fix for an earlier correlation bug — but it has a real cost: one
junction genuinely saturated to 100% only moves a 5-junction average by
about 20 points, reading as "attacks barely register" even when the attack
fully worked. Changed to the **maximum** across junctions instead, the same
"worst-first" principle the status banner already uses (`SEVERITY_RANK` in
`app.js`): a severe, real incident at one junction is a severe, real
incident for the network, not diluted by four calm ones.

**Per-junction.** That alone still wasn't enough: a single junction's own
`congestion_index()` was the *total* queue across all four approaches
divided by a separate reference point, so one attacked approach (capped at
`MAX_QUEUE_PER_APPROACH`) only reached about 50-60% on its own junction —
a real, clearly-elevated signal, but not the "100% under a real attack" a
security dashboard should show. Redefined to the **busiest single
approach's** own queue relative to its own hard cap, not a sum against a
separate constant. This isn't just a demo convenience: real traffic
engineering rates an intersection's level of service by its worst/critical
movement, not an average across every approach, so a single successful
spoof-congestion attack (which saturates exactly one approach to its cap)
now reads as fully saturated on its own, matching what actually happened.
Verified live, full cycle: baseline 0% → one default attack on one approach
→ **100%**, immediately → Restore Normal Operation → 0%.

## Forecast playback: five real issues, found by watching it, not by inspection

The Live Monitor's forecast animation went through five genuinely distinct
failure modes before landing on its current design, each one found by
actually watching it run, several of them real regressions a fix for the
previous one introduced:

1. **Chaotic motion.** The original version drove the forecast canvas the
   same way live traffic is driven: `reconcile()` sets a target car count,
   then the shared 40ms `tick()`/`draw()` loop smoothly interpolates cars
   toward it. That works live because `reconcile()` only runs once every ~2
   real seconds (a WebSocket update), leaving ~50 animation frames to glide
   into position before the next one arrives. During forecast playback
   `reconcile()` instead ran every 90ms — only ~2 frames of headroom — so
   cars snapped and reshuffled at high frequency: reported as "the car
   simulator goes crazy."
2. **No motion at all.** The fix for (1) dropped interpolation entirely:
   each tick reconciled and drew once, immediately. That traded chaotic
   motion for none — cars only ever popped into position — reported as
   "cars do not go, they just stop."
3. **Strobing lights.** `server/forecast.py` deliberately reuses
   `orchestrator.py`'s exact `_decide_phase` (see its own module docstring:
   the point is a forecast that reflects the real control logic, not a
   second approximation of it), so when `SWITCH_MARGIN` was lowered to fix a
   real "signal stuck on one phase" bug in the *live* simulation, the
   forecast's simulated trajectory inherited the same faster cycling —
   correct, real actuated-signal behavior under heavy, balanced rush-hour
   demand (confirmed live: a rush-hour forecast flips phase every ~3 ticks,
   29 times across 90 ticks). At playback speeds tuned for the old, slower
   trajectory, that compressed into a phase flip every few hundred ms of
   real time — reported as "everything just becomes bugged" and "lights
   jump from red to green all the time."

**The actual fix** brings interpolated motion back — cars visibly drive,
stop on red, and pull away on green, exactly like the live view — and gives
it enough real time per tick to work with (`reconcile()` now only sets the
next target once per simulated tick; the shared 40ms loop does the
continuous `tick()`/`draw()`, identically to how it already treats live
cards). 1333ms per simulated tick keeps even the fastest legitimate 3-tick
phase on screen for a comfortable ~4 real seconds, and totals 90 ticks ×
1333ms ≈ 2 real minutes for the full 90-tick trajectory — a real, honest
~1.5x fast-forward rather than a 15x compression that only worked by not
looking like traffic.

**A fourth issue, found the same way:** a forecast's disposable junction
always starts from a genuinely empty, `ALL_RED` slate (see
`forecast_congestion`'s own comment for why), which meant the *first* real
seconds of every recorded playback showed empty roads gradually filling in —
correct given where the simulation starts, but not "the traffic of this
hour" from frame one, reported as "all that happens is lights switching."
Fixed with a silent `WARM_UP_TICKS` period (40 ticks, not included in the
returned `ticks` or its throughput/congestion averages) that runs before
recording starts, so the played-back window begins from a state the queues
would actually be in a couple of minutes into that hour. Verified live: a
17:00 forecast's very first recorded tick already shows queues at 6-8
vehicles per approach, not zero, and stays consistently busy (queue-sum
27-28 out of a possible 32) across the entire recorded trajectory; a 03:00
forecast, by contrast, correctly stays near-empty throughout (queue-sum
0.2-0.8) — the warm-up settles to whatever is actually representative for
the requested hour, not an inflated floor.

**A fifth issue**: the ~2-minute total playback from the fix above was
reported as feeling "stuck." Requested down to a firm ~20 seconds — but
simply compressing `FORECAST_TICK_PLAYBACK_MS` further to hit that would
have walked straight back into failure mode 3 (phases legitimately flip
every 3 ticks under heavy demand; anything under roughly 600ms/tick starts
reading as flickering again, not watchable traffic). Reduced
`forecast.py`'s `FORECAST_TICKS` itself from 90 to 30 instead — fewer ticks
played back, not each one rushed — paired with `FORECAST_TICK_PLAYBACK_MS`
at 650ms. `WARM_UP_TICKS` is untouched, so the shorter recorded window still
starts from the same realistic, already-busy state. Also added a genuine
`try`/`finally` around the animation loop in `monitor.js`, so
`forecastPlaying` can never get stuck `true` regardless of cause — a
defensive fix, not a diagnosed one, since "stuck" turned out on testing to
just mean "very long," but a real safety net either way. Verified live: 30
ticks, 10 phase switches (matching the 3-tick cadence), a phase held
readable on screen for a full 1.5 real seconds mid-forecast, total playback
21.2 seconds end to end, and the card correctly hands back to live rendering
(hour badge shows the live hour again, not stuck on the forecasted one)
immediately after.

## Disconnected-state banner

Restarting the server (needed for every backend fix above) silently kills any
browser tab's open WebSocket connection, and the only prior signal was a
small header dot changing color — easy to miss, and repeatedly misread as a
logic bug in whatever happened to be on screen when the connection dropped,
since every panel just keeps showing its last-received data, frozen, with no
other indication. Both pages now show a loud, sticky banner ("⚠️ Lost
connection to the server — everything below is frozen, not live.
Reconnecting…") the instant the socket closes, and dim/desaturate the rest of
the page so stale content reads as visibly inert. Verified with a real
WebSocket client: killing the server process fires the `close` event
immediately, which is what drives this.

## No-cache headers: the browser-caching gap behind the disconnected-state banner too

A related, quieter version of the same class of problem: `StaticFiles`
ships `ETag`/`Last-Modified` but no `Cache-Control` header at all, leaving
the browser free to apply its own heuristic freshness window and skip even
asking the server whether a file changed. During active development —
`web/*.js` edited and the server restarted repeatedly, sometimes minutes
apart — a plain refresh (not a hard refresh) could keep showing behavior
from before the latest fix. That repeatedly got misread as a fix being
wrong, reverted, or never actually applied, when the code being served
(re-verified directly against the running server each time) was correct
the whole time; the disconnected-state banner above covers the WebSocket
half of "the page looks live but isn't," this covers the static-file half.

A small `@app.middleware("http")` in `main.py` now sets
`Cache-Control: no-cache, must-revalidate` on every response. `no-cache`,
deliberately not `no-store`: still allows a fast `304 Not Modified` when a
file genuinely hasn't changed (via the existing `ETag`), this only forces
the revalidation round-trip to actually happen on every load instead of
being silently skipped.

## Time of day and the ML Forecast tool

**A real hourly traffic curve underneath three simple buttons.** The main
dashboard's Zone 3 keeps the original Light / Normal / Rush Hour control, but
each button is now really just a representative hour (03:00 / 14:00 / 17:00)
handed to `/api/hour`, backed by `tel_aviv_data.py`'s
`HOURLY_TRAFFIC_MULTIPLIER` — a 24-value curve following the standard bimodal
urban-commute shape every source consulted while researching it agreed on
(low overnight, a morning peak around 07:00-09:00, a midday dip with a small
lunch bump, a larger evening peak around 16:00-18:00) — see the module for the
sources on that shape, and for why the exact numbers are labeled a reasonable
modeling choice rather than a measured Tel Aviv statistic no source actually
published. There's a single hourly curve and a single `/api/hour` endpoint
either way; the three buttons are just a simpler front door onto the same 24
hours the Live Network Monitor's forecast tool (below) can pick from
individually.

**The ML Forecast tool** lives on the Live Network Monitor page, one instance
per junction card, and answers "if it were this hour right now, what would
this junction look like?" without touching the live simulation.
`server/forecast.py` fast-forwards a disposable copy of the junction through
90 simulated ticks using the exact same trained predictor and the exact same
phase-decision/serving logic the live orchestrator runs (reused directly, not
reimplemented), fed the chosen hour's traffic intensity instead of whatever
the live network is currently set to. It was originally on the main
dashboard too; moved to the Monitor page to keep the attack-console page
focused on one job (pick a target, attack it) rather than growing a second,
unrelated "what if" tool alongside it.

**A second thing this surfaced and fixed while building it, not shipped
unnoticed:** once the ML predictor was wired into a query tool people could hit
repeatedly, a real instability became visible that the live dashboard alone
had been masking — asking for the same hour's forecast a minute apart could
give meaningfully different answers, because the model was training on every
single live tick forever at a constant learning rate, and constant-rate SGD on
noisy individual real-world outcomes (the same single-Bernoulli-trial noise
problem the warm-up calibration pass above works around) never actually
converges, it just keeps jittering. Fixed by decaying the learning rate for
live updates as more of them accumulate (`LIVE_LEARNING_RATE_DECAY` in
`ml_predictor.py`); warm-up itself is untouched and unaffected. Verified, not
assumed: after roughly 3-4 minutes of live updates, repeated forecasts for the
same hour now settle to within about 5% of each other, while a sustained
pattern shift (standing in for a real, sustained spoof-congestion campaign)
still measurably moves the model afterward — so the security property this
model exists to support didn't get traded away for stability.

## Live Network Monitor

A second page (`monitor.html`, linked from the main dashboard's header)
showing all five junctions animating simultaneously, each with its own live
car-simulation canvas, health badge, phase, and congestion meter, plus its own
ML Forecast controls, all on the same live WebSocket feed. It has no attack
console, mode toggle, or incident-response playbook: purely observational, a
"what's happening across the whole corridor right now" view, deliberately kept
separate from the attack console rather than crammed into one increasingly
dense page. The car-simulation rendering itself (`car-sim.js`) is the exact
same code the main dashboard's single canvas uses, pulled into its own shared
module specifically so both pages behave identically rather than risking two
copies drifting apart.

**The forecast plays out on the actual junction canvas, not just as a number.**
`server/forecast.py` returns its full tick-by-tick trajectory (`ticks`:
queues, phase, and congestion at every one of the 90 simulated ticks), and
each monitor card's Forecast button steps its car-simulation canvas through
that trajectory, roughly 22 seconds to watch a full 3-simulated-minute
forecast build up and clear (see "Forecast playback speed" below for why
that's slower than it sounds like it needs to be). Each canvas also carries
a small hour badge in
its top-right corner, normally the network's live simulated hour, so what
you're looking at and the time of day it represents are always correlated,
and swapped to a distinct accent color showing the forecasted hour for the
duration of an animation, so a forecast can never be mistaken for live
traffic.

**A bug this surfaced and fixed, not shipped unnoticed:** the first version of
this drove the canvas the same way live traffic does — `reconcile()` sets a
target car count, then a separate 40ms loop smoothly interpolates cars toward
it. That works live because `reconcile()` only runs once every ~2 real
seconds (a WebSocket update), leaving ~50 animation frames to glide into
position before the next one lands. During forecast playback `reconcile()`
was instead running every 90ms, only ~2 frames of headroom, while the
underlying queue values legitimately jump tick to tick (a light change can
clear a queue in one step). Cars had no time to glide before their target
moved again, so they visibly snapped and reshuffled at high frequency instead
of flowing — a genuinely broken animation, not a stylistic complaint. Fixed
by dropping the smooth-interpolation attempt during playback entirely:
each simulated tick now reconciles and draws once, directly, so what's on
screen is exactly "how many cars are queued right now," a clean readable
step rather than a failing animation (`playForecastAnimation` in
`monitor.js`).

## Live request payloads

The attack console's Zone 3 shows the exact JSON body Execute is about to
POST, live, for whichever attack type and target are currently selected,
updating on every relevant field change. It is generated by the same function
(`buildAttackPayload` in `app.js`) that actually sends the request, not a
separately-maintained example, so the preview can never say something
different from what really goes out over the wire. Deliberately just the raw
request — nothing appended below it — so it answers exactly one question:
what literally goes out over the wire.

## Live demo script

1. **Normal operation.** Open the dashboard. Five junctions, all healthy,
   queues low and stable, KPIs in a comfortable range. Mode boots into "Legacy
   Retrofit" by default (see `Network.__init__` in `network.py`), so the
   network is already running unauthenticated, exactly the state the attack
   below needs, with nothing to switch first.
2. **Point out Kaplan-Begin and Namir-Einstein running busier.** Click either
   junction; the detail card shows its real, cited traffic-volume source, and
   its queue bars run measurably higher than Rokach-Yehudit's over time — the
   simulation is calibrated from real research, not uniform across all five.
3. **Show the ML prediction.** Point at the lighter cap above each queue bar:
   the ML predictor's live forecast for that approach's next few seconds,
   trained continuously from the traffic you're watching, not canned.
4. **Attack it.** From Simulation Controls, run a Command Injection against any
   junction. Its map node turns critical, the status banner in its detail card
   reads "Collision risk," and the security event table logs it as T0855.
5. **Show the AI orchestrator noticing.** Point out the congestion trend chart
   and the active-incidents KPI both moving — this isn't a canned animation,
   it's the same control loop that runs the network reacting to a junction it
   can no longer safely manage.
6. **Respond.** In the Incident Response Playbook panel, click **Fail-Safe
   Flash** to stabilize it, then **Restore Normal Operation** to hand it back
   to the AI.
7. **Switch on ITC Secure Integration.** The toggle resets the network to a
   clean baseline.
8. **Repeat the attack.** Same Command Injection — rejected outright, logged as
   a warning, junction keeps running normally.
9. **Show the flood response.** Run a Flood attack. Watch the Telemetry &
   Anomaly Detection panel's channel-load meter climb in real time, then the
   security table show the auto-block and the map node go "Isolated" — held
   safe by itself, no operator action needed — then automatically recover
   ~25 seconds later.
10. **(Optional, technical audience)** Run Sensor Spoofing — Congestion in
    Legacy mode against a healthy junction and watch its queue bar jump
    instantly and the AI orchestrator visibly skew that junction's timing in
    response — then show the same request rejected in Secure mode. Point out
    that the ML predictor trained on that same forged report, too — the attack
    left a trace in what the model has learned, not just in the instant queue.
11. **Show the request payload.** Pick any attack type and point at the
    "Request payload" box in Simulation Controls — this is the literal JSON
    Execute is about to send, not a mockup.
12. **Coordinated attack.** Check "Coordinated," pick any attack type, hit
    Execute once — all five junctions get hit simultaneously in one click, a
    much more severe, more realistic pattern than attacking a single node.
13. **Open the Live Network Monitor** (header button, or a second browser
    tab). All five junctions animating at once, live, off the same WebSocket
    the dashboard uses — a good place to actually see a Coordinated attack's
    effect across the whole corridor at a glance. Pick an hour on any card and
    hit **Forecast** to watch that junction's canvas fast-forward through a
    full 3-simulated-minute forecast for that hour, without touching the live
    network at all.
