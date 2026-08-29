/*
 * monitor.js
 *
 * ITC Live Network Monitor: a second, simpler page showing all five
 * junctions animating at once in real time, separate from the main SOC
 * dashboard (index.html/app.js), which stays focused on one junction
 * at a time as the "attack simulator" view (pick a target, watch it).
 * Same server, same WebSocket, same car-sim.js renderer as that page,
 * just five independent instances running side by side instead of
 * one, and no attack console, command-injection form, or incident-
 * response playbook here at all: purely observational.
 */

const connectionStatusEl = document.getElementById("connection-status");
const connectionStatusTextEl = document.getElementById("connection-status-text");
const disconnectedBannerEl = document.getElementById("disconnected-banner");
const statusBannerEl = document.getElementById("status-banner");
const statusBannerIconEl = document.getElementById("status-banner-icon");
const statusBannerTextEl = document.getElementById("status-banner-text");
const kpiCongestionEl = document.getElementById("kpi-congestion");
const monitorGridEl = document.getElementById("monitor-grid");

const HEALTH_LABELS = { good: "Normal", warning: "Fail-safe", serious: "Isolated", critical: "Collision risk" };
const SEVERITY_RANK = { critical: 0, serious: 1, warning: 2, good: 3 };

/* Same thresholds app.js's KPI tile uses for this exact metric, kept
   as its own copy here since this page doesn't load app.js. */
function severityClassFor(value, warnAt, criticalAt) {
  if (value >= criticalAt) return "stat-value-critical";
  if (value >= warnAt) return "stat-value-warning";
  return "stat-value-good";
}

/* Same meter-coloring logic as app.js's setSeverityMeter, kept as its
   own copy here for the same reason: this page doesn't load app.js. */
function setSeverityMeter(el, value, referenceMax) {
  const pct = Math.max(2, Math.min(100, (value / referenceMax) * 100));
  el.style.width = `${pct}%`;
  el.classList.remove("meter-elevated", "meter-critical");
  if (pct >= 90) el.classList.add("meter-critical");
  else if (pct >= 55) el.classList.add("meter-elevated");
}

let currentNetwork = null;
let gridBuilt = false;
/* One independent car-sim renderer per junction, keyed by intersection
   id, plus references to that card's other live-updating elements.
   Built once, the first time a network snapshot arrives (see
   buildGridOnce), then reused for the life of the page: the DOM nodes
   are never rebuilt on later updates, only their text/canvas content. */
const cards = {};

function buildGridOnce() {
  if (gridBuilt || !currentNetwork) return;

  currentNetwork.intersections.forEach((intersection) => {
    const card = document.createElement("section");
    card.className = "monitor-card";
    card.setAttribute("aria-label", intersection.name);

    const header = document.createElement("div");
    header.className = "monitor-card-header";
    const name = document.createElement("h3");
    name.textContent = intersection.name;
    const health = document.createElement("span");
    health.className = "health-badge";
    header.appendChild(name);
    header.appendChild(health);
    card.appendChild(header);

    const stats = document.createElement("div");
    stats.className = "monitor-stats-row";
    const phase = document.createElement("span");
    stats.appendChild(phase);
    card.appendChild(stats);

    /* This junction's own congestion, as a small visual meter, not
       just a number: reuses the exact same .local-congestion-row /
       .meter-track / .meter-fill structure and setSeverityMeter
       coloring the main dashboard's detail card uses, so a glance at
       either page reads the same way. */
    const congestionRow = document.createElement("div");
    congestionRow.className = "local-congestion-row";
    const congestionLabel = document.createElement("span");
    congestionLabel.textContent = "Congestion";
    const congestionTrack = document.createElement("div");
    congestionTrack.className = "meter-track";
    const congestionFill = document.createElement("div");
    congestionFill.className = "meter-fill";
    congestionTrack.appendChild(congestionFill);
    const congestionValue = document.createElement("span");
    congestionValue.className = "channel-value";
    congestionRow.appendChild(congestionLabel);
    congestionRow.appendChild(congestionTrack);
    congestionRow.appendChild(congestionValue);
    card.appendChild(congestionRow);

    /* Wraps the canvas so the hour badge can sit absolutely positioned
       in its top-right corner: normally the network's live simulated
       hour, so the picture and the time it represents are always
       readable together; swapped to the forecasted hour, styled
       differently, for the duration of a forecast animation (see
       playForecastAnimation). */
    const canvasWrap = document.createElement("div");
    canvasWrap.className = "monitor-canvas-wrap";

    const canvas = document.createElement("canvas");
    canvas.width = 300;
    canvas.height = 300;
    canvas.className = "monitor-canvas";
    canvas.setAttribute("aria-label", `Live view of ${intersection.name}`);
    canvasWrap.appendChild(canvas);

    const hourBadge = document.createElement("span");
    hourBadge.className = "hour-badge";
    canvasWrap.appendChild(hourBadge);

    card.appendChild(canvasWrap);

    /* ML Forecast: same idea and same server/forecast.py endpoint as
       the main dashboard's detail card, just one instance per junction
       here instead of one shared instance for whichever junction is
       selected there, since this page shows all five at once with
       nothing "selected." */
    const forecastControls = document.createElement("div");
    forecastControls.className = "forecast-controls";

    const hourSelect = document.createElement("select");
    hourSelect.setAttribute("aria-label", `Hour to forecast for ${intersection.name}`);
    for (let hour = 0; hour < 24; hour++) {
      const option = document.createElement("option");
      option.value = String(hour);
      option.textContent = `${String(hour).padStart(2, "0")}:00`;
      hourSelect.appendChild(option);
    }

    const forecastBtn = document.createElement("button");
    forecastBtn.type = "button";
    forecastBtn.className = "btn";
    forecastBtn.textContent = "Forecast";

    forecastControls.appendChild(hourSelect);
    forecastControls.appendChild(forecastBtn);
    card.appendChild(forecastControls);

    const forecastResult = document.createElement("div");
    forecastResult.className = "forecast-result";
    forecastResult.hidden = true;
    card.appendChild(forecastResult);

    forecastBtn.addEventListener("click", async () => {
      forecastBtn.disabled = true;
      try {
        const hour = Number(hourSelect.value);
        const response = await fetch("/api/forecast", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ intersection_id: intersection.id, hour }),
        });
        const result = await response.json();
        renderForecastResult(forecastResult, result, hour);
        if (result.ok && result.ticks) {
          await playForecastAnimation(cards[intersection.id], result, hour);
        }
      } finally {
        forecastBtn.disabled = false;
      }
    });

    monitorGridEl.appendChild(card);

    cards[intersection.id] = {
      healthEl: health,
      phaseEl: phase,
      congestionFillEl: congestionFill,
      congestionValueEl: congestionValue,
      hourBadgeEl: hourBadge,
      renderer: createCarSimRenderer(canvas),
      // While true, the shared animation loop below draws this card
      // from forecastDisplayState instead of live network data, and
      // the live hour badge/stats updates leave this card alone: set
      // and cleared only by playForecastAnimation.
      forecastPlaying: false,
      forecastDisplayState: null,
    };
  });

  gridBuilt = true;
}

/* Real ms of wall-clock time per simulated forecast tick during
   playback.

   Two earlier versions of this got the balance between "readable" and
   "fast" wrong in opposite directions, both found by watching it, not
   by inspection:

   1. 90ms/tick, driven the same way live traffic is: reconcile() sets
      the target car count, then the shared 40ms tick()/draw() loop
      smoothly interpolates cars toward it. That works live because
      reconcile() only runs once every ~2 real seconds (a WebSocket
      update), leaving ~50 animation frames to glide into position
      before the next one arrives. At 90ms/tick there were only ~2
      frames of headroom, so cars snapped and reshuffled at high
      frequency instead of flowing: the "goes crazy" bug.
   2. The fix for that dropped interpolated motion entirely -- each
      tick reconciled AND drew once, immediately, no gliding at all.
      That traded "chaotic motion" for "no motion": cars only ever
      popped directly into their new positions, correctly described as
      "cars do not go, they just stop." At 130ms, then even at 250ms
      after a later constant change (see below) made phases switch
      faster, holding each frame just long enough to read the number
      still wasn't the same thing as watching traffic move.

   The actual fix is to bring interpolation back (so cars visibly
   drive, stop on red, and pull away on green, exactly like the live
   view), and give it enough real time per tick to work with, the same
   ~50-frame ratio the live view gets for free. reconcile() below now
   only sets the next target once per tick; the shared 40ms loop (see
   its own comment) does continuous tick()/draw() for forecasting cards
   exactly like it already does for live ones.

   That got total playback time up to ~2 minutes (90 ticks), which was
   then reported as feeling "stuck" and asked to come down to a firm
   ~20 seconds. Rather than compress each tick's own playback time
   further to hit that (which would reintroduce exactly the two
   failures above -- forecast.py reuses orchestrator.py's exact
   decision logic, so under heavy demand it legitimately cycles phases
   every 3 ticks, MIN_GREEN_SECONDS' worth, and anything much under
   ~600ms/tick starts making that read as flickering again, not
   watchable traffic), forecast.py's FORECAST_TICKS itself came down
   from 90 to 30 -- fewer ticks played back, not each one rushed.
   650ms/tick keeps a 3-tick minimum phase on screen for just under 2
   real seconds, still comfortably readable, and 30 ticks * 650ms =
   19.5s lands right at the requested ~20 seconds. */
const FORECAST_TICK_PLAYBACK_MS = 650;
/* How long to hold the final frame, badge still showing the forecasted
   hour, before handing the card back to live rendering. */
const FORECAST_HOLD_MS = 1200;

/* Steps `card`'s renderer through a forecast's full tick-by-tick
   trajectory (server/forecast.py's `ticks`), so a forecast is
   something you watch play out on the actual junction canvas, not just
   a number. Updates the card's phase/congestion stats and hour badge
   in lockstep with the animation, then hands the card back to live
   rendering once it's done.

   Only calls reconcile() here, once per simulated tick: the shared
   40ms loop below does the actual tick()/draw() continuously, exactly
   like it does for live traffic, so cars smoothly drive toward
   whatever reconcile() last set instead of teleporting to it. */
async function playForecastAnimation(card, result, hour) {
  if (!card) return;
  card.forecastPlaying = true;
  card.renderer.reset();
  card.hourBadgeEl.textContent = `${String(hour).padStart(2, "0")}:00 (forecast)`;
  card.hourBadgeEl.classList.add("hour-badge-forecast");

  /* try/finally as a genuine safety net, not just tidiness: without it,
     any unexpected exception mid-loop (a malformed tick, a DOM node
     removed out from under this) would leave forecastPlaying stuck
     true forever, since nothing after the loop would ever run --
     exactly the shape of "now it is stuck on forecast" if the cause
     ever turns out to be that rather than the ~2-minute duration this
     same report also asked to shorten. Whatever happens, the card
     always gets handed back to live rendering. */
  try {
    for (const tickState of result.ticks) {
      const displayState = { phase: tickState.phase, alarm: null, queues: tickState.queues };
      card.forecastDisplayState = displayState;
      card.renderer.reconcile(displayState);

      card.phaseEl.innerHTML = "";
      card.phaseEl.appendChild(document.createTextNode("Phase: "));
      const phaseStrong = document.createElement("strong");
      phaseStrong.textContent = tickState.phase.replace("_", " ");
      card.phaseEl.appendChild(phaseStrong);

      card.congestionValueEl.textContent = `${tickState.congestion_index.toFixed(0)}%`;
      setSeverityMeter(card.congestionFillEl, tickState.congestion_index, 100);

      await new Promise((resolve) => setTimeout(resolve, FORECAST_TICK_PLAYBACK_MS));
    }
    await new Promise((resolve) => setTimeout(resolve, FORECAST_HOLD_MS));
  } finally {
    card.forecastPlaying = false;
    card.forecastDisplayState = null;
    card.hourBadgeEl.classList.remove("hour-badge-forecast");
    /* render() only runs on the next network update; nudge the badge
       and stats back to live values immediately instead of leaving the
       last forecast frame showing until one happens to arrive. */
    if (currentNetwork) render();
  }
}

/* Renders one /api/forecast response into `container`. A local copy of
   app.js's renderForecastResult, parameterized by container instead of
   a single fixed element: this page needs one of these per junction
   card rather than one shared result panel. */
function renderForecastResult(container, result, hour) {
  const label = `${String(hour).padStart(2, "0")}:00`;
  container.innerHTML = "";

  if (!result.ok) {
    container.appendChild(document.createTextNode("Couldn't run that forecast."));
    container.hidden = false;
    return;
  }

  const congestionLine = document.createElement("p");
  congestionLine.appendChild(document.createTextNode(`At ${label}, forecast to settle around `));
  const congestionStrong = document.createElement("strong");
  congestionStrong.textContent = `${result.congestion_index.toFixed(0)}% congested`;
  congestionLine.appendChild(congestionStrong);
  congestionLine.appendChild(document.createTextNode("."));
  container.appendChild(congestionLine);

  const throughputLine = document.createElement("p");
  throughputLine.textContent = `~${result.forecast_throughput_per_hour.toLocaleString()} vehicles/hour.`;
  container.appendChild(throughputLine);

  container.hidden = false;
}

/* Same worst-junction-wins logic as app.js's renderStatusBanner, kept
   as its own copy here (this page has no other shared dependency on
   app.js) but reworded: this page has no mode toggle or attack
   console, so it describes what is happening, not what button to
   press next. */
function renderStatusBanner() {
  const intersections = currentNetwork.intersections;
  let worst = "good";
  for (const intersection of intersections) {
    if (SEVERITY_RANK[intersection.health] < SEVERITY_RANK[worst]) {
      worst = intersection.health;
    }
  }

  statusBannerEl.className = `status-banner status-${worst}`;

  if (worst === "good") {
    statusBannerIconEl.textContent = "✅";
    statusBannerTextEl.textContent = "Network normal — all 5 junctions running automatically. No active incidents.";
    return;
  }

  const affected = intersections.filter((i) => i.health === worst);
  const names = affected.map((i) => i.name).join(", ");
  const plural = affected.length > 1 ? "s" : "";

  if (worst === "critical") {
    statusBannerIconEl.textContent = "🚨";
    statusBannerTextEl.textContent = `COLLISION RISK at ${names}: conflicting green lights are currently showing.`;
  } else if (worst === "serious") {
    statusBannerIconEl.textContent = "🔒";
    statusBannerTextEl.textContent = `${affected.length} junction${plural} isolated: ${names}. Held safe, recovers automatically.`;
  } else {
    statusBannerIconEl.textContent = "⚠️";
    statusBannerTextEl.textContent = `${affected.length} junction${plural} in fail-safe: ${names}. Flashing red as a precaution.`;
  }
}

function render() {
  if (!currentNetwork) return;
  buildGridOnce();
  renderStatusBanner();

  const congestion = currentNetwork.kpis.congestion_index;
  kpiCongestionEl.textContent = `${congestion.toFixed(0)}%`;
  kpiCongestionEl.className = `stat-value ${severityClassFor(congestion, 30, 70)}`;

  currentNetwork.intersections.forEach((intersection) => {
    const card = cards[intersection.id];
    if (!card) return;

    card.healthEl.textContent = HEALTH_LABELS[intersection.health];
    card.healthEl.className = `health-badge health-${intersection.health}`;

    /* A forecast animation owns this card's phase/congestion/car-sim
       state and its hour badge while it plays (see
       playForecastAnimation); leave all of that alone here so live
       updates don't fight the animation mid-playback. Health above is
       still fine to update: it reflects real live incidents (attacks,
       isolation), which are worth showing even while a forecast for
       that junction happens to be playing. */
    if (card.forecastPlaying) return;

    card.hourBadgeEl.textContent = `${String(currentNetwork.simulated_hour).padStart(2, "0")}:00`;

    card.phaseEl.innerHTML = "";
    card.phaseEl.appendChild(document.createTextNode("Phase: "));
    const phaseStrong = document.createElement("strong");
    phaseStrong.textContent = intersection.phase.replace("_", " ");
    card.phaseEl.appendChild(phaseStrong);

    card.congestionValueEl.textContent = `${intersection.congestion_index.toFixed(0)}%`;
    setSeverityMeter(card.congestionFillEl, intersection.congestion_index, 100);

    /* Only reconciles the target car count here; tick()/draw() run on
       their own fast animation loop below so motion stays smooth
       between these (much less frequent) network updates. */
    card.renderer.reconcile(intersection);
  });
}

/* WebSocket connection: the same pattern app.js uses, kept as its own
   copy since this page doesn't load app.js at all. */
function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

  ws.addEventListener("open", () => {
    connectionStatusEl.classList.add("connected");
    connectionStatusTextEl.textContent = "live";
    disconnectedBannerEl.hidden = true;
    document.body.classList.remove("page-stale");
  });

  ws.addEventListener("message", (event) => {
    const payload = JSON.parse(event.data);
    if (payload.type === "snapshot" || payload.type === "update") {
      currentNetwork = payload.network;
      render();
    }
  });

  ws.addEventListener("close", () => {
    connectionStatusEl.classList.remove("connected");
    connectionStatusTextEl.textContent = "reconnecting…";
    disconnectedBannerEl.hidden = false;
    document.body.classList.add("page-stale");
    setTimeout(connectWebSocket, 1500);
  });
}

/* Animates all five canvases continuously, on the same 40ms cadence
   app.js uses for its one canvas, so this page doesn't feel visibly
   choppier than the main dashboard. Nothing here can be paused by an
   educational pop-up the way app.js's can: this page has no attack
   console to open one from.

   A card mid-forecast-animation is driven from its own
   forecastDisplayState (updated once per simulated tick by
   playForecastAnimation) instead of live network data, so the canvas
   shows the forecast's cars actually driving rather than snapping
   between positions or freezing on live traffic mid-playback -- see
   FORECAST_TICK_PLAYBACK_MS's comment for why this needed to come back
   after an earlier version deliberately removed it. */
setInterval(() => {
  if (!currentNetwork) return;
  currentNetwork.intersections.forEach((intersection) => {
    const card = cards[intersection.id];
    if (!card) return;
    const displayState = card.forecastPlaying ? card.forecastDisplayState : intersection;
    if (!displayState) return;
    card.renderer.tick(displayState);
    card.renderer.draw(displayState);
  });
}, 40);

/* Initial load: an immediate REST snapshot so the grid isn't blank for
   the brief moment before the WebSocket finishes connecting, exactly
   like app.js's loadInitialState(). */
async function loadInitialState() {
  const response = await fetch("/api/network");
  currentNetwork = await response.json();
  render();
}

loadInitialState();
connectWebSocket();
