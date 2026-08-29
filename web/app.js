/*
 * app.js
 *
 * Frontend for the ITC digital-twin SOC dashboard.
 *
 * One WebSocket connection keeps a local copy of the server's full
 * network snapshot in sync; every render function below reads from that
 * single `currentNetwork` object, so there is one source of truth and
 * no risk of panels disagreeing with each other.
 *
 * The attack console and the standalone attacker.py script call the
 * exact same public endpoints (/api/command, /api/telemetry) with no
 * signature: there is no special-cased "trusted UI" path, which is
 * the point of the demo.
 *
 * Beyond the live data panels, this file also drives three things aimed
 * squarely at making the dashboard understandable with zero background:
 *   1. A small canvas "live view" of the selected junction: cars that
 *      actually move, stop on red, and visibly pile up under attack.
 *   2. An educational pop-up shown every time an attack is executed,
 *      explaining what it is, how it affects a real system, and what
 *      just happened, before the dashboard moves on.
 *   3. A guided incident-response cue: after an attack gets through, the
 *      one playbook button that actually addresses it glows, with a
 *      plain-language hint above it, so "what do I click next" is never
 *      a guess.
 */

const SVG_NS = "http://www.w3.org/2000/svg";

/* Element references */

const connectionStatusEl = document.getElementById("connection-status");
const connectionStatusTextEl = document.getElementById("connection-status-text");
const disconnectedBannerEl = document.getElementById("disconnected-banner");
const modeSwitchEl = document.getElementById("mode-switch");
const modeLabelLegacyEl = document.getElementById("mode-label-legacy");
const modeLabelSecureEl = document.getElementById("mode-label-secure");

const legacyInfoBtnEl = document.getElementById("legacy-info-btn");
const legacyInfoPopoverEl = document.getElementById("legacy-info-popover");

const statusBannerEl = document.getElementById("status-banner");
const statusBannerIconEl = document.getElementById("status-banner-icon");
const statusBannerTextEl = document.getElementById("status-banner-text");

const kpiThroughputEl = document.getElementById("kpi-throughput");
const kpiWaitEl = document.getElementById("kpi-wait");
const kpiCongestionEl = document.getElementById("kpi-congestion");
const kpiIncidentsEl = document.getElementById("kpi-incidents");

const topologySvg = document.getElementById("topology-svg");
const selectedNameEl = document.getElementById("selected-name");
const selectedHealthEl = document.getElementById("selected-health");
const selectedPhaseEl = document.getElementById("selected-phase");
const realWorldContextEl = document.getElementById("real-world-context");
const queueBarsEl = document.getElementById("queue-bars");

const junctionCanvas = document.getElementById("junction-canvas");

const trendSvg = document.getElementById("trend-svg");
const trendTooltipEl = document.getElementById("trend-tooltip");
const trendCurrentValueEl = document.getElementById("trend-current-value");

const meterCommandEl = document.getElementById("meter-command");
const meterTelemetryEl = document.getElementById("meter-telemetry");
const channelCommandValueEl = document.getElementById("channel-command-value");
const channelTelemetryValueEl = document.getElementById("channel-telemetry-value");

const attackForm = document.getElementById("attack-form");
const attackTypeEl = document.getElementById("attack-type");
const attackTargetEl = document.getElementById("attack-target");
const attackApproachFieldEl = document.getElementById("attack-approach-field");
const attackApproachEl = document.getElementById("attack-approach");
const attackCountFieldEl = document.getElementById("attack-count-field");
const attackCountEl = document.getElementById("attack-count");
const attackDescriptionEl = document.getElementById("attack-description");
const attackFloodEl = document.getElementById("attack-flood");
const attackFloodCountEl = document.getElementById("attack-flood-count");
const attackCoordinatedEl = document.getElementById("attack-coordinated");
const payloadPreviewEl = document.getElementById("payload-preview");
const attackExecuteEl = document.getElementById("attack-execute");

const hourSegmentedEl = document.getElementById("hour-segmented");
const loadExplanationEl = document.getElementById("load-explanation");

const playbookTargetNameEl = document.getElementById("playbook-target-name");
const playbookHintEl = document.getElementById("playbook-hint");
const playbookFailsafeEl = document.getElementById("playbook-failsafe");
const playbookIsolateEl = document.getElementById("playbook-isolate");
const playbookRestoreEl = document.getElementById("playbook-restore");
const playbookRestoreAllEl = document.getElementById("playbook-restore-all");

const securityEventBodyEl = document.getElementById("security-event-body");
const opsLogListEl = document.getElementById("ops-log-list");

const modalBackdropEl = document.getElementById("attack-modal-backdrop");
const modalTagEl = document.getElementById("modal-tag");
const modalTitleEl = document.getElementById("modal-title");
const modalWhatEl = document.getElementById("modal-what");
const modalHowEl = document.getElementById("modal-how");
const modalOutcomeEl = document.getElementById("modal-outcome");
const modalGuidanceEl = document.getElementById("modal-guidance");
const modalDismissEl = document.getElementById("modal-dismiss");

/* A source distinct from attacker.py's default (203.0.113.7), so if you
   run both the UI console and the CLI tool in the same demo, the event
   feed clearly shows two separate "attackers" rather than one merged
   one. */
const CONSOLE_ATTACKER_SOURCE = "203.0.113.9";

/* Local state */

let currentNetwork = null;
let selectedIntersectionId = null;
let targetSelectPopulated = false;

/* True while the educational pop-up is open. The junction canvas
   animation freezes during this window, per the "pause the simulation
   while explaining it" request. */
let simulationPaused = false;

const ATTACK_DESCRIPTIONS = {
  inject:
    "Sends an unsigned FORCE_ALL_GREEN command straight to the target's command channel: the legacy baseline applies it with no authentication check at all.",
  "spoof-congestion":
    "Reports a single, implausibly large fake vehicle count on one approach, poisoning the AI orchestrator's queue estimate and skewing its timing decisions.",
  "spoof-emergency":
    "Claims a fake emergency vehicle on one approach to force an unearned priority green, modeling real emergency-vehicle-preemption spoofing.",
};

/* Full educational content for the pop-up: what the attack is, how it
   affects a real system, and two possible outcomes depending on whether
   it actually got through. */
const ATTACK_EXPLANATIONS = {
  inject: {
    title: "Command Injection",
    what: "An unsigned command was sent straight to the junction's traffic-light controller, claiming to be a legitimate instruction.",
    how: "This junction's Legacy Retrofit link doesn't check who is allowed to send commands, so a forged instruction is obeyed exactly like a real one from the AI orchestrator would be.",
    outcomeSuccess:
      "It worked. Both directions were forced green at the same time right now: a real collision risk.",
    outcomeBlocked:
      "It was rejected. The command carried no valid signature, so the controller refused to act on it.",
  },
  "spoof-congestion": {
    title: "Sensor Spoofing: Fake Congestion",
    what: "A fake sensor report claimed an implausibly large number of vehicles were waiting on one approach.",
    how: "The AI orchestrator trusts its camera/sensor feed to decide signal timing. A forged report poisons that data, the same way a real compromised or spoofed sensor would.",
    outcomeSuccess:
      "It worked. The orchestrator is now skewing timing toward that approach, at the expense of real traffic on the others.",
    outcomeBlocked:
      "It was rejected. The report carried no valid signature, so it never reached the orchestrator's decision logic.",
  },
  "spoof-emergency": {
    title: "Sensor Spoofing: Fake Preemption",
    what: "A fake report claimed an emergency vehicle was approaching, requesting priority green.",
    how: "Real emergency-vehicle-preemption (EVP) systems grant priority based on a signal from the vehicle. A forged signal asks for the same priority with no real emergency vehicle anywhere nearby.",
    outcomeSuccess:
      "It worked. Priority green was granted on a forged claim: this is what preemption spoofing looks like on real EVP hardware.",
    outcomeBlocked: "It was rejected. The claim carried no valid signature, so no priority was granted.",
  },
};

const HEALTH_LABELS = { good: "Normal", warning: "Fail-safe", serious: "Isolated", critical: "Collision risk" };
const SEVERITY_LABELS = { good: "Info", warning: "Warning", serious: "Serious", critical: "Critical" };
const QUEUE_COLORS = { N: "var(--cat-1-blue)", E: "var(--cat-2-orange)", S: "var(--cat-3-aqua)", W: "var(--cat-4-yellow)" };
const QUEUE_BAR_MAX = 8; /* vehicles: bar height scale reference, matches server/network.py's MAX_QUEUE_PER_APPROACH so a spoof-congestion attack still fills the bar */

/* Describes whichever hour the Traffic load control is currently on
   (see renderTimeOfDay/#hour-segmented). The Light/Normal/Rush Hour
   buttons are just three fixed hours, but this stays keyed by hour
   rather than by button label, since it also has to describe whatever
   hour /api/hour last reported even between button presses. */
function describeHour(hour) {
  const label = `${String(hour).padStart(2, "0")}:00`;
  if (hour >= 7 && hour <= 9) {
    return `${label} — Morning rush. Press Execute attack now to see how much faster a cyberattack causes real gridlock when the network is already under load.`;
  }
  if (hour >= 16 && hour <= 18) {
    return `${label} — Evening rush, typically the busiest window of the day.`;
  }
  if (hour <= 4) {
    return `${label} — Deep night. Quiet, off-peak traffic: the easiest hour to see an attack's effect in isolation.`;
  }
  return `${label} — Moderate daytime traffic, calibrated from a real urban commute pattern (see the README), not a flat average.`;
}

/* WebSocket connection */

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
    /* Everything on the page keeps looking exactly as "live" as before
       with no connection at all -- KPIs, the car canvas, the trend
       chart are all just frozen at whatever currentNetwork last held.
       This is what actually makes that unmistakable instead of reading
       as a logic bug in whatever happens to be on screen when the
       connection drops (a real, repeated source of confusion). */
    disconnectedBannerEl.hidden = false;
    document.body.classList.add("page-stale");
    setTimeout(connectWebSocket, 1500);
  });
}

/* Master render */

function render() {
  if (!currentNetwork) return;
  renderStatusBanner();
  renderModeSwitch();
  renderKpis();
  populateTargetSelectOnce();
  renderTopology();
  renderDetailCard();
  renderTrendChart();
  renderChannelLoad();
  renderTimeOfDay();
  renderSecurityEvents();
  renderOpsLog();
  renderPlaybookPanel();
  renderPayloadPreview();
}

/* Worst-first severity order, matching the dataviz status scale. Used
   to find the single most urgent thing happening across all five
   junctions, so the banner always leads with whatever needs attention
   most, not just whichever junction happens to update last. */
const SEVERITY_RANK = { critical: 0, serious: 1, warning: 2, good: 3 };

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
    const secure = currentNetwork.mode === "secure";
    statusBannerIconEl.textContent = "✅";
    statusBannerTextEl.textContent = secure
      ? "Network normal — all 5 junctions running automatically under ITC Secure Integration. No active threats."
      : "Network normal — all 5 junctions running automatically. Legacy Retrofit mode: the command and telemetry channels don't require authentication.";
    return;
  }

  const affected = intersections.filter((i) => i.health === worst);
  const names = affected.map((i) => i.name).join(", ");
  const plural = affected.length > 1 ? "s" : "";

  if (worst === "critical") {
    statusBannerIconEl.textContent = "🚨";
    statusBannerTextEl.textContent = `COLLISION RISK at ${names}: an unauthorized command forced conflicting green lights. This is exactly what Legacy Retrofit mode allows — switch to ITC Secure Integration to stop it.`;
  } else if (worst === "serious") {
    statusBannerIconEl.textContent = "🔒";
    statusBannerTextEl.textContent = `${affected.length} junction${plural} isolated: ${names}. Held safe and cut off from the AI orchestrator — recovers automatically in under 30 seconds.`;
  } else {
    statusBannerIconEl.textContent = "⚠️";
    /* Not "while it recovers": the only way to reach this specific
       branch (alarm=FAILSAFE, but NOT isolated -- an isolated junction
       reaches the branch above instead, which really does recover on
       its own) is a manually-triggered Fail-Safe Flash, which has no
       auto-recovery timer at all. It holds here until a human clicks
       Restore, forever otherwise (verified: this is exactly the
       FAILSAFE-hold fix above -- it no longer self-clears, on purpose).
       The old wording implied it would resolve itself, which it
       structurally cannot; reported as "the attack doesn't resolve"
       by someone reasonably waiting for text that said it would. */
    statusBannerTextEl.textContent = `${affected.length} junction${plural} in fail-safe: ${names}. Flashing red as a precaution — click Restore Normal Operation when you're ready to hand it back to the AI.`;
  }
}

function renderModeSwitch() {
  const secure = currentNetwork.mode === "secure";
  modeSwitchEl.classList.toggle("on", secure);
  modeSwitchEl.setAttribute("aria-checked", String(secure));
  modeLabelLegacyEl.classList.toggle("active", !secure);
  modeLabelSecureEl.classList.toggle("active", secure);
}

/* Traffic-light coloring for the KPIs that have an obvious "bad
   direction": congestion, wait time, and incident count. Throughput
   is left neutral since higher isn't a problem the way it is for the
   others. */
function severityClassFor(value, warnAt, criticalAt) {
  if (value >= criticalAt) return "stat-value-critical";
  if (value >= warnAt) return "stat-value-warning";
  return "stat-value-good";
}

function renderKpis() {
  const k = currentNetwork.kpis;
  kpiThroughputEl.textContent = k.throughput_per_hour.toLocaleString();

  kpiWaitEl.textContent = k.avg_wait_seconds.toFixed(1);
  kpiWaitEl.className = `stat-value ${severityClassFor(k.avg_wait_seconds, 5, 15)}`;

  kpiCongestionEl.textContent = `${k.congestion_index.toFixed(0)}%`;
  kpiCongestionEl.className = `stat-value ${severityClassFor(k.congestion_index, 30, 70)}`;

  kpiIncidentsEl.textContent = `${k.active_incidents} / 5`;
  kpiIncidentsEl.className = `stat-value ${severityClassFor(k.active_incidents, 1, 3)}`;
}

/* Legacy / Retrofit info popover */

legacyInfoBtnEl.addEventListener("click", (event) => {
  event.stopPropagation();
  legacyInfoPopoverEl.hidden = !legacyInfoPopoverEl.hidden;
});

document.addEventListener("click", (event) => {
  if (!legacyInfoPopoverEl.hidden && !legacyInfoPopoverEl.contains(event.target) && event.target !== legacyInfoBtnEl) {
    legacyInfoPopoverEl.hidden = true;
  }
});

/* Zone 1: topology map + detail card + live junction canvas */

const TOPOLOGY_VIEWBOX_W = 160;
const TOPOLOGY_VIEWBOX_H = 100;

function healthColorVar(health) {
  return `var(--status-${health})`;
}

function renderTopology() {
  /* Rebuilt from scratch on every update: five nodes and four edges is
     cheap enough that a diffing approach would add complexity for no
     real benefit at this scale. */
  while (topologySvg.firstChild) topologySvg.removeChild(topologySvg.firstChild);
  topologySvg.setAttribute("viewBox", `0 0 ${TOPOLOGY_VIEWBOX_W} ${TOPOLOGY_VIEWBOX_H}`);

  const byId = {};
  currentNetwork.intersections.forEach((i) => (byId[i.id] = i));

  const toX = (x) => (x / 100) * TOPOLOGY_VIEWBOX_W;
  const toY = (y) => (y / 100) * TOPOLOGY_VIEWBOX_H;

  /* Edges first, so nodes draw on top of the lines that meet them. */
  currentNetwork.edges.forEach(([fromId, toId]) => {
    const from = byId[fromId];
    const to = byId[toId];
    if (!from || !to) return;
    const line = document.createElementNS(SVG_NS, "line");
    line.setAttribute("x1", toX(from.x));
    line.setAttribute("y1", toY(from.y));
    line.setAttribute("x2", toX(to.x));
    line.setAttribute("y2", toY(to.y));
    line.setAttribute("class", "topology-edge");
    topologySvg.appendChild(line);
  });

  if (!selectedIntersectionId && currentNetwork.intersections.length > 0) {
    selectedIntersectionId = currentNetwork.intersections[0].id;
  }
  syncAttackTargetToSelection();

  currentNetwork.intersections.forEach((intersection) => {
    const cx = toX(intersection.x);
    const cy = toY(intersection.y);
    const w = 34;
    const h = 20;

    const group = document.createElementNS(SVG_NS, "g");
    group.style.cursor = "pointer";
    /* Keyboard-operable, not just clickable: an SVG <g> gets none of a
       real <button>'s default behavior for free, so this was previously
       mouse/touch-only with no way to reach or activate a junction node
       from the keyboard at all. */
    group.setAttribute("tabindex", "0");
    group.setAttribute("role", "button");
    group.setAttribute("aria-label", `Inspect ${intersection.name}`);
    group.addEventListener("click", () => {
      selectIntersection(intersection.id);
    });
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectIntersection(intersection.id);
      }
    });

    const rect = document.createElementNS(SVG_NS, "rect");
    rect.setAttribute("x", cx - w / 2);
    rect.setAttribute("y", cy - h / 2);
    rect.setAttribute("width", w);
    rect.setAttribute("height", h);
    rect.setAttribute("rx", 2.5);
    rect.setAttribute(
      "class",
      "topology-node-rect" + (intersection.id === selectedIntersectionId ? " selected" : "")
    );
    group.appendChild(rect);

    /* Health indicator dot, top-right corner of the node. */
    const healthDot = document.createElementNS(SVG_NS, "circle");
    healthDot.setAttribute("cx", cx + w / 2 - 2.5);
    healthDot.setAttribute("cy", cy - h / 2 + 2.5);
    healthDot.setAttribute("r", 1.8);
    healthDot.setAttribute("fill", healthColorVar(intersection.health));
    group.appendChild(healthDot);

    const label = document.createElementNS(SVG_NS, "text");
    label.setAttribute("x", cx);
    label.setAttribute("y", cy - 1.5);
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("class", "topology-node-label");
    label.textContent = intersection.name; /* textContent, never innerHTML, even for our own data */
    group.appendChild(label);

    const sub = document.createElementNS(SVG_NS, "text");
    sub.setAttribute("x", cx);
    sub.setAttribute("y", cy + 4.5);
    sub.setAttribute("text-anchor", "middle");
    sub.setAttribute("class", "topology-node-sub");
    sub.textContent = intersection.isolated ? "isolated" : intersection.phase.replace("_", " ");
    group.appendChild(sub);

    topologySvg.appendChild(group);
  });
}

function selectIntersection(intersectionId) {
  if (intersectionId === selectedIntersectionId) return;
  selectedIntersectionId = intersectionId;
  resetCarSimulation();
  renderTopology();
  renderDetailCard();
  renderPlaybookPanel();
}

/* Keeps the attack console's target dropdown pointed at whichever
   junction is currently selected on the map/detail card. Without this,
   clicking a different junction on the map (or in the detail card)
   would inspect it while the attack form silently kept firing at
   whatever street was previously chosen, so an attack aimed at the
   junction the user is looking at could appear to "not work" simply
   because it was actually landing somewhere else. */
function syncAttackTargetToSelection() {
  if (!selectedIntersectionId) return;
  if (attackTargetEl.value !== selectedIntersectionId) {
    attackTargetEl.value = selectedIntersectionId;
  }
}

const COMPASS_NAMES = { N: "North", E: "East", S: "South", W: "West" };

function renderDetailCard() {
  const intersection = currentNetwork.intersections.find((i) => i.id === selectedIntersectionId);
  if (!intersection) return;

  selectedNameEl.textContent = intersection.name;
  selectedPhaseEl.textContent = intersection.phase.replace("_", " ");

  /* Real-world grounding (server/tel_aviv_data.py): only two of the
     five junctions have one (a genuine, cited fact, not invented for
     the other three), so this hides itself rather than show nothing
     useful. Built with textContent/createElement, never innerHTML,
     even though this data originates on our own server. */
  if (intersection.real_world_context) {
    realWorldContextEl.innerHTML = "";
    realWorldContextEl.appendChild(document.createTextNode(`${intersection.real_world_context.summary} `));
    const sourceLink = document.createElement("a");
    sourceLink.href = intersection.real_world_context.source;
    sourceLink.target = "_blank";
    sourceLink.rel = "noopener noreferrer";
    sourceLink.className = "real-world-context-link";
    sourceLink.textContent = "(source)";
    realWorldContextEl.appendChild(sourceLink);
    realWorldContextEl.hidden = false;
  } else {
    realWorldContextEl.hidden = true;
  }

  selectedHealthEl.textContent = HEALTH_LABELS[intersection.health];
  selectedHealthEl.className = `health-badge health-${intersection.health}`;

  queueBarsEl.innerHTML = "";
  ["N", "E", "S", "W"].forEach((approach) => {
    const value = intersection.queues[approach] ?? 0;
    const predicted = intersection.predicted_arrivals?.[approach] ?? 0;
    const pct = Math.max(2, Math.min(100, (value / QUEUE_BAR_MAX) * 100));
    /* Capped by the remaining headroom above the actual bar, not just
       QUEUE_BAR_MAX independently, so the predicted cap never visually
       overlaps the solid bar it sits on top of even when both are
       large. */
    const predictedPct = Math.max(0, Math.min(100 - pct, (predicted / QUEUE_BAR_MAX) * 100));

    const col = document.createElement("div");
    col.className = "queue-bar-col";

    const valueEl = document.createElement("span");
    valueEl.className = "queue-bar-value";
    valueEl.textContent = value.toFixed(1);

    /* Stacked pair: a lighter, same-hue cap on top showing the ML
       predictor's forecast for the next few seconds (server/
       ml_predictor.py), the solid bar below it showing the real count
       right now. Same categorical color, lower opacity, per the
       dataviz convention that a forecast/uncertain extension of a
       series reads as a lighter variant of that series, not a new one. */
    const stack = document.createElement("div");
    stack.className = "queue-bar-stack";
    stack.title = `${value.toFixed(1)} waiting now, +${predicted.toFixed(1)} AI-predicted in the next few seconds`;

    const predictedCap = document.createElement("div");
    predictedCap.className = "queue-bar-predicted";
    predictedCap.style.height = `${predictedPct}%`;
    predictedCap.style.background = QUEUE_COLORS[approach];

    const bar = document.createElement("div");
    bar.className = "queue-bar";
    bar.style.height = `${pct}%`;
    bar.style.background = QUEUE_COLORS[approach];

    stack.appendChild(predictedCap);
    stack.appendChild(bar);

    const labelEl = document.createElement("span");
    labelEl.className = "queue-bar-label";
    labelEl.textContent = COMPASS_NAMES[approach];

    col.appendChild(valueEl);
    col.appendChild(stack);
    col.appendChild(labelEl);
    queueBarsEl.appendChild(col);
  });

  reconcileCarSimulation(intersection);
}

/* Live junction canvas: the currently-selected junction's "attack
   simulator" view. The actual car-simulation logic (lane math, signal
   rendering, animation) lives in car-sim.js, shared with monitor.js's
   Live Network Monitor page; this is a single instance of it bound to
   this page's one canvas. */
const junctionRenderer = createCarSimRenderer(junctionCanvas);

function resetCarSimulation() {
  junctionRenderer.reset();
}

function reconcileCarSimulation(intersection) {
  junctionRenderer.reconcile(intersection);
}

/* Redraws continuously (not just on WebSocket updates) so car motion and
   the fail-safe flash both animate smoothly. Frozen while an attack's
   educational pop-up is open. */
setInterval(() => {
  if (simulationPaused || !currentNetwork) return;
  const intersection = currentNetwork.intersections.find((i) => i.id === selectedIntersectionId);
  if (!intersection) return;
  junctionRenderer.tick(intersection);
  junctionRenderer.draw(intersection);
}, 40);

/* Zone 2: congestion trend chart + channel load */

let trendListenersAttached = false;

function renderTrendChart() {
  const history = currentNetwork.congestion_history;
  while (trendSvg.firstChild) trendSvg.removeChild(trendSvg.firstChild);
  if (history.length === 0) return;

  const w = 600;
  const h = 140;
  const padTop = 10;
  const padBottom = 20;
  const plotH = h - padTop - padBottom;

  trendCurrentValueEl.textContent = `${history[history.length - 1].value.toFixed(0)}%`;

  /* Gridlines at 0/50/100: recessive, one-step-off-surface gray. */
  [0, 50, 100].forEach((tick) => {
    const y = padTop + plotH - (tick / 100) * plotH;
    const line = document.createElementNS(SVG_NS, "line");
    line.setAttribute("x1", 0);
    line.setAttribute("x2", w);
    line.setAttribute("y1", y);
    line.setAttribute("y2", y);
    line.setAttribute("class", "trend-gridline");
    trendSvg.appendChild(line);

    const label = document.createElementNS(SVG_NS, "text");
    label.setAttribute("x", 2);
    label.setAttribute("y", y - 2);
    label.setAttribute("class", "trend-axis-label");
    label.textContent = `${tick}%`;
    trendSvg.appendChild(label);
  });

  const xFor = (index) => (history.length === 1 ? 0 : (index / (history.length - 1)) * w);
  const yFor = (value) => padTop + plotH - (Math.min(100, value) / 100) * plotH;

  const linePoints = history.map((point, index) => `${xFor(index)},${yFor(point.value)}`).join(" ");
  const areaPoints = `0,${padTop + plotH} ${linePoints} ${w},${padTop + plotH}`;

  const area = document.createElementNS(SVG_NS, "polygon");
  area.setAttribute("points", areaPoints);
  area.setAttribute("class", "trend-area");
  trendSvg.appendChild(area);

  const line = document.createElementNS(SVG_NS, "polyline");
  line.setAttribute("points", linePoints);
  line.setAttribute("class", "trend-line");
  trendSvg.appendChild(line);

  /* Crosshair + hover dot, hidden until the pointer moves over the chart. */
  const crosshair = document.createElementNS(SVG_NS, "line");
  crosshair.setAttribute("y1", padTop);
  crosshair.setAttribute("y2", padTop + plotH);
  crosshair.setAttribute("class", "trend-crosshair");
  crosshair.style.display = "none";
  trendSvg.appendChild(crosshair);

  const hoverDot = document.createElementNS(SVG_NS, "circle");
  hoverDot.setAttribute("r", 3.5);
  hoverDot.setAttribute("class", "trend-dot");
  hoverDot.style.display = "none";
  trendSvg.appendChild(hoverDot);

  /* Pointer handling reads live `history`/`xFor` via closure, so we only
     need to attach the listeners once: re-attaching on every render
     would leak listeners onto the (rebuilt) SVG element each time since
     the element itself is stable even though its children are rebuilt. */
  if (!trendListenersAttached) {
    trendSvg.addEventListener("pointermove", (event) => {
      const rect = trendSvg.getBoundingClientRect();
      const relativeX = ((event.clientX - rect.left) / rect.width) * w;
      const hist = currentNetwork.congestion_history;
      if (hist.length === 0) return;
      const nearestIndex = Math.max(
        0,
        Math.min(hist.length - 1, Math.round((relativeX / w) * (hist.length - 1)))
      );
      const point = hist[nearestIndex];
      const px = hist.length === 1 ? 0 : (nearestIndex / (hist.length - 1)) * w;
      const py = padTop + plotH - (Math.min(100, point.value) / 100) * plotH;

      const ch = trendSvg.querySelector(".trend-crosshair");
      const dot = trendSvg.querySelector(".trend-dot");
      if (ch) {
        ch.setAttribute("x1", px);
        ch.setAttribute("x2", px);
        ch.style.display = "block";
      }
      if (dot) {
        dot.setAttribute("cx", px);
        dot.setAttribute("cy", py);
        dot.style.display = "block";
      }

      const time = new Date(point.ts * 1000).toLocaleTimeString();
      trendTooltipEl.innerHTML = "";
      const valueStrong = document.createElement("strong");
      valueStrong.textContent = `${point.value.toFixed(0)}%`;
      trendTooltipEl.appendChild(valueStrong);
      trendTooltipEl.appendChild(document.createTextNode(` at ${time}`));
      trendTooltipEl.hidden = false;
      trendTooltipEl.style.left = `${(px / w) * 100}%`;
    });

    trendSvg.addEventListener("pointerleave", () => {
      const ch = trendSvg.querySelector(".trend-crosshair");
      const dot = trendSvg.querySelector(".trend-dot");
      if (ch) ch.style.display = "none";
      if (dot) dot.style.display = "none";
      trendTooltipEl.hidden = true;
    });

    trendListenersAttached = true;
  }
}

/* requests/min treated as "100% of the meter" for display scale. Derived,
   not guessed: detection.py's organic telemetry is one arrival roll per
   approach per DETECTION_TICK_SECONDS (2s) tick, capped at one event per
   approach per tick, across 5 junctions x 4 approaches x 30 ticks/min --
   600 req/min is the hard mathematical ceiling of legitimate telemetry
   traffic, reachable only if every single roll on every approach at
   every junction succeeded (effectively, absolute rush-hour peak on the
   busiest junctions). The old value of 60 was sized for a single
   junction and never rescaled when the network grew to five, so the
   telemetry meter had been pegged near-max during ordinary traffic with
   no attack involved at all, making it useless as a "is this actually a
   flood" signal. 800 leaves real headroom above that 600 ceiling, so
   normal operation (even genuine rush hour) reads well under the
   meter's elevated/critical bands, and an actual flood, which stacks on
   top of organic traffic, still stands out clearly. */
const CHANNEL_METER_REFERENCE = 800;

function renderChannelLoad() {
  const load = currentNetwork.channel_load;
  channelCommandValueEl.textContent = `${load.command_per_min} req/min`;
  channelTelemetryValueEl.textContent = `${load.telemetry_per_min} req/min`;

  setSeverityMeter(meterCommandEl, load.command_per_min, CHANNEL_METER_REFERENCE);
  setSeverityMeter(meterTelemetryEl, load.telemetry_per_min, CHANNEL_METER_REFERENCE);
}

/* Shared green/yellow/red severity coloring for any meter on the
   dashboard: traffic-light colors for a traffic dashboard. Low is
   good (green, the default fill color), a middle band is a caution
   (amber), and the top band is a problem (red). */
function setSeverityMeter(el, value, referenceMax) {
  const pct = Math.max(2, Math.min(100, (value / referenceMax) * 100));
  el.style.width = `${pct}%`;
  el.classList.remove("meter-elevated", "meter-critical");
  if (pct >= 90) el.classList.add("meter-critical");
  else if (pct >= 55) el.classList.add("meter-elevated");
}

/* Zone 3: attack console + load control */

function populateTargetSelectOnce() {
  if (targetSelectPopulated || currentNetwork.intersections.length === 0) return;
  currentNetwork.intersections.forEach((intersection) => {
    const option = document.createElement("option");
    option.value = intersection.id;
    option.textContent = intersection.name;
    attackTargetEl.appendChild(option);
  });
  targetSelectPopulated = true;
}

function updateAttackFormFields() {
  const type = attackTypeEl.value;
  attackApproachFieldEl.style.display = type === "inject" ? "none" : "flex";
  attackCountFieldEl.style.display = type === "spoof-congestion" ? "flex" : "none";
  attackDescriptionEl.textContent = ATTACK_DESCRIPTIONS[type];
  renderPayloadPreview();
}

attackTypeEl.addEventListener("change", updateAttackFormFields);
updateAttackFormFields();

/* The reverse direction of syncAttackTargetToSelection: picking a
   street directly from the dropdown (instead of clicking the map)
   should also move the map/detail-card selection, so the junction
   highlighted on screen always matches the one about to be attacked. */
attackTargetEl.addEventListener("change", () => {
  selectIntersection(attackTargetEl.value);
  renderPayloadPreview();
});

/* Every field that changes what Execute would actually send keeps the
   live payload preview in sync, so what's shown is never stale
   relative to what a click would do. */
[attackApproachEl, attackCountEl, attackFloodEl, attackFloodCountEl, attackCoordinatedEl].forEach((el) => {
  el.addEventListener("input", renderPayloadPreview);
  el.addEventListener("change", renderPayloadPreview);
});

/* Builds the exact {path, body} an attack would POST, for one target,
   without sending it: the single source of truth both the live payload
   preview and the actual send (sendAttackPayload) read from, so the
   preview can never show something different from what Execute
   actually does. */
function buildAttackPayload(type, targetId) {
  const approach = attackApproachEl.value;
  const count = parseInt(attackCountEl.value, 10) || 40;

  if (type === "inject") {
    return {
      path: "/api/command",
      body: { intersection_id: targetId, phase: "FORCE_ALL_GREEN", source: CONSOLE_ATTACKER_SOURCE },
    };
  }
  if (type === "spoof-congestion") {
    return {
      path: "/api/telemetry",
      body: {
        intersection_id: targetId,
        approach,
        road_user_type: "car",
        count,
        source: CONSOLE_ATTACKER_SOURCE,
      },
    };
  }
  return {
    path: "/api/telemetry",
    body: {
      intersection_id: targetId,
      approach,
      road_user_type: "emergency",
      count: 1,
      source: CONSOLE_ATTACKER_SOURCE,
    },
  };
}

async function sendAttackPayload(payload) {
  const response = await fetch(payload.path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload.body),
  });
  return response.json();
}

async function fireAttackOnce(type, targetId) {
  return sendAttackPayload(buildAttackPayload(type, targetId));
}

/* An attack "succeeded" (from the attacker's point of view) when the
   dangerous/spoofed outcome actually took effect, not merely when the
   HTTP call returned ok:true. A command that got vetoed by the conflict
   monitor still returns ok:true (the request was processed), but the
   collision it was trying to cause did not happen, so that reads as
   blocked here. */
function attackSucceeded(type, response) {
  if (!response.ok) return false;
  if (type === "inject") return response.alarm === "COLLISION_RISK";
  return true;
}

attackForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  attackExecuteEl.disabled = true;
  const type = attackTypeEl.value;
  const selectedTarget = attackTargetEl.value;
  /* Coordinated fires the same attack at every junction instead of just
     the selected one, modeling a real, more severe threat pattern: an
     attacker rarely has a reason to touch only one node in a network
     they've already reached. Combines freely with Flood: each target
     gets its own repeat-count worth of requests. */
  const targets = attackCoordinatedEl.checked
    ? currentNetwork.intersections.map((i) => i.id)
    : [selectedTarget];
  const repeat = attackFloodEl.checked ? parseInt(attackFloodCountEl.value, 10) || 10 : 1;
  /* More than one request total (either dimension) is a batch: showing
     the educational pop-up after every single one would be unusable,
     so one summary pop-up appears once the whole batch is done
     instead, the same shape Flood alone already used. */
  const isBatch = targets.length > 1 || repeat > 1;

  try {
    let sent = 0;
    let succeededCount = 0;
    /* Tracks the most recent response seen. When nothing in the batch
       succeeded, this ends up holding the reason the loop actually
       stopped on (e.g. "source blocked" if the auto-block cut it
       short), which is exactly the reason showAttackModal needs to
       pick the right guidance; when something succeeded, the reason
       is never consulted anyway (see showAttackModal's succeeded
       branch), so which response this lands on doesn't matter there. */
    let representativeResponse = null;

    targetLoop: for (const targetId of targets) {
      for (let i = 0; i < repeat; i++) {
        const response = await fireAttackOnce(type, targetId);
        sent++;
        if (attackSucceeded(type, response)) succeededCount++;
        representativeResponse = response;
        /* In Secure mode, every request from this console is unsigned
           by construction, so a flood of the default 10 requests trips
           the 3-strike auto-block (see
           security.py's ThreatTracker) almost immediately. Once that
           happens every remaining request in this same batch, at this
           target or any other, would just be rejected for the same
           reason, so stop the whole batch early instead of burning
           through the rest of it for nothing. The block clears on its
           own after BLOCK_DURATION_SECONDS, so no manual step is
           needed to try again; the security event feed below shows it
           happening. */
        if (!response.ok && response.reason === "source blocked") break targetLoop;
        if (isBatch) await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }

    if (isBatch) {
      showAttackModal(
        type,
        succeededCount > 0,
        selectedTarget,
        representativeResponse ? representativeResponse.reason : undefined,
        { sent, succeededCount, targetCount: targets.length, isFlood: attackFloodEl.checked }
      );
    } else {
      const succeeded = attackSucceeded(type, representativeResponse);
      showAttackModal(type, succeeded, selectedTarget, representativeResponse.reason);
    }
  } finally {
    attackExecuteEl.disabled = false;
  }
});

/* Live preview of the exact request Execute is about to send: reuses
   buildAttackPayload, the same function that actually sends it, so
   this can never drift from reality. Deliberately just the raw
   request -- POST path and JSON body, nothing appended below it -- so
   this box answers exactly one question: what literally goes out over
   the wire. */
function renderPayloadPreview() {
  if (!currentNetwork) return;
  const type = attackTypeEl.value;
  const targetId = attackTargetEl.value;
  const payload = buildAttackPayload(type, targetId);
  payloadPreviewEl.textContent = `POST ${payload.path}\n${JSON.stringify(payload.body, null, 2)}`;
}

/* Traffic load control: three buttons, each really just a shorthand
   for a representative hour handed to the same /api/hour endpoint the
   Live Monitor's forecast tool uses (see index.html's comment on
   #hour-segmented for exactly which hour each maps to and why) -- the
   real hourly curve in tel_aviv_data.py stays the single source of
   truth either way, this is just a simpler front door onto it than
   picking an exact hour. */
function renderTimeOfDay() {
  const hour = currentNetwork.simulated_hour;
  hourSegmentedEl.querySelectorAll(".segmented-btn").forEach((btn) => {
    btn.classList.toggle("active", Number(btn.dataset.hour) === hour);
  });
  loadExplanationEl.textContent = describeHour(hour);
}

async function setSimulatedHour(hour) {
  await fetch("/api/hour", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hour }),
  });
}

hourSegmentedEl.addEventListener("click", (event) => {
  const btn = event.target.closest(".segmented-btn");
  if (!btn) return;
  setSimulatedHour(Number(btn.dataset.hour));
});

modeSwitchEl.addEventListener("click", () => {
  const nextMode = currentNetwork.mode === "secure" ? "legacy" : "secure";
  fetch("/api/mode", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode: nextMode }),
  });
});

/* Educational attack pop-up + guided incident response */

/* Which playbook button is the right FIRST response, chosen by what
   each attack actually leaves broken, not a blanket default. All three
   buttons do genuinely different things (see their tooltips in
   index.html):
     - Command Injection leaves an actual physical hazard (both
       directions green at once, alarm=COLLISION_RISK). This USED TO
       recommend Fail-Safe Flash on the claim that "Isolate Node alone
       doesn't touch the current phase" -- that claim was simply wrong,
       contradicted by main.py's own _isolate(), which sets
       phase="ALL_RED" exactly like Fail-Safe Flash does. Isolate Node
       fixes the immediate hazard exactly as fast, AND (see the next
       point) additionally stops the channel from being abused again,
       so it's the strictly more complete single action, not merely an
       equally valid alternative. Found live, not by re-reading the
       code first: a junction left in Fail-Safe (not isolated) keeps
       accepting organic telemetry with phase=ALL_RED serving nothing,
       so its queues climb with nothing draining them -- confirmed
       live, congestion 25% to 100% in 8 seconds sitting in Fail-Safe
       with nothing else happening. The exact same attack, isolated
       instead, held perfectly flat (25% for the full 10-second
       window) because isolation also rejects incoming telemetry (see
       apply_telemetry's isolation check in main.py). Reported as
       "congestion goes up and nothing fixes the system."
     - Sensor Spoofing (both kinds) leaves corrupted STATE behind, a
       fake queue number or a fake standing preemption, that Isolate
       Node does not clean up (isolation only stops FUTURE commands/
       telemetry; it never touches queues or last_preemption). Restore
       Normal Operation is what actually clears that fabricated data,
       see network.py's reset_intersection.
     - Flood is a different axis from the above, not a fourth attack
       type: any of the three attacks repeated rapidly is a channel
       being abused over and over, not a single exploit landing once.
       Restore alone would just get immediately re-broken by the next
       request in the same flood, so Isolate Node (cut the channel off
       now) is still the right override for Sensor Spoofing floods
       specifically, even though it now coincides with Injection's own
       single-attack recommendation below rather than overriding it.
     - Coordinated is a THIRD axis, and takes priority over both of the
       above: it means every junction was hit, not just the one
       currently selected. A genuine bug, reported directly and not
       found by re-reading the code first: recommendedActionFor used to
       check isFlood only, so a Coordinated attack (with or without
       Flood also checked) still glowed a SINGLE-junction button --
       Isolate Node for inject, Restore for spoof-* -- which, if
       clicked, would fix only whichever one junction happened to be
       selected before the attack, silently leaving the other four
       exactly as attacked. targetCount > 1 (see the submit handler's
       own floodSummary) now overrides everything else: any Coordinated
       attack, flooded or not, recommends Restore All Junctions, the
       one action whose scope actually matches what was attacked.
*/
const RECOMMENDED_ACTION = {
  inject: { id: "playbook-isolate", label: "Isolate Node", el: () => playbookIsolateEl },
  "spoof-congestion": { id: "playbook-restore", label: "Restore Normal Operation", el: () => playbookRestoreEl },
  "spoof-emergency": { id: "playbook-restore", label: "Restore Normal Operation", el: () => playbookRestoreEl },
};
const ISOLATE_FOR_FLOOD_ACTION = {
  id: "playbook-isolate",
  label: "Isolate Node",
  el: () => playbookIsolateEl,
};
const RESTORE_ALL_FOR_COORDINATED_ACTION = {
  id: "playbook-restore-all",
  label: "Restore All Junctions",
  el: () => playbookRestoreAllEl,
};

/* The single source of truth both showAttackModal and armGuidedResponse
   read from, so they can never recommend two different buttons for the
   same attack. Checked in priority order: scope (Coordinated, every
   junction hit) matters more than repetition (Flood, one channel abused
   repeatedly) matters more than the per-type default. */
function recommendedActionFor(type, floodSummary) {
  if (floodSummary && floodSummary.targetCount > 1) return RESTORE_ALL_FOR_COORDINATED_ACTION;
  if (floodSummary && floodSummary.isFlood) return ISOLATE_FOR_FLOOD_ACTION;
  return RECOMMENDED_ACTION[type];
}

let guidedTargetButton = null;

function showAttackModal(type, succeeded, targetIntersectionId, reason, floodSummary) {
  /* Select the attacked junction first: the recommended playbook action
     always acts on whatever is currently selected, so without this, a
     user who clicks a different junction on the map before responding
     would end up isolating the wrong one. This also switches the live
     canvas/detail card straight to the junction that was just hit. */
  selectIntersection(targetIntersectionId);

  const info = ATTACK_EXPLANATIONS[type];
  const intersection = currentNetwork.intersections.find((i) => i.id === targetIntersectionId);
  const targetName = intersection ? intersection.name : targetIntersectionId;

  modalTitleEl.textContent = floodSummary ? `${info.title} (Flood)` : info.title;
  modalWhatEl.textContent = info.what;
  modalHowEl.textContent = info.how;

  /* A flood is many requests, not one, so the single success/blocked
     sentence from ATTACK_EXPLANATIONS doesn't fit: report how many of
     the batch actually got through instead. Everything else about the
     modal (title, what/how, guided response) still applies exactly the
     same as a single attack. */
  if (floodSummary) {
    const { sent, succeededCount, targetCount } = floodSummary;
    const summarySentence =
      succeededCount > 0
        ? `${succeededCount} of ${sent} flood requests got through.`
        : `All ${sent} flood requests were rejected.`;
    /* Coordinated hits every junction at once, not just whichever one
       was selected beforehand -- "(Target: X)" alone would misreport a
       5-junction attack as a 1-junction one, the exact thing Coordinated
       is supposed to demonstrate is more severe than. */
    const targetDescription =
      targetCount > 1 ? `${targetCount} junctions, coordinated` : targetName;
    modalOutcomeEl.textContent = `${summarySentence} (Target: ${targetDescription}.)`;
  } else {
    modalOutcomeEl.textContent = `${succeeded ? info.outcomeSuccess : info.outcomeBlocked} (Target: ${targetName}.)`;
  }

  if (succeeded) {
    modalTagEl.textContent = "Attack succeeded";
    modalTagEl.classList.remove("modal-tag-blocked");
    const action = recommendedActionFor(type, floodSummary);
    modalGuidanceEl.textContent = `Recommended response: click "${action.label}" below, it's about to glow.`;
    armGuidedResponse(type, floodSummary);
  } else {
    modalTagEl.textContent = "Attack blocked";
    modalTagEl.classList.add("modal-tag-blocked");
    /* Each rejection reason means something genuinely different, so
       "This was rejected automatically" alone would be misleading (or
       flatly wrong) for at least two of them:
         - "isolated": the junction itself is isolated (manually via
           Isolate Node, or auto-blocked) and is rejecting EVERY
           request right now, in either Legacy or Secure mode -- this
           has nothing to do with signature verification, so the old
           fallback text ("rejected automatically by ITC Secure
           Integration") was actively false here, and worse, gave no
           confirmation that clicking Isolate Node is exactly what's
           defending the junction right now. Reported as "the defense
           doesn't work at all" by someone who'd just clicked Isolate
           Node and had no way to tell it was the reason anything was
           being blocked.
         - "source blocked": this console's simulated attacker already
           tripped the 3-strike auto-block on an earlier attempt, so
           this request (and every one after it) never even reached the
           signature/plausibility checks. Clears on its own after
           BLOCK_DURATION_SECONDS (security.py), so the guidance is
           "wait," not "no action needed," which would read as if
           nothing unusual was happening. */
    if (reason === "isolated") {
      modalGuidanceEl.textContent =
        "This junction is currently isolated — Isolate Node is doing exactly what it's supposed to: rejecting every request, from anyone, until it's restored. That's the defense working, not a rejected-but-otherwise-normal request.";
    } else if (reason === "source blocked") {
      modalGuidanceEl.textContent =
        "Your simulated attacker is already blocked network-wide from an earlier attempt. It clears on its own after about 30 seconds; try again after that.";
    } else {
      modalGuidanceEl.textContent = "This was rejected automatically by ITC Secure Integration. No action needed.";
    }
    /* Deliberately NOT calling disarmGuidedResponse() here. A blocked
       attack has nothing to remediate, so it must not clear a glow that
       is still pending from an earlier, unrelated attack that actually
       got through: otherwise firing a second (blocked) attack makes
       the first, still-unaddressed one look "handled" when it isn't. */
  }

  simulationPaused = true;
  modalBackdropEl.hidden = false;
}

function armGuidedResponse(type, floodSummary) {
  disarmGuidedResponse();
  const action = recommendedActionFor(type, floodSummary);
  guidedTargetButton = action.el();
  guidedTargetButton.classList.add("guided-glow");
  playbookHintEl.textContent = `👉 Recommended: click "${action.label}" to respond to the attack on ${playbookTargetNameEl.textContent}.`;
  playbookHintEl.hidden = false;
}

function disarmGuidedResponse() {
  if (guidedTargetButton) {
    guidedTargetButton.classList.remove("guided-glow");
    guidedTargetButton = null;
  }
  playbookHintEl.hidden = true;
}

modalDismissEl.addEventListener("click", () => {
  modalBackdropEl.hidden = true;
  simulationPaused = false;
  if (guidedTargetButton) {
    guidedTargetButton.scrollIntoView({ behavior: "smooth", block: "center" });
  }
});

/* Zone 4: incident response playbook + security event table */

/* Whether Restore All would actually change anything right now. Not
   just active_incidents (alarm set or isolated): a successful
   spoof-congestion attack sets neither of those, it only inflates
   queues, so a first version of this check left the button disabled
   -- and therefore silently inert, since a disabled button never fires
   a click at all -- immediately after the exact attack this button
   exists to clean up after. Found by testing the actual Coordinated ->
   Restore All flow end to end, not by inspection. */
function anythingToRestore() {
  return currentNetwork.intersections.some(
    (i) => i.alarm !== null || i.isolated || Object.values(i.queues).some((q) => q > 0)
  );
}

function renderPlaybookPanel() {
  const intersection = currentNetwork.intersections.find((i) => i.id === selectedIntersectionId);
  playbookTargetNameEl.textContent = intersection ? intersection.name : "—";
  /* Nothing to restore network-wide when every junction is already
     healthy: disabled rather than hidden, so it doesn't jump around in
     the layout every time an incident starts/ends. */
  playbookRestoreAllEl.disabled = !anythingToRestore();
}

/* What to tell the operator after each mitigation action actually
   completes, phrased the same way the status banner talks about the
   same states, so the language stays consistent across the dashboard. */
const MITIGATION_MESSAGES = {
  failsafe_flash: (name) =>
    `🛡️ ${name} forced into fail-safe. Flashing red as a precaution while it's investigated.`,
  isolate_node: (name) =>
    `🔒 1 junction isolated: ${name}. Held safe and cut off from the AI orchestrator — recovers automatically in under 30 seconds.`,
  restore: (name) => `✅ ${name} restored to normal operation — back under full AI control.`,
};

function runPlaybook(action, buttonEl) {
  if (!selectedIntersectionId) return;
  const intersection = currentNetwork.intersections.find((i) => i.id === selectedIntersectionId);
  const name = intersection ? intersection.name : selectedIntersectionId;

  fetch("/api/playbook", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ intersection_id: selectedIntersectionId, action }),
  })
    .then((response) => response.json())
    .then((result) => {
      /* FastAPI returns HTTP 200 for this endpoint either way; success
         or failure is only distinguishable from the JSON body's own
         `ok` field, not the HTTP status, so that's what has to be
         checked here rather than the raw response object. */
      if (!result.ok) return;
      /* Responding via any playbook action counts as "handled", so
         clear the guided hint even if the user picked a different
         button than the one recommended. */
      disarmGuidedResponse();
      showSuccessFlash(buttonEl);
      showMitigationToast(MITIGATION_MESSAGES[action](name));
    });
}

/* Same shape as runPlaybook, but "restore_all" is network-wide (no
   intersection_id needed, see main.py's own handling of that action)
   instead of one junction. What actually made responding to a
   Coordinated attack slow was never the attack, it was selecting each
   of the 5 attacked junctions in turn and clicking Restore on each one
   individually. One request now hands all 5 back to the AI at once.

   Deliberately NOT the same instant "zero every queue" restore uses
   for one junction: main.py's restore_all clears alarm/isolation and
   forces ALL_RED immediately (see the visible flash to red right after
   clicking), but leaves queues alone, letting the AI orchestrator
   drain them through its own real service rate exactly like it would
   for any other backlog -- watchable, over roughly the real time that
   takes, not an unrealistic instant snap to zero across all 5 at once. */
function runRestoreAll() {
  fetch("/api/playbook", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "restore_all" }),
  })
    .then((response) => response.json())
    .then((result) => {
      if (!result.ok) return;
      disarmGuidedResponse();
      showSuccessFlash(playbookRestoreAllEl);
      showMitigationToast(
        "✅ All 5 junctions handed back to the AI orchestrator — congestion clears over the next ~15 seconds, not instantly."
      );
    });
}

playbookRestoreAllEl.addEventListener("click", runRestoreAll);

function showSuccessFlash(buttonEl) {
  const original = buttonEl.querySelector("small").textContent;
  buttonEl.querySelector("small").textContent = "✅ Done — dashboard is updating…";
  setTimeout(() => {
    buttonEl.querySelector("small").textContent = original;
  }, 2500);
}

const mitigationToastEl = document.getElementById("mitigation-toast");
const mitigationToastTextEl = document.getElementById("mitigation-toast-text");
let mitigationToastTimer = null;

/* Reported as "too slow to see" at the old 6000ms -- combined with the
   old, smaller text size, it had mostly finished fading before it
   registered as something to read, not just dismiss reflexively. */
const MITIGATION_TOAST_DURATION_MS = 10000;

function showMitigationToast(message) {
  mitigationToastTextEl.textContent = message;
  mitigationToastEl.hidden = false;
  if (mitigationToastTimer) clearTimeout(mitigationToastTimer);
  mitigationToastTimer = setTimeout(() => {
    mitigationToastEl.hidden = true;
  }, MITIGATION_TOAST_DURATION_MS);
}

mitigationToastEl.addEventListener("click", () => {
  mitigationToastEl.hidden = true;
  if (mitigationToastTimer) clearTimeout(mitigationToastTimer);
});

playbookFailsafeEl.addEventListener("click", () => runPlaybook("failsafe_flash", playbookFailsafeEl));
playbookIsolateEl.addEventListener("click", () => runPlaybook("isolate_node", playbookIsolateEl));
playbookRestoreEl.addEventListener("click", () => runPlaybook("restore", playbookRestoreEl));

function renderSecurityEvents() {
  const events = currentNetwork.security_events;
  securityEventBodyEl.innerHTML = "";

  const byId = {};
  currentNetwork.intersections.forEach((i) => (byId[i.id] = i.name));

  /* Newest first, capped so the table stays scannable. */
  events
    .slice(-150)
    .reverse()
    .forEach((event) => {
      const row = document.createElement("tr");
      if (event.severity === "critical") {
        row.className = "event-row-critical";
      }

      const timeCell = document.createElement("td");
      timeCell.className = "event-time";
      timeCell.textContent = new Date(event.ts * 1000).toLocaleTimeString();

      const severityCell = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = `severity-badge severity-${event.severity}`;
      badge.textContent = SEVERITY_LABELS[event.severity] || event.severity;
      severityCell.appendChild(badge);

      const junctionCell = document.createElement("td");
      junctionCell.textContent = event.intersection_id ? byId[event.intersection_id] || event.intersection_id : "—";

      const messageCell = document.createElement("td");
      messageCell.className = "event-message";
      messageCell.appendChild(document.createTextNode(event.message));
      if (event.technique) {
        const techniqueEl = document.createElement("span");
        techniqueEl.className = "event-technique";
        techniqueEl.textContent = `MITRE ATT&CK for ICS: ${event.technique}`;
        messageCell.appendChild(techniqueEl);
      }

      row.appendChild(timeCell);
      row.appendChild(severityCell);
      row.appendChild(junctionCell);
      row.appendChild(messageCell);
      securityEventBodyEl.appendChild(row);
    });
}

function renderOpsLog() {
  opsLogListEl.innerHTML = "";
  currentNetwork.ops_log.slice(-40).forEach((entry) => {
    const li = document.createElement("li");
    const time = new Date(entry.ts * 1000).toLocaleTimeString();
    li.textContent = `${time} — ${entry.message}`;
    opsLogListEl.appendChild(li);
  });
}

/* Attacks info reference panel: viewable any time, not just when an
   attack is executed. Reuses the same ATTACK_EXPLANATIONS content the
   pop-up shows, so the two never drift apart. */

const attacksInfoBtnEl = document.getElementById("attacks-info-btn");
const attacksInfoBackdropEl = document.getElementById("attacks-info-backdrop");
const attacksInfoListEl = document.getElementById("attacks-info-list");
const attacksInfoDismissEl = document.getElementById("attacks-info-dismiss");

let attacksInfoBuilt = false;

function buildAttacksInfoList() {
  if (attacksInfoBuilt) return;
  Object.values(ATTACK_EXPLANATIONS).forEach((info) => {
    const item = document.createElement("div");
    item.className = "attacks-info-item";

    const heading = document.createElement("h4");
    heading.textContent = info.title;
    item.appendChild(heading);

    const dl = document.createElement("dl");
    [
      ["What it is", info.what],
      ["How it affects a real system", info.how],
      ["If it gets through", info.outcomeSuccess],
      ["If it's blocked", info.outcomeBlocked],
    ].forEach(([label, text]) => {
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = text;
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    item.appendChild(dl);

    attacksInfoListEl.appendChild(item);
  });
  attacksInfoBuilt = true;
}

attacksInfoBtnEl.addEventListener("click", () => {
  buildAttacksInfoList();
  simulationPaused = true;
  attacksInfoBackdropEl.hidden = false;
});

attacksInfoDismissEl.addEventListener("click", () => {
  attacksInfoBackdropEl.hidden = true;
  simulationPaused = false;
});

/* Fun-fact panel: fills the empty space beside the 300px junction
   canvas with real trivia about traffic engineering and control-system
   security, tying the demo back to the wider field it's illustrating
   instead of leaving that space blank. */

const funFactTextEl = document.getElementById("fun-fact-text");
const funFactNextEl = document.getElementById("fun-fact-next");

const FUN_FACTS = [
  "The world's first electric traffic signal was installed in Cleveland, Ohio in 1914. Before that, intersections were controlled by a police officer with a manual stop/go sign.",
  "Traffic lights borrowed their red-and-green color scheme directly from 19th-century railroad signaling, where red already meant \"stop.\"",
  "Yellow was chosen for the caution light because it is one of the most attention-grabbing colors to the human eye, even at the edge of your vision.",
  "In 2014, University of Michigan researchers found real production traffic controllers reachable over unencrypted, unauthenticated wireless links: the exact weakness this demo's Legacy mode models.",
  "A real traffic cabinet has a hardware Malfunction Management Unit (MMU) wired between the controller and the signal lamps. Even if the controller software is fully compromised, the MMU independently forces flashing red rather than let conflicting greens show, exactly like this demo's Conflict Monitor.",
  "Most real emergency-vehicle preemption hardware uses a line-of-sight optical or radio strobe mounted on the vehicle, not GPS, which is also why it can be spoofed by anyone able to mimic that signal.",
  "Braess's Paradox: adding a brand-new road to a congested network can sometimes make overall travel times worse, not better, by changing how drivers redistribute themselves across it.",
  "Little's Law (L = lambda x W) is the same queueing-theory formula this dashboard uses to estimate average wait time from queue length and arrival rate. It works for traffic, call centers, and checkout lines alike.",
  "MITRE ATT&CK for ICS is a public, real-world catalog of attacker techniques against industrial control systems, the same framework traffic, power-grid, and water-treatment operators use to classify incidents.",
  "Roundabouts physically remove the head-on left-turn conflict behind many of the most severe intersection crashes, which is why traffic engineers increasingly prefer them over signals at lower-volume junctions.",
  "A \"retrofit\" deployment connects new smart cameras and edge compute to a city's existing signal poles and controllers instead of replacing the physical hardware: cheaper and faster to roll out, but it inherits whatever authentication story the old controller already had.",
  "Defense in depth means never letting one broken assumption, a stolen password, a forged signature, be the only thing standing between an attacker and a dangerous outcome, whether the system behind it is a traffic cabinet or a bank.",
];

let lastFunFactIndex = -1;

function showRandomFunFact() {
  if (FUN_FACTS.length <= 1) {
    funFactTextEl.textContent = FUN_FACTS[0] || "";
    return;
  }
  let index = lastFunFactIndex;
  while (index === lastFunFactIndex) {
    index = Math.floor(Math.random() * FUN_FACTS.length);
  }
  lastFunFactIndex = index;
  funFactTextEl.textContent = FUN_FACTS[index];
}

funFactNextEl.addEventListener("click", showRandomFunFact);
showRandomFunFact();
setInterval(showRandomFunFact, 15000);

/* Initial load */

async function loadInitialState() {
  const response = await fetch("/api/network");
  currentNetwork = await response.json();
  render();
}

loadInitialState();
connectWebSocket();
