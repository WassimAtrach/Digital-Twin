/*
 * car-sim.js
 *
 * The live junction canvas renderer: cars that actually move, stop on
 * red, and visibly pile up. Originally lived entirely inside app.js as
 * a single canvas bound to whichever junction was selected; pulled out
 * here so it can be reused unchanged by both:
 *   - app.js's SOC dashboard: one canvas, the currently-selected
 *     junction (the "attack simulator" view: pick a target, watch it).
 *   - monitor.js's Live Network Monitor: five canvases, all five
 *     junctions animating at once (a real-time overview, not tied to
 *     whichever one you're about to attack).
 *
 * createCarSimRenderer(canvas) returns one independent, stateful
 * renderer bound to a single <canvas> element. Each call creates its
 * own private car-position state, so multiple renderers (one per
 * canvas) never share or clash with each other's cars: this is what
 * lets the monitor page run five of these side by side.
 *
 * No build step, plain classic <script> like every other file here: a
 * page that wants this loads car-sim.js before its own script and
 * calls createCarSimRenderer() as a normal global function.
 */

const MAX_VISIBLE_CARS_PER_APPROACH = 5;
const CAR_LENGTH = 13; /* along the direction of travel */
const CAR_WIDTH = 8; /* across the direction of travel */
/* CAR_SPACING must exceed the car's own footprint (CAR_LENGTH) by a
   real margin (CAR_GAP). An earlier version set them equal, so queued
   cars sat edge-to-edge with zero visible gap and read as one solid
   merged bar instead of distinct vehicles. */
const CAR_GAP = 9;
const CAR_SPACING = CAR_LENGTH + CAR_GAP;
const CAR_FLOW_SPEED = 2.6;
const STOP_LINE = 45; /* distance from center where a red light holds a car */
const CAR_EXIT_DISTANCE = 55; /* how far past center before an exiting car is removed */
const CAR_COLORS = { N: "#3987e5", S: "#199e70", E: "#d95926", W: "#c98500" };
/* Chance, per reconcile() call, of spawning one ambient (non-queued)
   car on an approach that currently has zero backlog and zero cars
   already shown -- see reconcile()'s own comment for why an empty
   queue shouldn't mean an empty-looking road. Tuned by feel for "an
   otherwise-idle approach shows a car within a handful of reconciles,
   not on literally every one of them": at the live page's ~2s
   reconcile cadence that is roughly one new car every ~8 real seconds
   per idle approach on average. */
const AMBIENT_CAR_CHANCE = 0.25;

function approachLightState(intersection, approach) {
  const { phase, alarm } = intersection;

  if (phase === "CONFLICT") return "green"; /* the dangerous state: every approach shows green at once */

  if (phase === "ALL_RED") {
    if (alarm === "FAILSAFE") {
      const blinkOn = Math.floor(Date.now() / 500) % 2 === 0;
      return blinkOn ? "red" : "off";
    }
    return "red";
  }

  if (phase === "NS_GREEN") return approach === "N" || approach === "S" ? "green" : "red";
  if (phase === "EW_GREEN") return approach === "E" || approach === "W" ? "green" : "red";
  return "red";
}

function drawBulb(ctx, cx, cy, litColor, isLit) {
  ctx.beginPath();
  ctx.arc(cx, cy, 5, 0, Math.PI * 2);
  ctx.fillStyle = isLit ? litColor : "#1c2942";
  ctx.fill();
  if (isLit) {
    ctx.save();
    ctx.shadowColor = litColor;
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.restore();
  }
}

function drawSignalHead(ctx, state, x, y, label) {
  ctx.fillStyle = "#0b1220";
  ctx.fillRect(x, y, 16, 30);
  drawBulb(ctx, x + 8, y + 8, "#e74c3c", state === "red");
  drawBulb(ctx, x + 8, y + 21, "#2ecc71", state === "green");

  ctx.fillStyle = "#8ea0bd";
  ctx.font = "10px system-ui, sans-serif";
  ctx.textAlign = "center";
  ctx.fillText(label, x + 8, y + 44);
  ctx.textAlign = "left";
}

function roundedRectPath(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

/* Draws one car as a rounded body with a slightly darker "windshield"
   band on its leading edge, so it reads as a vehicle with a front and
   back rather than an anonymous colored block. */
function drawCar(ctx, approach, x, y, w, h) {
  roundedRectPath(ctx, x, y, w, h, 2.5);
  ctx.fillStyle = CAR_COLORS[approach];
  ctx.fill();

  ctx.fillStyle = "rgba(0, 0, 0, 0.32)";
  if (approach === "N") {
    roundedRectPath(ctx, x, y, w, h * 0.32, 2);
  } else if (approach === "S") {
    roundedRectPath(ctx, x, y + h * 0.68, w, h * 0.32, 2);
  } else if (approach === "E") {
    roundedRectPath(ctx, x, y, w * 0.32, h, 2);
  } else {
    roundedRectPath(ctx, x + w * 0.68, y, w * 0.32, h, 2);
  }
  ctx.fill();
}

/* One independent car-simulation + renderer bound to `canvas`. Every
   method takes the intersection snapshot to work from explicitly
   (never reads a shared/global "currently selected" variable), so a
   page can drive any number of these independently, each pointed at a
   different junction.
*/
function createCarSimRenderer(canvas) {
  const ctx = canvas.getContext("2d");
  let carSim = { N: [], S: [], E: [], W: [] };

  function reset() {
    carSim = { N: [], S: [], E: [], W: [] };
  }

  /* Adds/removes car entries to match the server's queue numbers.
     Called on every network update; tick()/draw() below then animate
     and render whatever reconcile() last set up, independently of the
     update cadence. */
  function reconcile(intersection) {
    ["N", "S", "E", "W"].forEach((approach) => {
      const rawQueue = intersection.queues[approach] ?? 0;
      const cars = carSim[approach];

      if (rawQueue > 0) {
        const targetCount = Math.min(MAX_VISIBLE_CARS_PER_APPROACH, Math.round(rawQueue));
        while (cars.length < targetCount) {
          const back = cars.length ? cars[cars.length - 1].distance : STOP_LINE;
          cars.push({ distance: Math.max(back + CAR_SPACING, STOP_LINE + CAR_SPACING) });
        }
        while (cars.length > targetCount) {
          cars.pop();
        }
        return;
      }

      /* Zero backlog isn't the same as an unused road. queues[approach]
         tracks vehicles waiting to be served; it says nothing about a
         car that arrives and drives straight through without ever
         queuing, which is most cars during light traffic. Without
         this, any approach with a fractional queue under 0.5 (the
         normal case for most of a calm hour: Math.round(0.3) === 0)
         rendered as permanently empty, reported as "there must be some
         cars" even during real, non-zero traffic hours.

         Tops up to exactly one ambient car, at a low chance per
         reconcile, only when the approach is already empty -- never
         forces one away early on a later miss, so a spawned car always
         clears through normally via tick()'s existing drive/exit logic
         instead of visibly vanishing mid-wait. A flat rate, not scaled
         by the real hourly multiplier or this junction's calibration
         factor: a deliberate simplification, not a claim that this
         reflects real relative traffic volume the way queues/congestion
         do. */
      if (cars.length === 0 && Math.random() < AMBIENT_CAR_CHANCE) {
        cars.push({ distance: STOP_LINE + CAR_SPACING });
      }
    });
  }

  function tick(intersection) {
    ["N", "S", "E", "W"].forEach((approach) => {
      const isGreen = approachLightState(intersection, approach) === "green";
      const cars = carSim[approach];
      cars.forEach((car) => {
        if (isGreen) {
          car.distance -= CAR_FLOW_SPEED;
        } else if (car.distance < STOP_LINE) {
          /* Already past the stop line when the light changed: a real
             driver mid-crossing doesn't slam on the brakes inside the
             junction, so let it finish clearing instead of freezing it
             there. Only cars still behind the stop line hold position. */
          car.distance -= CAR_FLOW_SPEED;
        }
      });
      while (cars.length && cars[0].distance < -CAR_EXIT_DISTANCE) {
        cars.shift();
      }
    });
  }

  function draw(intersection) {
    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h / 2;
    const roadWidth = 80;

    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = "#0d0d0d";
    ctx.fillRect(0, 0, w, h);

    ctx.fillStyle = "#22262b";
    ctx.fillRect(0, cy - roadWidth / 2, w, roadWidth);
    ctx.fillRect(cx - roadWidth / 2, 0, roadWidth, h);

    ctx.strokeStyle = "#3a3f46";
    ctx.setLineDash([6, 6]);
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(0, cy);
    ctx.lineTo(w, cy);
    ctx.moveTo(cx, 0);
    ctx.lineTo(cx, h);
    ctx.stroke();
    ctx.setLineDash([]);

    /* Stop-line markings: a visual reason cars queue exactly where they
       do, rather than an unexplained empty gap before the junction box. */
    ctx.strokeStyle = "rgba(255, 255, 255, 0.35)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(cx - roadWidth / 2, cy - STOP_LINE);
    ctx.lineTo(cx, cy - STOP_LINE);
    ctx.moveTo(cx, cy + STOP_LINE);
    ctx.lineTo(cx + roadWidth / 2, cy + STOP_LINE);
    ctx.moveTo(cx + STOP_LINE, cy - roadWidth / 2);
    ctx.lineTo(cx + STOP_LINE, cy);
    ctx.moveTo(cx - STOP_LINE, cy);
    ctx.lineTo(cx - STOP_LINE, cy + roadWidth / 2);
    ctx.stroke();

    /* Right-hand-traffic lane offsets: a car heading south (the N
       approach) keeps to the west (left, on screen) half of the
       vertical road; a car heading north (S approach) keeps to the
       east (right) half, and the equivalent for the horizontal road.
       Without this, both directions rendered on the same centerline,
       which is why opposing traffic used to look like it shared one
       lane. */
    const LANE_OFFSET = roadWidth / 4;

    ["N", "S", "E", "W"].forEach((approach) => {
      const along = approach === "N" || approach === "S";
      const cw = along ? CAR_WIDTH : CAR_LENGTH;
      const ch = along ? CAR_LENGTH : CAR_WIDTH;
      carSim[approach].forEach((car) => {
        const d = car.distance;
        let x, y;
        if (approach === "N") {
          x = cx - LANE_OFFSET - cw / 2;
          y = cy - d - ch / 2;
        } else if (approach === "S") {
          x = cx + LANE_OFFSET - cw / 2;
          y = cy + d - ch / 2;
        } else if (approach === "E") {
          x = cx + d - cw / 2;
          y = cy - LANE_OFFSET - ch / 2;
        } else {
          x = cx - d - cw / 2;
          y = cy + LANE_OFFSET - ch / 2;
        }
        drawCar(ctx, approach, x, y, cw, ch);
      });
    });

    /* Each signal is placed at the corner adjacent to the lane it
       controls: NW serves the N (southbound, west-lane) approach, SE
       serves S, NE serves E, SW serves W, so it sits right where that
       lane's queue forms rather than at an arbitrary offset. */
    drawSignalHead(ctx, approachLightState(intersection, "N"), cx - roadWidth / 2 - 24, cy - roadWidth / 2 - 42, "North");
    drawSignalHead(ctx, approachLightState(intersection, "S"), cx + roadWidth / 2 + 8, cy + roadWidth / 2 + 6, "South");
    drawSignalHead(ctx, approachLightState(intersection, "E"), cx + roadWidth / 2 + 8, cy - roadWidth / 2 - 42, "East");
    drawSignalHead(ctx, approachLightState(intersection, "W"), cx - roadWidth / 2 - 24, cy + roadWidth / 2 + 6, "West");
  }

  return { reset, reconcile, tick, draw };
}
