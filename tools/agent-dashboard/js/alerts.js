/* SentinelOS build-team dashboard — alerts module.
 * Provides two features:
 *   1. Browser Notifications + WebAudio beeps on agent status transitions
 *      (done / blocked). Fired on Dash.onPoll; skips the very first poll.
 *   2. Stale-agent detection panel: flags any working agent whose latest
 *      history entry is older than 3 minutes. Rendered on Dash.onRender.
 *
 * Depends on window.Dash (core.js). Plain browser JS, no build, no deps. */
(function () {
  "use strict";

  /* ── scoped styles (injected once) ──────────────────────────────────────── */
  (function injectStyles() {
    if (document.getElementById("alerts-styles")) return;
    var style = document.createElement("style");
    style.id = "alerts-styles";
    style.textContent = [
      ".alerts-panel { font-size: 13px; line-height: 1.6; }",
      ".alerts-healthy { color: #6fcf97; display: flex; align-items: center; gap: 6px; }",
      ".alerts-healthy::before { content: '\\2713'; font-weight: 700; }",
      ".alerts-stale-list { list-style: none; margin: 0; padding: 0; }",
      ".alerts-stale-item {",
      "  display: flex; align-items: baseline; gap: 6px;",
      "  padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,.06);",
      "}",
      ".alerts-stale-item:last-child { border-bottom: none; }",
      ".alerts-warn-icon { color: #f2994a; flex-shrink: 0; }",
      ".alerts-agent-name { color: #e0e0e0; font-weight: 600; }",
      ".alerts-stale-detail { color: #9e9e9e; font-size: 12px; }",
    ].join("\n");
    document.head.appendChild(style);
  }());

  /* ── notification permission: request once on first gesture or first poll ─ */
  var permissionRequested = false;
  function ensurePermission() {
    if (permissionRequested) return;
    if (!("Notification" in window)) { permissionRequested = true; return; }
    if (Notification.permission === "granted" || Notification.permission === "denied") {
      permissionRequested = true; return;
    }
    permissionRequested = true;
    Notification.requestPermission().catch(function () { /* silent */ });
  }
  document.addEventListener("click", ensurePermission, { once: true });
  document.addEventListener("keydown", ensurePermission, { once: true });

  /* ── WebAudio soft beep ─────────────────────────────────────────────────── */
  var audioCtx = null;
  function getAudioCtx() {
    if (!audioCtx) {
      try {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      } catch (_) { /* no audio support */ }
    }
    return audioCtx;
  }
  function beep(freqHz, durationMs) {
    var ctx = getAudioCtx();
    if (!ctx) return;
    try {
      var osc = ctx.createOscillator();
      var gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = "sine";
      osc.frequency.setValueAtTime(freqHz, ctx.currentTime);
      gain.gain.setValueAtTime(0.08, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + durationMs / 1000);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + durationMs / 1000);
    } catch (_) { /* silent on any audio error */ }
  }

  /* ── fire one notification + beep for a status transition ──────────────── */
  function fireNotification(agent, newStatus) {
    var prefix = newStatus === "done" ? "✓" : "✕";
    var title = prefix + " " + agent.name + " · " + newStatus;
    var body = agent.task || "";

    if ("Notification" in window && Notification.permission === "granted") {
      try { new Notification(title, { body: body, silent: true }); } catch (_) { /* silenced */ }
    }

    /* done → high pitch (880 Hz, 180 ms); blocked → low pitch (330 Hz, 280 ms) */
    if (newStatus === "done") {
      beep(880, 180);
    } else {
      beep(330, 280);
    }
  }

  /* ── 1. NOTIFICATIONS — onPoll ──────────────────────────────────────────── */
  Dash.onPoll(function (data, prev) {
    /* Skip the very first poll — no baseline to diff against. */
    if (prev === null) { ensurePermission(); return; }
    ensurePermission();

    var agents = (data && data.agents) || [];
    var prevAgents = (prev && prev.agents) || [];

    /* Build quick lookup of previous statuses by agent name. */
    var prevStatus = {};
    prevAgents.forEach(function (a) { prevStatus[a.name] = a.status; });

    agents.forEach(function (agent) {
      var was = prevStatus[agent.name];   /* undefined = brand-new agent */
      var now = agent.status;
      /* Only fire when transitioning INTO done or blocked from a different state. */
      if ((now === "done" || now === "blocked") && was !== now) {
        fireNotification(agent, now);
      }
    });
  });

  /* ── 2. STALE DETECTION — onRender ─────────────────────────────────────── */
  var STALE_MS = 3 * 60 * 1000; /* 3 minutes */

  Dash.onRender(function (data) {
    var parseTs = Dash.helpers.parseTs;
    var fmtDur  = Dash.helpers.fmtDur;
    var escHtml = Dash.helpers.escHtml;

    var agents = (data && data.agents) || [];
    var now = Date.now();

    var stale = agents.filter(function (a) {
      if (a.status !== "working") return false;
      var hist = Array.isArray(a.history) ? a.history : [];
      if (hist.length === 0) return false;
      var latest = hist[hist.length - 1];
      var t = parseTs(latest.ts);
      return t !== null && (now - t) > STALE_MS;
    });

    var panel = Dash.panel("stale", "Stale / stuck");
    panel.className = "alerts-panel";

    if (stale.length === 0) {
      panel.innerHTML = '<div class="alerts-healthy">all active agents healthy</div>';
      return;
    }

    var items = stale.map(function (a) {
      var hist = a.history;
      var latest = hist[hist.length - 1];
      var t = parseTs(latest.ts);
      var age = (t !== null) ? fmtDur(now - t) : "unknown";
      return '<li class="alerts-stale-item">'
        + '<span class="alerts-warn-icon">⚠</span>'
        + '<span class="alerts-agent-name">' + escHtml(a.name) + '</span>'
        + '<span class="alerts-stale-detail">— working ' + escHtml(age) + ' with no update</span>'
        + '</li>';
    }).join("");

    panel.innerHTML = '<ul class="alerts-stale-list">' + items + "</ul>";
  });

}());
