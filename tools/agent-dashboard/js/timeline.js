/* timeline.js — Team Timeline (Gantt) panel for the SentinelOS build dashboard */
(function () {
  'use strict';

  /* ── inject scoped styles exactly once ── */
  if (!document.getElementById('gantt-style')) {
    const s = document.createElement('style');
    s.id = 'gantt-style';
    s.textContent = `
      .gantt-wrap {
        font-family: var(--mono, monospace);
        color: var(--text, #cdd6f4);
        padding: 10px 14px;
        box-sizing: border-box;
        overflow-x: auto;
      }
      .gantt-empty {
        color: var(--dim, #6c7086);
        font-size: 0.85em;
        padding: 18px 0;
        text-align: center;
      }
      .gantt-axis {
        display: flex;
        position: relative;
        height: 20px;
        margin-bottom: 4px;
        border-bottom: 1px solid var(--line, #313244);
      }
      .gantt-tick {
        position: absolute;
        font-size: 0.7em;
        color: var(--dim, #6c7086);
        transform: translateX(-50%);
        white-space: nowrap;
      }
      .gantt-row {
        display: flex;
        align-items: center;
        height: 26px;
        margin-bottom: 4px;
      }
      .gantt-label {
        width: 160px;
        min-width: 160px;
        font-size: 0.8em;
        color: var(--dim, #6c7086);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        padding-right: 8px;
        box-sizing: border-box;
      }
      .gantt-track {
        position: relative;
        flex: 1;
        height: 18px;
        background: var(--panel, #1e1e2e);
        border: 1px solid var(--line, #313244);
        border-radius: 3px;
        overflow: hidden;
      }
      .gantt-bar {
        position: absolute;
        height: 100%;
        border-radius: 2px;
        min-width: 2px;
      }
      .gantt-bar-working {
        background: var(--working, #f9a825);
        opacity: 0.85;
      }
      .gantt-bar-done {
        background: var(--done, #a6e3a1);
        opacity: 0.7;
      }
    `;
    document.head.appendChild(s);
  }

  /* ── helpers ── */
  const parseTs = function (ts) {
    return (Dash.helpers && Dash.helpers.parseTs) ? Dash.helpers.parseTs(ts) : (ts ? new Date(ts).getTime() : null);
  };
  const escHtml = function (s) {
    return (Dash.helpers && Dash.helpers.escHtml)
      ? Dash.helpers.escHtml(s)
      : String(s).replace(/[&<>"']/g, function (c) {
          return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
        });
  };
  const ROLE_ICON = (Dash.helpers && Dash.helpers.ROLE_ICON) || {};
  const icon = function (name) { return ROLE_ICON[name] || '🤖'; };

  /* ── panel ── */
  const container = Dash.panel('timeline', 'Team Timeline');

  /* ── render ── */
  Dash.onRender(function (data) {
    const agents = (data && data.agents) || [];

    /* collect agents that have history */
    const rows = agents.filter(function (a) { return a.history && a.history.length > 0; });

    if (rows.length === 0) {
      container.innerHTML = '<div class="gantt-wrap"><div class="gantt-empty">No history yet — agents will appear here once they start work.</div></div>';
      return;
    }

    /* determine time range */
    let tMin = Infinity;
    rows.forEach(function (a) {
      a.history.forEach(function (h) {
        const ms = parseTs(h.ts);
        if (ms !== null && ms < tMin) { tMin = ms; }
      });
    });
    if (!isFinite(tMin)) {
      container.innerHTML = '<div class="gantt-wrap"><div class="gantt-empty">No valid timestamps found.</div></div>';
      return;
    }
    const tMax = Date.now();
    const span = Math.max(tMax - tMin, 1);

    /* extract working spans for one agent */
    function getSpans(agent) {
      const h = agent.history;
      const spans = [];
      for (let i = 0; i < h.length; i++) {
        const entry = h[i];
        if (entry.kind === 'status' && entry.status === 'working') {
          const start = parseTs(entry.ts);
          if (start === null) { continue; }
          let end = null;
          if (i + 1 < h.length) { end = parseTs(h[i + 1].ts); }
          if (end === null) { end = tMax; }
          spans.push({ start: start, end: end });
        }
      }
      return spans;
    }

    /* build tick marks (6 ticks = 0 .. 5) */
    const TICK_COUNT = 5;
    const ticks = [];
    for (let t = 0; t <= TICK_COUNT; t++) {
      const ms = tMin + (span * t) / TICK_COUNT;
      const d = new Date(ms);
      const label = d.toTimeString().slice(0, 8); /* HH:MM:SS */
      ticks.push({ pct: (t / TICK_COUNT) * 100, label: label });
    }

    /* render HTML */
    let html = '<div class="gantt-wrap">';

    /* axis row */
    html += '<div style="display:flex;align-items:flex-end;">';
    html += '<div style="width:160px;min-width:160px;"></div>';
    html += '<div class="gantt-axis" style="flex:1;">';
    ticks.forEach(function (tick) {
      html += '<span class="gantt-tick" style="left:' + tick.pct.toFixed(2) + '%">' + escHtml(tick.label) + '</span>';
    });
    html += '</div></div>';

    /* agent rows */
    rows.forEach(function (agent) {
      const spans = getSpans(agent);
      const labelTxt = escHtml(icon(agent.role) + ' ' + agent.name);
      html += '<div class="gantt-row">';
      html += '<div class="gantt-label" title="' + escHtml(agent.name) + '">' + labelTxt + '</div>';
      html += '<div class="gantt-track">';
      spans.forEach(function (s) {
        const left = ((s.start - tMin) / span) * 100;
        const width = Math.max(((s.end - s.start) / span) * 100, 0.2);
        const cls = (s.end >= tMax) ? 'gantt-bar-working' : 'gantt-bar-done';
        html += '<div class="gantt-bar ' + cls + '" style="left:' + left.toFixed(3) + '%;width:' + width.toFixed(3) + '%"></div>';
      });
      html += '</div>';
      html += '</div>';
    });

    html += '</div>';
    container.innerHTML = html;
  });

}());
