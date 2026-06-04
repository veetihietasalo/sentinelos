/* SentinelOS build-team dashboard — Event Feed panel.
 * Merges every agent's history into one reverse-chronological stream.
 * Registers against window.Dash; do NOT edit core.js. */
(function () {
  "use strict";

  // ── inject styles once ────────────────────────────────────────────────────────
  (function injectStyles() {
    if (document.getElementById("feed-styles")) return;
    var style = document.createElement("style");
    style.id = "feed-styles";
    style.textContent = [
      ".feed-panel {",
      "  font-family: var(--mono, monospace);",
      "  font-size: 0.78rem;",
      "  line-height: 1.55;",
      "  color: var(--fg, #c8c8d0);",
      "  background: transparent;",
      "}",
      ".feed-empty {",
      "  color: var(--dim, #555);",
      "  padding: 0.5rem 0;",
      "  font-style: italic;",
      "}",
      ".feed-list {",
      "  display: flex;",
      "  flex-direction: column;",
      "  gap: 2px;",
      "}",
      ".feed-row {",
      "  display: grid;",
      "  grid-template-columns: minmax(0,14em) 6em 1ch 1fr;",
      "  column-gap: 0.5em;",
      "  align-items: baseline;",
      "  padding: 2px 0;",
      "  border-bottom: 1px solid rgba(255,255,255,0.04);",
      "  overflow: hidden;",
      "}",
      ".feed-row:last-child { border-bottom: none; }",
      ".feed-who {",
      "  color: var(--fg, #c8c8d0);",
      "  opacity: 0.75;",
      "  overflow: hidden;",
      "  text-overflow: ellipsis;",
      "  white-space: nowrap;",
      "}",
      ".feed-ts {",
      "  color: var(--dim, #555);",
      "  white-space: nowrap;",
      "  text-align: right;",
      "}",
      ".feed-glyph { font-size: 0.9em; }",
      ".feed-glyph.working { color: var(--working, #4fc3f7); }",
      ".feed-glyph.done    { color: var(--done,    #81c784); }",
      ".feed-glyph.blocked { color: var(--blocked, #e57373); }",
      ".feed-glyph.idle    { color: var(--idle,    #888);    }",
      ".feed-glyph.log     { color: var(--dim,     #555);    }",
      ".feed-task {",
      "  overflow: hidden;",
      "  text-overflow: ellipsis;",
      "  white-space: nowrap;",
      "}",
      ".feed-task.working { color: var(--working, #4fc3f7); }",
      ".feed-task.done    { color: var(--done,    #81c784); }",
      ".feed-task.blocked { color: var(--blocked, #e57373); }",
      ".feed-task.idle    { color: var(--idle,    #888);    }",
      ".feed-task.log     { color: var(--dim,     #555);    }"
    ].join("\n");
    document.head.appendChild(style);
  })();

  // ── cap constant ─────────────────────────────────────────────────────────────
  var MAX_ROWS = 60;

  // ── render hook ──────────────────────────────────────────────────────────────
  window.Dash.onRender(function (data) {
    var h         = window.Dash.helpers;
    var escHtml   = h.escHtml;
    var fmtTime   = h.fmtTime;
    var parseTs   = h.parseTs;
    var ROLE_ICON = h.ROLE_ICON;
    var FLOW_ICON = h.FLOW_ICON;

    var body = window.Dash.panel("feed", "Event Feed");

    // ── inject wrapper once ───────────────────────────────────────────────────
    if (!body.querySelector(".feed-panel")) {
      body.innerHTML = '<div class="feed-panel"><div class="feed-list"></div></div>';
    }
    var list = body.querySelector(".feed-list");

    // ── collect + tag every history entry ────────────────────────────────────
    var agents  = (data && Array.isArray(data.agents)) ? data.agents : [];
    var entries = [];
    agents.forEach(function (agent) {
      var hist = Array.isArray(agent.history) ? agent.history : [];
      hist.forEach(function (entry) {
        entries.push({
          agentName: agent.name,
          ts:        entry.ts     || "",
          kind:      entry.kind   || "status",
          status:    entry.status || "",
          task:      entry.task   || "—",
          tsMs:      parseTs(entry.ts)
        });
      });
    });

    // ── sort DESC (newest first); null timestamps sink to bottom ─────────────
    entries.sort(function (a, b) {
      if (a.tsMs == null && b.tsMs == null) return 0;
      if (a.tsMs == null) return 1;
      if (b.tsMs == null) return -1;
      return b.tsMs - a.tsMs;
    });

    // ── cap to MAX_ROWS ───────────────────────────────────────────────────────
    if (entries.length > MAX_ROWS) entries = entries.slice(0, MAX_ROWS);

    // ── empty state ───────────────────────────────────────────────────────────
    if (entries.length === 0) {
      list.innerHTML = '<div class="feed-empty">no events yet.</div>';
      return;
    }

    // ── build rows ────────────────────────────────────────────────────────────
    var html = entries.map(function (e) {
      var isLog   = e.kind === "log";
      var cls     = isLog ? "log" : (e.status || "idle");
      var glyph   = (FLOW_ICON[cls] != null) ? FLOW_ICON[cls] : "·";
      var icon    = ROLE_ICON[e.agentName] || "🤖"; /* 🤖 */
      var timeStr = fmtTime(e.ts);

      return (
        '<div class="feed-row">' +
        '<span class="feed-who">' + icon + "&thinsp;" + escHtml(e.agentName) + "</span>" +
        '<span class="feed-ts">'  + escHtml(timeStr) + "</span>" +
        '<span class="feed-glyph ' + escHtml(cls) + '">' + escHtml(glyph) + "</span>" +
        '<span class="feed-task '  + escHtml(cls) + '">' + escHtml(e.task)  + "</span>" +
        "</div>"
      );
    }).join("");

    list.innerHTML = html;
  });

})();
