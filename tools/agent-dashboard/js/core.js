/* SentinelOS build-team dashboard — core.
 * Defines window.Dash: shared state, the render pipeline, and a small plug-in API
 * that feature modules (timeline.js, feed.js, alerts.js, …) register against.
 * Feature modules MUST NOT edit this file — they call Dash.onRender / Dash.onPoll /
 * Dash.panel and read Dash.data / Dash.helpers. */
(function () {
  "use strict";

  const REPO = "https://github.com/veetihietasalo/sentinelos";
  const POLL_MS = 5000;
  const STORAGE_KEY = "sentinelos-dash-v1";

  const STAGE_AGENTS = {
    spec: ["kernel-architect", "docs-writer"],
    architect: ["kernel-architect"],
    implement: ["hal-specialist", "memory-engineer", "kernel-engineer", "driver-engineer",
      "ui-engineer", "scheduler-engineer", "userland-engineer", "security-engineer"],
    verify: ["verification-engineer"], test: ["test-engineer"], review: ["kernel-reviewer"]
  };
  const ROLE_ICON = {
    "kernel-architect": "🏛️", "hal-specialist": "⚙️", "kernel-engineer": "🦀",
    "memory-engineer": "🧠", "driver-engineer": "🔌", "scheduler-engineer": "⏱️",
    "userland-engineer": "📦", "security-engineer": "🛡️", "ui-engineer": "🎨",
    "verification-engineer": "🔬", "test-engineer": "🧪", "toolchain-engineer": "🔧",
    "kernel-reviewer": "🔎", "docs-writer": "📝"
  };
  const FLOW_ICON = { working: "▶", done: "✓", blocked: "✕", idle: "○", log: "·" };
  const STATUS_ORDER = ["working", "done", "idle", "blocked"];

  // ── helpers ───────────────────────────────────────────────────────────────
  function escHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function parseTs(ts) { if (!ts) return null; const t = new Date(ts).getTime(); return isNaN(t) ? null : t; }
  function fmtTime(ts) { if (!ts) return ""; const p = String(ts).split("T"); return (p[1] || p[0] || "").slice(0, 8); }
  function fmtDur(ms) {
    if (ms == null || isNaN(ms) || ms < 0) return "";
    const s = Math.floor(ms / 1000); if (s < 60) return s + "s";
    const m = Math.floor(s / 60), rs = s % 60; if (m < 60) return rs ? `${m}m ${rs}s` : `${m}m`;
    const h = Math.floor(m / 60), rm = m % 60; return rm ? `${h}h ${rm}m` : `${h}h`;
  }
  function fmtTokens(n) {
    if (n == null || isNaN(n)) return "";
    return n >= 1000 ? (n / 1000).toFixed(n >= 100000 ? 0 : 1) + "k tok" : n + " tok";
  }

  // ── shared state (persisted: feature 5) ─────────────────────────────────────
  const state = { expanded: new Set(), hidden: new Set(), stageFilter: null };

  function loadState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY); if (!raw) return;
      const o = JSON.parse(raw);
      if (Array.isArray(o.expanded)) o.expanded.forEach((n) => state.expanded.add(n));
      if (Array.isArray(o.hidden)) o.hidden.forEach((n) => state.hidden.add(n));
      if (typeof o.stageFilter === "string") state.stageFilter = o.stageFilter;
    } catch (_) { /* ignore */ }
  }
  function saveState() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        expanded: [...state.expanded], hidden: [...state.hidden], stageFilter: state.stageFilter
      }));
    } catch (_) { /* ignore */ }
  }

  // ── the plug-in registry ────────────────────────────────────────────────────
  const renderHooks = [];
  const pollHooks = [];

  const Dash = {
    data: null, prev: null, state,
    REPO, POLL_MS,
    helpers: { escHtml, parseTs, fmtTime, fmtDur, fmtTokens, ROLE_ICON, FLOW_ICON, STAGE_AGENTS, STATUS_ORDER },
    onRender(fn) { if (typeof fn === "function") renderHooks.push(fn); },
    onPoll(fn) { if (typeof fn === "function") pollHooks.push(fn); },
    /** Create/return the mounted body <div> for a feature panel in #ext-panels. */
    panel(id, title) {
      const host = document.getElementById("ext-panels");
      let sec = document.getElementById("panel-" + id);
      if (!sec) {
        sec = document.createElement("div");
        sec.className = "ext-panel";
        sec.id = "panel-" + id;
        sec.innerHTML = `<div class="section-label">${escHtml(title)}</div><div class="ext-body"></div>`;
        host.appendChild(sec);
      }
      return sec.querySelector(".ext-body");
    },
    rerender() { if (this.data) renderAll(this.data); }
  };
  window.Dash = Dash;

  // ── now-building banner ─────────────────────────────────────────────────────
  function renderNowBuilding(agents) {
    const el = document.getElementById("nowbuilding");
    const working = agents.filter((a) => a.status === "working");
    const blocked = agents.filter((a) => a.status === "blocked");
    if (blocked.length) {
      el.className = "nowbuilding"; el.style.borderLeftColor = "var(--blocked)";
      el.innerHTML = `⚠ <b style="color:var(--blocked)">blocked:</b> ` +
        blocked.map((a) => `<span class="nb-agent">${ROLE_ICON[a.name] || ""} ${escHtml(a.name)}</span> — ${escHtml(a.task)}`).join(" &nbsp;·&nbsp; ");
      return;
    }
    if (working.length === 0) {
      el.className = "nowbuilding idlebar"; el.innerHTML = `◦ team idle — no agents currently building.`; return;
    }
    el.className = "nowbuilding"; el.style.borderLeftColor = "var(--working)";
    el.innerHTML = `<b>now building (${working.length}):</b> ` +
      working.map((a) => `${ROLE_ICON[a.name] || ""} <span class="nb-agent">${escHtml(a.name)}</span> — ${escHtml(a.task)}`).join(" &nbsp;·&nbsp; ");
  }

  // ── pipeline (auto-detect phase; click a stage to filter: feature 7) ─────────
  function stageState(stage, agents) {
    const names = STAGE_AGENTS[stage] || [];
    const mine = agents.filter((a) => names.includes(a.name));
    if (mine.some((a) => a.status === "blocked")) return "blocked";
    if (mine.some((a) => a.status === "working")) return "working";
    if (mine.length && mine.some((a) => a.status === "done") && mine.every((a) => a.status === "done" || a.status === "idle")) return "done";
    return "idle";
  }
  function renderPipeline(stages, agents) {
    const el = document.getElementById("pipeline"); el.innerHTML = "";
    const states = stages.map((s) => stageState(s, agents));
    let current = -1;
    for (let i = 0; i < stages.length; i++) if (states[i] === "working" || states[i] === "blocked") current = i;
    if (current === -1) for (let i = 0; i < stages.length; i++) if (states[i] === "done") current = i;
    stages.forEach((s, i) => {
      const stage = document.createElement("span");
      stage.className = "stage " + states[i] + (i === current ? " current" : "") + (state.stageFilter === s ? " stage-selected" : "");
      stage.innerHTML = `<span class="sdot"></span>${escHtml(s)}`;
      stage.title = "filter to " + s + " agents";
      stage.addEventListener("click", () => {
        state.stageFilter = state.stageFilter === s ? null : s; saveState(); Dash.rerender();
      });
      el.appendChild(stage);
      if (i < stages.length - 1) { const a = document.createElement("span"); a.className = "stage-arrow"; a.textContent = "›"; el.appendChild(a); }
    });
    document.getElementById("phase-hint").textContent =
      current >= 0 ? `— phase: ${stages[current]} (${states[current] === "done" ? "completed" : states[current]})` : "";
  }

  // ── status filter chips ─────────────────────────────────────────────────────
  function renderFilters(agents) {
    const counts = { working: 0, done: 0, idle: 0, blocked: 0 };
    agents.forEach((a) => { if (counts[a.status] !== undefined) counts[a.status]++; });
    const el = document.getElementById("filters"); el.innerHTML = "";
    STATUS_ORDER.forEach((st) => {
      const chip = document.createElement("button");
      chip.className = "filter-chip " + st + (state.hidden.has(st) ? " off" : "");
      chip.title = (state.hidden.has(st) ? "show " : "hide ") + st + " agents";
      chip.innerHTML = `<span class="dot ${st}"></span> ${st} <span class="fc">${counts[st]}</span>`;
      chip.addEventListener("click", () => {
        if (state.hidden.has(st)) state.hidden.delete(st); else state.hidden.add(st);
        saveState(); Dash.rerender();
      });
      el.appendChild(chip);
    });
    if (state.stageFilter) {
      const note = document.createElement("span");
      note.className = "stagefilter-note";
      note.textContent = `stage: ${state.stageFilter} ✕`;
      note.title = "clear stage filter";
      note.addEventListener("click", () => { state.stageFilter = null; saveState(); Dash.rerender(); });
      el.appendChild(note);
    }
  }

  // ── output flow (durations + bar + live counter + commit links: feature 8) ───
  function flowHtml(a) {
    let hist = Array.isArray(a.history) ? a.history.slice() : [];
    if (hist.length === 0) hist = [{ ts: "", kind: "status", status: a.status, task: a.task }];
    const tsMs = hist.map((e) => parseTs(e.ts));
    const durs = hist.map((e, i) => (i < hist.length - 1 && tsMs[i] != null && tsMs[i + 1] != null) ? (tsMs[i + 1] - tsMs[i]) : null);
    const finite = durs.filter((d) => d != null);
    const maxDur = finite.length ? Math.max(...finite) : 1;

    const rows = hist.map((e, i) => {
      const isLog = e.kind === "log";
      const cls = isLog ? "log" : (e.status || "idle");
      const verb = isLog ? "log" : (e.status || "");
      const isLast = i === hist.length - 1;
      const ts = fmtTime(e.ts);
      const icon = FLOW_ICON[cls] || "·";
      let extra = "";
      if (durs[i] != null) {
        const pct = Math.max(4, Math.round(durs[i] / maxDur * 100));
        extra = `<span class="flow-dur">ran ${escHtml(fmtDur(durs[i]))}</span><div class="flow-bar"><span style="width:${pct}%"></span></div>`;
      } else if (isLast && !isLog && e.status === "working" && tsMs[i] != null) {
        extra = `<span class="running-chip">running <span class="live" data-since="${tsMs[i]}"></span></span>`;
      }
      const commit = e.commit ? `<a class="flow-commit" href="${REPO}/commit/${encodeURIComponent(e.commit)}" target="_blank" rel="noopener">⎇ ${escHtml(String(e.commit).slice(0, 7))}</a>` : "";
      return `<div class="flow-entry ${cls}${isLast ? " latest" : ""}">`
        + `<span class="flow-icon">${icon}</span>`
        + (ts ? `<span class="flow-ts">${escHtml(ts)}</span>` : "")
        + `<span class="flow-verb ${cls}">${escHtml(verb)}</span>`
        + `<span class="flow-task">${escHtml(e.task || "—")}</span>`
        + commit + extra + `</div>`;
    }).join("");
    return `<div class="card-flow"><div class="flow-label">output flow</div><div class="flow-list">${rows}</div></div>`;
  }

  // ── agent cards (role icons + token badge: feature 6) ────────────────────────
  function renderAgents(agents) {
    const grid = document.getElementById("grid"); grid.innerHTML = "";
    let visible = agents.filter((a) => !state.hidden.has(a.status));
    if (state.stageFilter) {
      const names = STAGE_AGENTS[state.stageFilter] || [];
      visible = visible.filter((a) => names.includes(a.name));
    }
    document.getElementById("agents-hint").textContent =
      `— showing ${visible.length} of ${agents.length}` + (state.stageFilter ? ` · stage: ${state.stageFilter}` : "");
    if (visible.length === 0) { grid.innerHTML = '<div class="grid-empty">no agents match the current filters.</div>'; return; }

    visible.forEach((a) => {
      const card = document.createElement("div");
      card.className = "card" + (state.expanded.has(a.name) ? " expanded" : "");
      card.dataset.status = a.status; card.dataset.name = a.name;
      const isActive = a.status === "working";
      const histLen = Array.isArray(a.history) ? a.history.length : 0;
      const countLabel = histLen > 0 ? `${histLen} event${histLen === 1 ? "" : "s"}` : "flow";
      const icon = ROLE_ICON[a.name] || "🤖";
      const tokenBadge = (a.tokens != null) ? `<span class="token-badge" title="tokens reported">${escHtml(fmtTokens(a.tokens))}</span>` : "";
      card.innerHTML = `
        <div class="card-top">
          <div class="card-header">
            <span class="agent-name"><span class="role-icon">${icon}</span>${escHtml(a.name)}</span>
            <span class="badges">${tokenBadge}<span class="model-badge ${a.model.toLowerCase()}">${a.model.toUpperCase()}</span></span>
          </div>
          <div class="agent-role">${escHtml(a.role)}</div>
          <div class="status-row">
            <div class="dot ${a.status}"></div>
            <span class="status-label ${a.status}">${escHtml(a.status)}</span>
            <span class="flow-count">${escHtml(countLabel)}</span>
            <span class="chev">▸</span>
          </div>
          <div class="task-line${isActive ? " active-task" : ""}">${escHtml(a.task)}</div>
        </div>
        ${flowHtml(a)}`;
      card.querySelector(".card-top").addEventListener("click", () => {
        if (state.expanded.has(a.name)) state.expanded.delete(a.name); else state.expanded.add(a.name);
        card.classList.toggle("expanded"); saveState();
      });
      grid.appendChild(card);
    });
    tickLive();
  }

  function renderMeta(project, updated, updatedAt) {
    const stamp = updatedAt ? updatedAt.replace("T", " ") : updated;
    document.getElementById("meta-line").textContent = `project: ${project}  |  updated: ${stamp || "—"}`;
  }

  // ── full render = core sections + feature hooks ──────────────────────────────
  function renderAll(data) {
    const agents = data.agents || [];
    renderMeta(data.project, data.updated, data.updatedAt);
    renderNowBuilding(agents);
    renderPipeline(data.pipeline || [], agents);
    renderFilters(agents);
    renderAgents(agents);
    renderHooks.forEach((fn) => { try { fn(data); } catch (e) { console.error("[dash] render hook", e); } });
  }

  function tickLive() {
    document.querySelectorAll(".live[data-since]").forEach((el) => {
      el.textContent = fmtDur(Date.now() - Number(el.dataset.since));
    });
  }
  setInterval(tickLive, 1000);

  function pulseTick() { const t = document.getElementById("tick"); if (!t) return; t.classList.add("pulse-tick"); setTimeout(() => t.classList.remove("pulse-tick"), 500); }

  async function load() {
    try {
      const r = await fetch("status.json?_=" + Date.now());
      if (!r.ok) throw new Error("non-ok");
      const data = await r.json();
      Dash.prev = Dash.data; Dash.data = data;
      pollHooks.forEach((fn) => { try { fn(data, Dash.prev); } catch (e) { console.error("[dash] poll hook", e); } });
      renderAll(data); pulseTick();
    } catch (_) { /* leave last good render */ }
  }

  // start after all module scripts have parsed + registered their hooks
  loadState();
  window.addEventListener("load", () => { load(); setInterval(load, POLL_MS); });
})();
