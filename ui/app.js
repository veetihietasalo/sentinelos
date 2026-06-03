const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// Escape system-derived strings (paths, process names, bundle ids) before they
// touch innerHTML — findings are attacker-influenceable, so never trust them raw.
const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

const VECTOR_LABELS = { kexts:"kernel ext", net:"network", launchd:"launchd", tcc:"tcc perms" };
const sevClass = s => ({review:"b-review",threat:"b-threat",info:"b-info",clear:"b-clear"}[s] || "b-info");
const dotClass = s => ({clear:"dot-clear",review:"dot-review",threat:"dot-threat",unavailable:"dot-unavailable"}[s] || "dot-unavailable");

function worst(reports){
  if (reports.some(r=>r.status==="threat")) return ["threat","● threat"];
  if (reports.some(r=>r.status==="review")) return ["review","● review"];
  if (reports.some(r=>r.status==="unavailable")) return ["review","● review"];
  return ["clear","● secure"];
}

function render(snap){
  if(!snap) return;
  const side = document.getElementById("vectors");
  side.innerHTML = snap.reports.map(r=>
    `<div class="vrow"><span>${esc(VECTOR_LABELS[r.vector_id]||r.vector_id)}</span>`+
    `<span class="${dotClass(r.status)}">${r.status==="clear"?"ok":r.status==="unavailable"?"n/a":"!"}</span></div>`
  ).join("");
  const findings = snap.reports.flatMap(r=>r.findings);
  document.getElementById("findings").innerHTML = findings.length ? findings.map(f=>
    `<div class="find"><span class="badge ${sevClass(f.severity)}">${esc(String(f.severity).toUpperCase())}</span>`+
    `<div><div>${esc(f.title)}</div><div style="color:var(--dim);font-size:11px">${esc(f.detail)}</div></div></div>`
  ).join("") : `<div style="color:var(--dim);padding:8px">no findings — clean</div>`;
  const [klass,label] = worst(snap.reports);
  const ov = document.getElementById("overall");
  ov.textContent = label; ov.className = "overall "+dotClass(klass==="clear"?"clear":klass);
}

async function sweep(){ render(await invoke("run_sweep")); }
document.getElementById("sweep").addEventListener("click", sweep);
listen("sentinel://snapshot", e => render(e.payload));
(async () => { const s = await invoke("get_snapshot"); if (s) render(s); else sweep(); })();
