"""
SecSuite Web Dashboard — FastAPI + SQLite-backed.

Endpoints:
  GET  /                   — Main dashboard HTML
  GET  /api/stats          — Aggregate counters across all runs
  GET  /api/runs           — Run history (newest first, limit 50)
  GET  /api/runs/{run_id}  — Single run details
  GET  /api/findings       — Confirmed findings across all runs
  GET  /api/findings/{run_id} — Findings for a specific run
  GET  /api/remediations/{run_id} — Remediation scripts for a run
  GET  /api/trend/risk     — Risk score over last 30 days
  GET  /api/trend/exposure — Confirmed exposure count over last 30 days
  POST /api/run            — Trigger a new loop run (background task)
  GET  /api/run/status     — Live run progress (SSE-compatible JSON)
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone

# Ensure project root is on sys.path when run directly
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from pydantic import BaseModel  # noqa: E402

from core.db import (  # noqa: E402
    get_exposure_trend,
    get_risk_trend,
    get_run,
    get_stats,
    list_confirmed_findings,
    list_findings,
    list_remediations,
    list_runs,
)
from core.logger import get_logger  # noqa: E402

logger = get_logger("dashboard")

# ── Live run state ─────────────────────────────────────────────────────────────

_live_run: dict = {"running": False, "target": "", "log": [], "error": ""}


class RunRequest(BaseModel):
    target: str
    mode: str = "confirm_and_plan"
    profile: str = "lan"


def _create_app():
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse

    app = FastAPI(title="SecSuite Dashboard", version="2.0.0")

    # ── API routes ─────────────────────────────────────────────────────────────

    @app.get("/api/stats")
    async def api_stats():
        return get_stats()

    @app.get("/api/runs")
    async def api_runs(limit: int = 50):
        return list_runs(limit)

    @app.get("/api/runs/{run_id}")
    async def api_run(run_id: str):
        run = get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        return run

    @app.get("/api/findings")
    async def api_findings_all(limit: int = 200):
        return list_confirmed_findings(limit)

    @app.get("/api/findings/{run_id}")
    async def api_findings_run(run_id: str):
        return list_findings(run_id)

    @app.get("/api/remediations/{run_id}")
    async def api_remediations(run_id: str):
        return list_remediations(run_id)

    @app.get("/api/trend/risk")
    async def api_trend_risk(days: int = 30):
        return get_risk_trend(days)

    @app.get("/api/trend/exposure")
    async def api_trend_exposure(days: int = 30):
        return get_exposure_trend(days)

    @app.get("/api/run/status")
    async def api_run_status():
        return {
            "running": _live_run["running"],
            "target": _live_run["target"],
            "log": _live_run["log"][-50:],   # last 50 lines
            "error": _live_run["error"],
        }

    @app.post("/api/run")
    async def api_trigger_run(body: RunRequest):
        global _live_run
        target = (body.target or "").strip()
        mode = body.mode
        profile = body.profile

        if not target:
            raise HTTPException(status_code=400, detail="target is required")
        if _live_run["running"]:
            raise HTTPException(status_code=409, detail="A run is already in progress")

        _live_run = {"running": True, "target": target, "log": [], "error": ""}
        asyncio.create_task(_background_run(target, mode, profile))
        return {"status": "started", "target": target, "mode": mode, "profile": profile}

    # ── Main dashboard HTML ────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return _DASHBOARD_HTML

    return app


async def _background_run(target: str, mode: str, profile: str) -> None:
    """Run the security loop as a background task, logging progress."""
    global _live_run
    try:
        from core.guardrails import guardrails
        from modules.orchestrator.loop import RedBlueOrchestrator

        def _log(msg: str) -> None:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            _live_run["log"].append(f"[{ts}] {msg}")

        _log(f"Creating engagement session for {target}")
        session = guardrails.create_session(
            operator=os.environ.get("USER", "operator"),
            engagement_id=f"DASH-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            roe_allowed=["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"],
            ttl_hours=8,
            allow_live_exploitation=False,
        )
        _log(f"Session: {session.session_id}")

        runner = RedBlueOrchestrator(output_dir="/tmp/secsuite-loop")
        _log(f"Starting {mode} loop with profile={profile}...")

        report = await runner.run(target, mode=mode, scan_profile=profile)
        d = report.to_dict()

        _log(f"Scan complete — hosts={d['summary']['hosts']} "
             f"services={d['summary']['services']} "
             f"cves={d['summary']['cves']} "
             f"confirmed={d['summary']['confirmed_exploitable']}")
        _log(f"Risk score: {d['risk_score']} ({d['risk_color']})")
        if d["errors"]:
            for e in d["errors"]:
                _log(f"ERROR: {e}")
        _log("Done.")
    except Exception as exc:
        _live_run["error"] = str(exc)
        _live_run["log"].append(f"[FATAL] {exc}")
        logger.error(f"Background run failed: {exc}")
    finally:
        _live_run["running"] = False


# ── Dashboard HTML (inline) ────────────────────────────────────────────────────

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecSuite Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;background:#0a0a0f;color:#c9d1d9;min-height:100vh}
a{color:#58a6ff;text-decoration:none}
.nav{background:#161b22;padding:.75rem 1.5rem;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #30363d;position:sticky;top:0;z-index:100}
.nav h1{color:#58a6ff;font-size:1.1rem;letter-spacing:.05em}
.nav-right{display:flex;gap:.5rem;align-items:center}
.badge{padding:.2rem .5rem;border-radius:12px;font-size:.7rem;font-weight:600;text-transform:uppercase}
.badge-green{background:#1f6a2e;color:#3fb950}
.badge-red{background:#6e040f;color:#f85149}
.badge-blue{background:#0c2d6b;color:#58a6ff}
.wrap{max-width:1400px;margin:0 auto;padding:1.5rem}
.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem}
.stat{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center}
.stat .n{font-size:2rem;font-weight:700;line-height:1}
.stat .l{font-size:.75rem;color:#8b949e;margin-top:.4rem;text-transform:uppercase;letter-spacing:.05em}
.n-crit{color:#f85149}.n-high{color:#e3892b}.n-med{color:#d29922}.n-low{color:#58a6ff}.n-blue{color:#58a6ff}.n-green{color:#3fb950}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:1.5rem}
.card-hdr{padding:.75rem 1rem;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center}
.card-hdr h2{font-size:.9rem;color:#8b949e;text-transform:uppercase;letter-spacing:.08em}
.card-body{padding:1rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{padding:.5rem .75rem;text-align:left;color:#8b949e;font-weight:500;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #21262d}
td{padding:.6rem .75rem;border-bottom:1px solid #21262d;vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1c2128}
.sev{display:inline-block;padding:.15rem .45rem;border-radius:4px;font-size:.7rem;font-weight:700;text-transform:uppercase}
.sev-CRITICAL{background:#6e040f;color:#f85149}
.sev-HIGH{background:#3d1a00;color:#e3892b}
.sev-MEDIUM{background:#2d2200;color:#d29922}
.sev-LOW{background:#0c2d6b;color:#58a6ff}
.sev-MINIMAL,.sev-NONE{background:#21262d;color:#8b949e}
.risk-bar{height:8px;border-radius:4px;background:#21262d;overflow:hidden;margin-top:.35rem}
.risk-fill{height:100%;border-radius:4px;transition:width .4s}
.tabs{display:flex;gap:.5rem;margin-bottom:1rem}
.tab{padding:.4rem .9rem;border-radius:6px;border:1px solid #30363d;background:transparent;color:#8b949e;cursor:pointer;font-size:.8rem}
.tab.active{background:#1f6a2e;color:#3fb950;border-color:#238636}
.tab:hover:not(.active){border-color:#58a6ff;color:#58a6ff}
.tab-pane{display:none}.tab-pane.active{display:block}
.btn{padding:.5rem 1rem;border-radius:6px;border:none;cursor:pointer;font-size:.85rem;font-weight:500}
.btn-primary{background:#238636;color:#fff}.btn-primary:hover{background:#2ea043}
.btn-sm{padding:.3rem .7rem;font-size:.75rem}
.btn-outline{background:transparent;border:1px solid #30363d;color:#c9d1d9}.btn-outline:hover{border-color:#58a6ff;color:#58a6ff}
input,select{background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;padding:.5rem .75rem;font-size:.85rem}
input:focus,select:focus{outline:none;border-color:#58a6ff}
.form-row{display:flex;gap:.75rem;flex-wrap:wrap;align-items:flex-end}
.form-group{display:flex;flex-direction:column;gap:.3rem}
.form-group label{font-size:.75rem;color:#8b949e}
.log-box{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:.75rem;font-family:monospace;font-size:.75rem;height:200px;overflow-y:auto;color:#3fb950}
.log-box .err{color:#f85149}
.chart-wrap{position:relative;height:180px;width:100%}
canvas{display:block}
.empty{color:#8b949e;font-size:.85rem;padding:1rem 0;text-align:center}
.mono{font-family:monospace;font-size:.8rem}
.pre{white-space:pre-wrap;font-family:monospace;font-size:.75rem;background:#0d1117;padding:.75rem;border-radius:6px;border:1px solid #30363d;max-height:200px;overflow-y:auto}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;align-items:center;justify-content:center}
.modal.open{display:flex}
.modal-inner{background:#161b22;border:1px solid #30363d;border-radius:10px;max-width:760px;width:90%;max-height:85vh;overflow-y:auto;padding:1.5rem}
.modal-inner h3{color:#58a6ff;margin-bottom:1rem;font-size:1rem}
.close-btn{float:right;background:transparent;border:none;color:#8b949e;cursor:pointer;font-size:1.2rem}
.close-btn:hover{color:#c9d1d9}
.pill{display:inline-block;padding:.1rem .4rem;border-radius:10px;font-size:.7rem;background:#21262d;color:#8b949e;margin-right:.2rem}
</style>
</head>
<body>
<nav class="nav">
  <h1>&#x1F6E1; SecSuite</h1>
  <div class="nav-right">
    <span id="run-badge" class="badge badge-green">IDLE</span>
    <button class="btn btn-outline btn-sm" onclick="loadAll()">&#x21BB; Refresh</button>
  </div>
</nav>

<div class="wrap">

  <!-- Stats -->
  <div class="stat-row" id="stat-row">
    <div class="stat"><div class="n n-blue">-</div><div class="l">Total Runs</div></div>
    <div class="stat"><div class="n n-crit">-</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n n-high">-</div><div class="l">High</div></div>
    <div class="stat"><div class="n n-med">-</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n n-low">-</div><div class="l">Low</div></div>
    <div class="stat"><div class="n n-green">-</div><div class="l">Confirmed</div></div>
    <div class="stat"><div class="n n-blue">-</div><div class="l">Remediations</div></div>
  </div>

  <!-- Trigger Run -->
  <div class="card">
    <div class="card-hdr"><h2>&#x25B6; Trigger Run</h2></div>
    <div class="card-body">
      <div class="form-row">
        <div class="form-group">
          <label>Target (IP / CIDR)</label>
          <input id="tgt-input" type="text" placeholder="192.168.1.0/24" style="width:220px">
        </div>
        <div class="form-group">
          <label>Mode</label>
          <select id="tgt-mode">
            <option value="recon_only">recon_only</option>
            <option value="confirm_only">confirm_only</option>
            <option value="confirm_and_plan" selected>confirm_and_plan</option>
            <option value="full_auto">full_auto</option>
          </select>
        </div>
        <div class="form-group">
          <label>Profile</label>
          <select id="tgt-profile">
            <option value="quick">quick</option>
            <option value="lan" selected>lan</option>
            <option value="normal">normal</option>
            <option value="full">full</option>
            <option value="stealth">stealth</option>
          </select>
        </div>
        <div class="form-group">
          <label>&nbsp;</label>
          <button class="btn btn-primary" onclick="triggerRun()">&#x25B6; Run</button>
        </div>
      </div>
      <div id="run-log" class="log-box" style="margin-top:.75rem;display:none"></div>
    </div>
  </div>

  <!-- Charts -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem">
    <div class="card">
      <div class="card-hdr"><h2>&#x1F4C8; Risk Score (30d)</h2></div>
      <div class="card-body"><div class="chart-wrap"><canvas id="risk-chart"></canvas></div></div>
    </div>
    <div class="card">
      <div class="card-hdr"><h2>&#x1F50D; Exposures (30d)</h2></div>
      <div class="card-body"><div class="chart-wrap"><canvas id="exp-chart"></canvas></div></div>
    </div>
  </div>

  <!-- Main tabs -->
  <div class="card">
    <div class="card-hdr">
      <div class="tabs">
        <button class="tab active" onclick="switchTab('findings',this)">Findings</button>
        <button class="tab" onclick="switchTab('runs',this)">Run History</button>
        <button class="tab" onclick="switchTab('remediations',this)">Remediations</button>
      </div>
    </div>
    <div class="card-body">

      <!-- Findings -->
      <div id="tab-findings" class="tab-pane active">
        <table>
          <thead><tr><th>Severity</th><th>IP:Port</th><th>Service</th><th>CVE</th><th>CVSS</th><th>Run</th><th>Date</th></tr></thead>
          <tbody id="findings-body"></tbody>
        </table>
      </div>

      <!-- Runs -->
      <div id="tab-runs" class="tab-pane">
        <table>
          <thead><tr><th>Engagement</th><th>Target</th><th>Mode</th><th>Risk</th><th>Confirmed</th><th>Remediations</th><th>Started</th></tr></thead>
          <tbody id="runs-body"></tbody>
        </table>
      </div>

      <!-- Remediations -->
      <div id="tab-remediations" class="tab-pane">
        <div id="rem-run-select" style="margin-bottom:1rem">
          <select id="rem-run-id" onchange="loadRemediationsForRun()" style="width:100%;max-width:400px">
            <option value="">-- Select run --</option>
          </select>
        </div>
        <div id="rem-list"></div>
      </div>

    </div>
  </div>
</div>

<!-- Remediation modal -->
<div class="modal" id="rem-modal">
  <div class="modal-inner">
    <button class="close-btn" onclick="closeModal()">&#x2715;</button>
    <h3 id="modal-title">Remediation</h3>
    <div id="modal-body"></div>
  </div>
</div>

<script>
// ── mini chart ────────────────────────────────────────────────────────────────
function drawChart(canvasId, labels, values, color, label) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.parentElement.offsetWidth, H = 180;
  canvas.width = W; canvas.height = H;
  ctx.clearRect(0, 0, W, H);
  if (!values.length) { ctx.fillStyle='#8b949e'; ctx.font='13px sans-serif'; ctx.textAlign='center'; ctx.fillText('No data', W/2, H/2); return; }
  const pad = {t:10,r:10,b:30,l:40};
  const max = Math.max(...values, 1);
  const xs = (i) => pad.l + i * (W - pad.l - pad.r) / (values.length - 1 || 1);
  const ys = (v) => pad.t + (1 - v/max) * (H - pad.t - pad.b);
  // grid
  ctx.strokeStyle='#21262d'; ctx.lineWidth=1;
  [0,.25,.5,.75,1].forEach(f=>{ const y=ys(max*f); ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(W-pad.r,y); ctx.stroke(); });
  // fill
  ctx.beginPath(); ctx.moveTo(xs(0), H-pad.b);
  values.forEach((v,i)=>ctx.lineTo(xs(i),ys(v)));
  ctx.lineTo(xs(values.length-1), H-pad.b); ctx.closePath();
  ctx.fillStyle=color+'22'; ctx.fill();
  // line
  ctx.beginPath(); ctx.strokeStyle=color; ctx.lineWidth=2;
  values.forEach((v,i)=>i===0?ctx.moveTo(xs(i),ys(v)):ctx.lineTo(xs(i),ys(v)));
  ctx.stroke();
  // x labels (first + last)
  ctx.fillStyle='#8b949e'; ctx.font='10px sans-serif'; ctx.textAlign='center';
  if (labels.length) {
    ctx.fillText(labels[0], xs(0), H-8);
    if (labels.length > 1) ctx.fillText(labels[labels.length-1], xs(labels.length-1), H-8);
  }
  // y max
  ctx.textAlign='right'; ctx.fillText(max, pad.l-4, pad.t+10);
}

// ── helpers ───────────────────────────────────────────────────────────────────
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') }
function fmtDate(s){ if(!s)return'—'; const d=new Date(s); return d.toLocaleDateString()+' '+d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'}); }
function sevClass(cvss){
  if(cvss>=9)return'CRITICAL';
  if(cvss>=7)return'HIGH';
  if(cvss>=4)return'MEDIUM';
  if(cvss>0)return'LOW';
  return'NONE';
}

// ── data loaders ──────────────────────────────────────────────────────────────
async function fetchJ(url){ const r=await fetch(url); if(!r.ok) throw new Error(r.status); return r.json(); }

async function loadStats(){
  try {
    const s = await fetchJ('/api/stats');
    document.getElementById('stat-row').innerHTML = `
      <div class="stat"><div class="n n-blue">${s.total_runs}</div><div class="l">Total Runs</div></div>
      <div class="stat"><div class="n n-crit">${s.critical}</div><div class="l">Critical</div></div>
      <div class="stat"><div class="n n-high">${s.high}</div><div class="l">High</div></div>
      <div class="stat"><div class="n n-med">${s.medium}</div><div class="l">Medium</div></div>
      <div class="stat"><div class="n n-low">${s.low}</div><div class="l">Low</div></div>
      <div class="stat"><div class="n n-green">${s.total_confirmed}</div><div class="l">Confirmed</div></div>
      <div class="stat"><div class="n n-blue">${s.total_remediations}</div><div class="l">Remediations</div></div>
    `;
  } catch(e){ console.error('stats',e); }
}

async function loadFindings(){
  try {
    const data = await fetchJ('/api/findings?limit=200');
    const tbody = document.getElementById('findings-body');
    if(!data.length){ tbody.innerHTML='<tr><td colspan="7" class="empty">No confirmed findings yet.</td></tr>'; return; }
    tbody.innerHTML = data.map(f=>{
      const sev = sevClass(f.cvss_score||0);
      const runShort = (f.run_id||'').slice(-8);
      return `<tr>
        <td><span class="sev sev-${sev}">${sev}</span></td>
        <td class="mono">${esc(f.ip)}:${f.port}</td>
        <td>${esc(f.service)} ${f.version?'<small style="color:#8b949e">'+esc(f.version)+'</small>':''}</td>
        <td class="mono" style="font-size:.75rem">${esc(f.cve_id)||'—'}</td>
        <td>${f.cvss_score?f.cvss_score.toFixed(1):'—'}</td>
        <td class="mono" style="font-size:.7rem" title="${esc(f.run_id)}">${runShort}</td>
        <td style="font-size:.75rem;color:#8b949e">${fmtDate(f.created_at)}</td>
      </tr>`;
    }).join('');
  } catch(e){ console.error('findings',e); }
}

async function loadRuns(){
  try {
    const data = await fetchJ('/api/runs?limit=50');
    const tbody = document.getElementById('runs-body');
    const sel = document.getElementById('rem-run-id');
    // populate remediation select
    sel.innerHTML = '<option value="">-- Select run --</option>' +
      data.map(r=>`<option value="${esc(r.id)}">${esc(r.engagement_id)} — ${esc(r.target)} (${fmtDate(r.started_at)})</option>`).join('');
    if(!data.length){ tbody.innerHTML='<tr><td colspan="7" class="empty">No runs yet.</td></tr>'; return; }
    tbody.innerHTML = data.map(r=>{
      const riskPct = Math.min(r.risk_score||0, 100);
      const color = r.risk_color==='CRITICAL'?'#f85149':r.risk_color==='HIGH'?'#e3892b':r.risk_color==='MEDIUM'?'#d29922':'#3fb950';
      return `<tr onclick="showRunDetail('${esc(r.id)}')" style="cursor:pointer">
        <td class="mono" style="font-size:.75rem">${esc(r.engagement_id)}</td>
        <td>${esc(r.target)}</td>
        <td><span class="pill">${esc(r.mode)}</span></td>
        <td>
          <span style="color:${color};font-weight:600">${riskPct}</span>
          <span style="color:#8b949e;font-size:.75rem"> / 100</span>
          <div class="risk-bar"><div class="risk-fill" style="width:${riskPct}%;background:${color}"></div></div>
        </td>
        <td>${r.confirmed_exploitable||0}</td>
        <td>${r.remediations_generated||0}</td>
        <td style="font-size:.75rem;color:#8b949e">${fmtDate(r.started_at)}</td>
      </tr>`;
    }).join('');
  } catch(e){ console.error('runs',e); }
}

async function loadTrends(){
  try {
    const [riskData, expData] = await Promise.all([
      fetchJ('/api/trend/risk?days=30'),
      fetchJ('/api/trend/exposure?days=30'),
    ]);
    drawChart('risk-chart', riskData.map(r=>r.day), riskData.map(r=>r.peak_risk), '#f85149', 'Risk');
    drawChart('exp-chart', expData.map(r=>r.day), expData.map(r=>r.unique_exposures), '#58a6ff', 'Exposures');
  } catch(e){ console.error('trends',e); }
}

async function loadRemediationsForRun(){
  const runId = document.getElementById('rem-run-id').value;
  const container = document.getElementById('rem-list');
  if(!runId){ container.innerHTML=''; return; }
  try {
    const data = await fetchJ('/api/remediations/'+encodeURIComponent(runId));
    if(!data.length){ container.innerHTML='<div class="empty">No remediations for this run.</div>'; return; }
    container.innerHTML = data.map((r,i)=>{
      const sev = sevClass(r.cvss_score||0);
      return `<div style="border:1px solid #30363d;border-radius:6px;margin-bottom:.75rem;overflow:hidden">
        <div style="padding:.6rem 1rem;background:#0d1117;display:flex;justify-content:space-between;align-items:center">
          <span><span class="sev sev-${sevClass(0)}" style="background:${r.safe?'#1f6a2e':'#6e040f'};color:${r.safe?'#3fb950':'#f85149'}">${r.safe?'SAFE':'UNSAFE'}</span>
          &nbsp;<span class="mono" style="font-size:.85rem">${esc(r.ip)}:${r.port}</span>
          &nbsp;<span style="color:#8b949e">${esc(r.service)}</span>
          ${r.cve_id?'&nbsp;<span class="mono" style="font-size:.75rem;color:#8b949e">'+esc(r.cve_id)+'</span>':''}</span>
          <button class="btn btn-outline btn-sm" onclick="openRem(${i})">View Script</button>
        </div>
        <div style="padding:.75rem 1rem;font-size:.82rem">${esc(r.explanation||'No explanation')}</div>
      </div>`;
    }).join('');
    // store for modal
    window._remData = data;
  } catch(e){ container.innerHTML='<div class="empty" style="color:#f85149">Error loading remediations.</div>'; }
}

function openRem(idx){
  const r = window._remData[idx];
  if(!r) return;
  document.getElementById('modal-title').textContent = `${r.service} @ ${r.ip}:${r.port}${r.cve_id?' — '+r.cve_id:''}`;
  document.getElementById('modal-body').innerHTML = `
    <p style="margin-bottom:.75rem;color:#8b949e;font-size:.85rem">${esc(r.explanation)}</p>
    ${r.warnings&&JSON.parse(r.warnings||'[]').length?'<p style="color:#e3892b;font-size:.8rem;margin-bottom:.5rem">&#9888; '+JSON.parse(r.warnings).join(' | ')+'</p>':''}
    <h4 style="color:#3fb950;font-size:.8rem;margin:.75rem 0 .3rem">Immediate Mitigation</h4>
    <div class="pre">${esc(r.immediate_mitigation)}</div>
    <h4 style="color:#3fb950;font-size:.8rem;margin:.75rem 0 .3rem">Permanent Fix</h4>
    <div class="pre">${esc(r.permanent_fix)}</div>
    ${r.rollback_script?'<h4 style="color:#d29922;font-size:.8rem;margin:.75rem 0 .3rem">Rollback</h4><div class="pre">'+esc(r.rollback_script)+'</div>':''}
    ${r.verification_command?'<h4 style="color:#58a6ff;font-size:.8rem;margin:.75rem 0 .3rem">Verify</h4><div class="pre">'+esc(r.verification_command)+'</div>':''}
    <p style="margin-top:.75rem;font-size:.72rem;color:#8b949e">Model: ${esc(r.model_used)} &nbsp;|&nbsp; Created: ${fmtDate(r.created_at)}</p>
  `;
  document.getElementById('rem-modal').classList.add('open');
}

async function showRunDetail(runId){
  try {
    const r = await fetchJ('/api/runs/'+encodeURIComponent(runId));
    const findings = await fetchJ('/api/findings/'+encodeURIComponent(runId));
    const confirmed = findings.filter(f=>f.exploit_status==='CONFIRMED');
    document.getElementById('modal-title').textContent = `Run: ${r.engagement_id} — ${r.target}`;
    document.getElementById('modal-body').innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:.75rem;margin-bottom:1rem">
        <div class="stat"><div class="n n-blue" style="font-size:1.4rem">${r.total_hosts||0}</div><div class="l">Hosts</div></div>
        <div class="stat"><div class="n n-blue" style="font-size:1.4rem">${r.total_services||0}</div><div class="l">Services</div></div>
        <div class="stat"><div class="n n-crit" style="font-size:1.4rem">${r.confirmed_exploitable||0}</div><div class="l">Confirmed</div></div>
      </div>
      <p style="font-size:.8rem;color:#8b949e;margin-bottom:.75rem">Mode: ${r.mode} &nbsp;|&nbsp; Profile: — &nbsp;|&nbsp; Risk: <strong style="color:#e3892b">${r.risk_score}</strong> (${r.risk_color})</p>
      ${confirmed.length?`<table style="font-size:.8rem"><thead><tr><th>IP:Port</th><th>Service</th><th>CVE</th><th>CVSS</th></tr></thead><tbody>${
        confirmed.map(f=>`<tr><td class="mono">${esc(f.ip)}:${f.port}</td><td>${esc(f.service)}</td><td class="mono">${esc(f.cve_id)||'—'}</td><td>${f.cvss_score||'—'}</td></tr>`).join('')
      }</tbody></table>`:'<div class="empty">No confirmed findings.</div>'}
      ${r.errors&&JSON.parse(r.errors||'[]').length?'<p style="color:#f85149;font-size:.78rem;margin-top:.75rem">Errors: '+JSON.parse(r.errors).join('; ')+'</p>':''}
    `;
    document.getElementById('rem-modal').classList.add('open');
  } catch(e){ alert('Could not load run detail'); }
}

function closeModal(){ document.getElementById('rem-modal').classList.remove('open'); }
document.getElementById('rem-modal').addEventListener('click', e=>{ if(e.target===e.currentTarget)closeModal(); });

// ── tab switching ─────────────────────────────────────────────────────────────
function switchTab(name, btn){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
}

// ── trigger run ───────────────────────────────────────────────────────────────
let _pollTimer = null;
async function triggerRun(){
  const target = document.getElementById('tgt-input').value.trim();
  const mode = document.getElementById('tgt-mode').value;
  const profile = document.getElementById('tgt-profile').value;
  if(!target){ alert('Enter a target'); return; }
  const logBox = document.getElementById('run-log');
  logBox.style.display='block';
  logBox.innerHTML='Starting...';
  document.getElementById('run-badge').textContent='RUNNING';
  document.getElementById('run-badge').className='badge badge-red';
  try {
    const r = await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,mode,profile})});
    if(!r.ok){ const e=await r.json(); const msg=typeof e.detail==='string'?e.detail:JSON.stringify(e.detail); logBox.innerHTML='<div class="err">Error: '+esc(msg)+'</div>'; document.getElementById('run-badge').textContent='IDLE'; document.getElementById('run-badge').className='badge badge-green'; return; }
    _pollTimer = setInterval(pollRunStatus, 1500);
  } catch(e){ alert('Failed to start run: '+e); }
}

async function pollRunStatus(){
  try {
    const s = await fetchJ('/api/run/status');
    const logBox = document.getElementById('run-log');
    logBox.innerHTML = s.log.map(l=>`<div class="${l.includes('[FATAL]')||l.includes('ERROR')?'err':''}">${esc(l)}</div>`).join('');
    logBox.scrollTop = logBox.scrollHeight;
    if(s.error) logBox.innerHTML += `<div class="err">FATAL: ${esc(s.error)}</div>`;
    if(!s.running){
      clearInterval(_pollTimer);
      document.getElementById('run-badge').textContent='IDLE';
      document.getElementById('run-badge').className='badge badge-green';
      loadAll();
    }
  } catch(e){ /* ignore poll errors */ }
}

// ── init ──────────────────────────────────────────────────────────────────────
async function loadAll(){
  await Promise.all([loadStats(), loadFindings(), loadRuns(), loadTrends()]);
}

loadAll();
setInterval(loadAll, 30000);
</script>
</body>
</html>"""


# ── Entry point ────────────────────────────────────────────────────────────────

class DashboardApp:
    """Thin wrapper kept for backward compatibility with cli/main.py."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port

    async def run(self) -> None:
        try:
            import uvicorn
        except ImportError:
            raise ImportError("uvicorn not installed. Run: pip install uvicorn") from None

        app = _create_app()
        logger.info(f"Dashboard starting at http://{self.host}:{self.port}")
        config = uvicorn.Config(app, host=self.host, port=self.port, log_level="warning")
        server = uvicorn.Server(config)
        await server.serve()


def create_app(host: str = "0.0.0.0", port: int = 8080) -> DashboardApp:
    return DashboardApp(host=host, port=port)
