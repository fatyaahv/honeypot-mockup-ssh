const API = "/api";
const severityOrder = ["Critical", "High", "Medium", "Low"];
const $ = (selector) => document.querySelector(selector);
let sessionData = [];
let selectedSessionId = null;

function escapeHtml(value) {
  return String(value ?? "—").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function formatShortDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function levelClass(level) {
  const normalized = String(level || "low").toLowerCase();
  const safeLevel = ["low", "medium", "high", "critical"].includes(normalized) ? normalized : "low";
  return `pill pill-${safeLevel}`;
}

async function api(path) {
  const response = await fetch(`${API}${path}`, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`API request failed (${response.status})`);
  return response.json();
}

async function loadDashboard() {
  $("#load-error").hidden = true;
  try {
    const [stats, alerts, sessions, risk, techniques] = await Promise.all([
      api("/stats/overview"), api("/alerts?limit=200"), api("/sessions?limit=200"),
      api("/risk-distribution"), api("/mitre/techniques")
    ]);
    renderStats(stats);
    renderAlerts(alerts.items);
    renderSessions(sessions.items);
    renderRisk(risk);
    renderMitre(techniques);
    $("#alert-count").textContent = alerts.total;
    $("#session-count").textContent = sessions.total;
    $("#last-updated").textContent = `Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  } catch (error) {
    $("#load-error").textContent = `${error.message}. Confirm the local API is running and a readable SQLite database is configured.`;
    $("#load-error").hidden = false;
  }
}

function renderStats(stats) {
  $("#stat-events").textContent = stats.total_events.toLocaleString();
  $("#stat-sessions").textContent = stats.total_sessions.toLocaleString();
  $("#stat-sources").textContent = stats.unique_source_ips.toLocaleString();
  $("#stat-alerts").textContent = stats.total_alerts.toLocaleString();
  $("#stat-priority").textContent = stats.high_critical_alerts.toLocaleString();
  $("#stat-risk").textContent = Number(stats.average_risk_score).toFixed(1);
}

function renderAlerts(alerts) {
  const body = $("#alerts-body");
  if (!alerts.length) {
    body.innerHTML = '<tr><td class="empty-cell" colspan="6">No alerts match these filters.</td></tr>';
    return;
  }
  body.innerHTML = alerts.map((alert) => `
    <tr class="alert-row clickable" data-session="${escapeHtml(alert.session_id)}" title="Open session investigation">
      <td class="mono">${escapeHtml(formatShortDate(alert.timestamp))}</td>
      <td class="mono">${escapeHtml(alert.source_ip)}</td>
      <td class="alert-type">${escapeHtml(alert.alert_type)}</td>
      <td><span class="${levelClass(alert.severity)}">${escapeHtml(alert.severity)}</span></td>
      <td><span class="risk-value">${escapeHtml(alert.risk_score)}</span> <span class="${levelClass(alert.risk_level)}">${escapeHtml(alert.risk_level)}</span></td>
      <td class="mono">${escapeHtml(alert.mitre_technique_id || "—")}</td>
    </tr>`).join("");
  body.querySelectorAll("tr[data-session]").forEach((row) => row.addEventListener("click", () => openSession(row.dataset.session)));
}

function renderSessions(items) {
  sessionData = items;
  const body = $("#sessions-body");
  if (!items.length) {
    body.innerHTML = '<tr><td class="empty-cell" colspan="8">No sessions found in the database.</td></tr>';
    return;
  }
  body.innerHTML = items.map((session) => `
    <tr class="clickable ${selectedSessionId === session.session_id ? "selected-row" : ""}" data-session="${escapeHtml(session.session_id)}">
      <td class="mono">${escapeHtml(formatShortDate(session.started_at))}</td>
      <td class="mono">${escapeHtml(session.session_id)}</td>
      <td class="mono">${escapeHtml(session.source_ip)}</td>
      <td>${escapeHtml(session.username || "—")}</td>
      <td>${escapeHtml(session.event_count)}</td>
      <td>${escapeHtml(session.alert_count)}</td>
      <td>${session.risk_score === null ? "—" : `<span class="risk-value">${escapeHtml(session.risk_score)}</span> <span class="${levelClass(session.risk_level)}">${escapeHtml(session.risk_level)}</span>`}</td>
      <td>${session.deception_profile ? `<span class="profile-tag">${escapeHtml(session.deception_profile)}</span>` : '<span class="muted">—</span>'}</td>
    </tr>`).join("");
  body.querySelectorAll("tr[data-session]").forEach((row) => row.addEventListener("click", () => openSession(row.dataset.session)));
}

function renderRisk(items) {
  const maximum = Math.max(1, ...items.map((item) => item.count));
  $("#risk-bars").innerHTML = items.map((item) => `
    <div class="risk-line"><span>${escapeHtml(item.risk_level)}</span><div class="risk-track"><div class="risk-fill fill-${item.risk_level.toLowerCase()}" style="width:${Math.round(item.count / maximum * 100)}%"></div></div><b>${escapeHtml(item.count)}</b></div>`).join("");
}

function renderMitre(items) {
  const top = items.slice(0, 6);
  $("#mitre-body").innerHTML = top.length ? top.map((item) => `
    <tr><td><span class="mono">${escapeHtml(item.technique_id)}</span><br><span>${escapeHtml(item.technique_name)}</span></td><td class="muted">${escapeHtml(item.tactic)}</td><td class="mono">${escapeHtml(item.occurrences)}</td></tr>`).join("") : '<tr><td class="empty-cell" colspan="3">No mapped techniques yet.</td></tr>';
}

async function loadFilteredAlerts(event) {
  if (event) event.preventDefault();
  const params = new URLSearchParams();
  const values = {
    severity: $("#filter-severity").value,
    risk_level: $("#filter-risk").value,
    source_ip: $("#filter-ip").value.trim(),
    alert_type: $("#filter-type").value
  };
  for (const [key, value] of Object.entries(values)) if (value) params.set(key, value);
  try {
    const result = await api(`/alerts?${params.toString()}`);
    renderAlerts(result.items);
    $("#alert-count").textContent = `${result.total} shown`;
  } catch (error) {
    $("#load-error").textContent = error.message;
    $("#load-error").hidden = false;
  }
}

async function openSession(sessionId) {
  if (!sessionId || sessionId === "None") return;
  selectedSessionId = sessionId;
  renderSessions(sessionData);
  try {
    const session = await api(`/sessions/${encodeURIComponent(sessionId)}`);
    const panel = $("#investigation-panel");
    $("#investigation-title").textContent = session.session_id;
    $("#investigation-content").innerHTML = renderInvestigation(session);
    panel.hidden = false;
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    $("#load-error").textContent = `Unable to load session: ${error.message}`;
    $("#load-error").hidden = false;
  }
}

function renderInvestigation(session) {
  const auth = session.authentication_activity || [];
  const commands = session.command_sequence || [];
  const alerts = session.related_alerts || [];
  const techniques = session.mitre_techniques || [];
  const profile = session.deception_profile_data;
  const profileInfo = profile ? `${profile.hostname} · ${Object.entries(profile.system_info || {}).map(([key, value]) => `${key}: ${value}`).join(" · ")}` : "No profile selected";
  const analysisText = session.ai_behavior_summary || "No persisted AI session analysis. Run the Phase 8 analysis pipeline to store one.";
  const risk = session.risk_score === null ? "No alert score" : `${session.risk_score} / 100 · ${session.risk_level}`;
  return `
    <article class="detail-card"><h3>SESSION CONTEXT</h3><div class="detail-grid">
      ${detailValue("Source IP", session.source_ip, true)}${detailValue("Username", session.username)}
      ${detailValue("Started", formatDate(session.started_at))}${detailValue("Ended", session.ended_at ? formatDate(session.ended_at) : "Session still open")}
      ${detailValue("Risk score", risk)}${detailValue("Deception profile", session.deception_profile || "Not selected")}
    </div></article>
    <article class="detail-card"><h3>AI BEHAVIORAL ANALYSIS</h3><p class="summary">${escapeHtml(analysisText)}</p><p class="confidence">Confidence: ${session.ai_confidence === null || session.ai_confidence === undefined ? "—" : `${Math.round(session.ai_confidence * 100)}%`}</p></article>
    <article class="detail-card"><h3>AUTHENTICATION ATTEMPTS (${auth.length})</h3><div class="sequence-list">${auth.length ? auth.map((item) => `<div class="sequence-item"><span class="time">${escapeHtml(formatShortDate(item.timestamp))}</span><span class="command">${escapeHtml(item.result)} · user ${escapeHtml(item.username || "unknown")}</span></div>`).join("") : '<span class="muted">No authentication events recorded.</span>'}</div></article>
    <article class="detail-card"><h3>COMMAND SEQUENCE (${commands.length})</h3><div class="sequence-list">${commands.length ? commands.map((item) => `<div class="sequence-item"><span class="time">${escapeHtml(formatShortDate(item.timestamp))}</span><span class="command">${escapeHtml(item.command)}</span></div>`).join("") : '<span class="muted">No commands recorded.</span>'}</div></article>
    <article class="detail-card"><h3>RELATED ALERTS (${alerts.length})</h3><div class="sequence-list">${alerts.length ? alerts.map((item) => `<div class="sequence-item"><span class="time">${escapeHtml(item.severity)}</span><span class="command">${escapeHtml(item.alert_type)} · risk ${escapeHtml(item.risk_score)} · ${escapeHtml(item.mitre_technique_id || "unmapped")}</span></div>`).join("") : '<span class="muted">No alerts linked to this session.</span>'}</div></article>
    <article class="detail-card"><h3>MITRE ATT&CK (${techniques.length})</h3>${techniques.length ? techniques.map((item) => `<span class="technique-chip">${escapeHtml(item.technique_id)} · ${escapeHtml(item.technique_name)} · ${escapeHtml(item.tactic)}</span>`).join("") : '<span class="muted">No mapped techniques.</span>'}</article>
    <article class="detail-card"><h3>SELECTED DECEPTION PROFILE</h3><p class="summary">${escapeHtml(profileInfo)}</p>${profile ? `<p class="muted">Fictional users: ${escapeHtml((profile.users || []).join(", "))}</p>` : ""}</article>`;
}

function detailValue(label, value, mono = false) {
  return `<div><span class="detail-label">${escapeHtml(label)}</span><span class="detail-value ${mono ? "mono" : ""}">${escapeHtml(value)}</span></div>`;
}

async function populateAlertTypes() {
  try {
    const result = await api("/alerts?limit=500");
    const types = [...new Set(result.items.map((item) => item.alert_type))].sort();
    const select = $("#filter-type");
    for (const type of types) {
      const option = document.createElement("option");
      option.value = type;
      option.textContent = type;
      select.append(option);
    }
  } catch (_) { /* The main load path shows API errors. */ }
}

$("#alert-filters").addEventListener("submit", loadFilteredAlerts);
$("#clear-filters").addEventListener("click", () => {
  $("#filter-severity").value = "";
  $("#filter-risk").value = "";
  $("#filter-ip").value = "";
  $("#filter-type").value = "";
  loadFilteredAlerts();
});
$("#refresh-button").addEventListener("click", loadDashboard);
$("#close-investigation").addEventListener("click", () => { $("#investigation-panel").hidden = true; selectedSessionId = null; renderSessions(sessionData); });
populateAlertTypes();
loadDashboard();
