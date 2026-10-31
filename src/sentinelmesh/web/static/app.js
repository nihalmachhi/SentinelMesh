"use strict";

const state = { incidents: [], findings: [], selectedIncident: null, selectedFinding: null, token: "", sessionValid: false, sort: { incidents: ["created_at", "desc"], findings: ["severity", "desc"] }, previousFocus: null };
const byId = id => document.getElementById(id);
const make = (tag, className = "", text = "") => { const node = document.createElement(tag); if (className) node.className = className; if (text !== "") node.textContent = String(text); return node; };
const button = (text, className = "") => { const node = make("button", className, text); node.type = "button"; return node; };

async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body !== undefined) headers.set("Content-Type", "application/json");
    if (options.auth && state.token) headers.set("Authorization", `Bearer ${state.token}`);
    const response = await fetch(path, { ...options, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
    const contentType = response.headers.get("Content-Type") || "";
    const value = contentType.includes("application/json") ? await response.json() : await response.text();
    if (!response.ok) throw new Error(value?.error || `${response.status} ${response.statusText}`);
    return value;
}

function showNotice(message, kind = "") { const notice = byId("notice"); notice.textContent = message; notice.className = `notice ${kind}`; notice.hidden = !message; }
function setPanel(id, tableId, message, kind = "") { byId(id).textContent = message; byId(id).className = `panel-state ${kind}`; byId(tableId).hidden = true; }
function severity(level) { return make("span", `severity ${String(level || "low").toLowerCase()}`, level || "unknown"); }
function sortRows(rows, key, direction) { return [...rows].sort((a,b) => { const av = a[key] ?? "", bv = b[key] ?? ""; const n = typeof av === "number" && typeof bv === "number" ? av-bv : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: "base" }); return n * (direction === "asc" ? 1 : -1); }); }
function selectButton(label, value, action) { const b = button(label, "row-select"); b.dataset.value = value; b.addEventListener("click", action); return b; }

function renderSummary(data) {
    for (const [key,id] of [["flow_count","flow-count"],["finding_count","finding-count"],["incident_count","incident-count"],["report_count","report-count"]]) byId(id).textContent = Number(data[key] || 0).toLocaleString();
    byId("summary-panel").setAttribute("aria-busy", "false");
}

function renderIncidents() {
    const panel = byId("incident-table"), body = panel.tBodies[0]; body.replaceChildren();
    const rows = sortRows(state.incidents, ...state.sort.incidents);
    byId("incident-count-label").textContent = `${rows.length} total`;
    if (!rows.length) { setPanel("incident-state", "incident-table", "No incidents yet. Analyze the synthetic sample to populate this view."); return; }
    for (const item of rows) {
        const row = body.insertRow();
        const id = row.insertCell(); id.append(selectButton(item.incident_id, item.incident_id, () => openIncident(item.incident_id)));
        row.insertCell().append(severity(item.severity));
        row.insertCell().append(make("span", "mono", item.host || "unknown"));
        row.insertCell().textContent = String(item.finding_count ?? 0);
        row.insertCell().textContent = item.status || "open";
    }
    byId("incident-state").hidden = true; panel.hidden = false;
}

function renderFindings() {
    const panel = byId("finding-table"), body = panel.tBodies[0]; body.replaceChildren();
    const rows = sortRows(state.findings, ...state.sort.findings);
    byId("finding-count-label").textContent = `${rows.length} total`;
    if (!rows.length) { setPanel("finding-state", "finding-table", "No findings yet. Analyze the synthetic sample to populate this view."); return; }
    for (const item of rows) {
        const row = body.insertRow();
        row.insertCell().append(selectButton(item.rule_id, item.finding_id, () => openFinding(item.finding_id)));
        row.insertCell().append(severity(item.severity));
        row.insertCell().append(selectButton(item.title, item.finding_id, () => openFinding(item.finding_id)));
        row.insertCell().textContent = String(item.evidence_ids?.length ?? 0);
    }
    byId("finding-state").hidden = true; panel.hidden = false;
}

function renderSortControls() {
    document.querySelectorAll(".sort-button").forEach(control => {
        const table = control.closest("table").id === "incident-table" ? "incidents" : "findings";
        const [key,direction] = state.sort[table];
        const current = control.dataset.sort === key;
        control.setAttribute("aria-sort", current ? (direction === "asc" ? "ascending" : "descending") : "none");
        control.querySelector("span").textContent = current ? (direction === "asc" ? "↑" : "↓") : "↕";
    });
}

async function loadDashboard() {
    showNotice(""); byId("summary-panel").setAttribute("aria-busy", "true");
    setPanel("incident-state", "incident-table", "Loading incidents…"); setPanel("finding-state", "finding-table", "Loading findings…");
    try {
        const [health, version, summary, incidents, findings] = await Promise.all([api("/api/health"), api("/api/version"), api("/api/summary"), api("/api/incidents"), api("/api/findings")]);
        byId("health-status").textContent = health.status === "ok" ? "Local API healthy" : "API unavailable"; byId("health-dot").className = `health-dot ${health.status === "ok" ? "good" : "bad"}`; byId("version").textContent = `v${version.version}`;
        state.incidents = incidents; state.findings = findings; renderSummary(summary); renderIncidents(); renderFindings(); renderSortControls();
    } catch (error) {
        byId("health-status").textContent = "API unavailable"; byId("health-dot").className = "health-dot bad";
        byId("summary-panel").setAttribute("aria-busy", "false");
        setPanel("incident-state", "incident-table", `Unable to load incidents: ${error.message}`, "error"); setPanel("finding-state", "finding-table", `Unable to load findings: ${error.message}`, "error");
        showNotice("Could not reach the local SentinelMesh API. Start it with: python -m sentinelmesh serve", "error");
    }
}

function updateMode() {
    byId("mode-pill").textContent = state.sessionValid ? "Analyst" : "Viewer"; byId("mode-pill").classList.toggle("analyst", state.sessionValid);
    byId("investigate-button").disabled = !state.sessionValid || !state.selectedIncident;
    byId("analyst-note").textContent = state.sessionValid ? "Token accepted for this page session." : "Enter the local token to enable analyst actions.";
}

async function unlock(event) {
    event.preventDefault(); state.token = byId("token-input").value.trim(); state.sessionValid = false; updateMode();
    if (!state.token) { showNotice("Enter the per-run token printed by the local server.", "error"); return; }
    try { await api("/api/session", { method: "POST", body: {}, auth: true }); state.sessionValid = true; showNotice("Analyst actions are enabled for this page session.", "success"); }
    catch (error) { state.token = ""; byId("token-input").value = ""; showNotice(`Token was not accepted: ${error.message}`, "error"); }
    updateMode();
}

function addFeatureList(parent, features) {
    const list = make("dl", "feature-list");
    for (const [key,value] of Object.entries(features || {})) { const term=make("dt", "mono", key); const desc=make("dd", "", typeof value === "object" ? JSON.stringify(value) : value); list.append(term,desc); }
    parent.append(list);
}

async function renderEvidence(findings) {
    const content=byId("drawer-content"); content.replaceChildren();
    if (!findings?.length) { content.append(make("p", "subtle", "No linked findings were returned.")); return; }
    for (const finding of findings) {
        const section=make("section", "evidence-flow"); section.append(make("h3", "", finding.title || finding.rule_id), severity(finding.severity), make("p", "", finding.summary || ""));
        section.append(make("p", "micro-label", `Rule: ${finding.rule_id} · score ${finding.score ?? "n/a"}`));
        addFeatureList(section, finding.observed_features);
        if (finding.attack_mapping) { const mapping=finding.attack_mapping; section.append(make("h3", "", "ATT&CK context"), make("p", "", `${mapping.technique_id} ${mapping.technique}: ${mapping.interpretation}`)); }
        section.append(make("h3", "", "Linked flow records"));
        const list=make("ul");
        for (const id of finding.evidence_ids || []) {
            const item=make("li", "mono", `${id} · loading`); list.append(item);
            api(`/api/flows/${encodeURIComponent(id)}`).then(flow => { item.textContent = `${flow.flow_id} · ${flow.timestamp} · ${flow.src_ip} → ${flow.dst_ip}:${flow.dst_port} · ${flow.bytes_sent.toLocaleString()} bytes`; }).catch(() => { item.textContent = `${id} · flow unavailable`; });
        }
        section.append(list); content.append(section);
    }
}

function showDrawer(title, findings, incident = null) {
    state.previousFocus = document.activeElement; state.selectedIncident = incident; state.selectedFinding = findings?.[0] || null;
    byId("drawer-title").textContent = title; byId("evidence-drawer").hidden = false; byId("drawer-backdrop").hidden = false; updateMode(); byId("drawer-close").focus();
    renderEvidence(findings);
}

async function openIncident(id) {
    try { const item = await api(`/api/incidents/${encodeURIComponent(id)}`); showDrawer(`Incident ${item.incident_id}`, item.findings || [], item); }
    catch (error) { showNotice(`Could not load incident: ${error.message}`, "error"); }
}
async function openFinding(id) {
    const finding = state.findings.find(item => item.finding_id === id); if (finding) showDrawer(finding.title || finding.rule_id, [finding]);
}
function closeDrawer() { byId("evidence-drawer").hidden = true; byId("drawer-backdrop").hidden = true; state.selectedIncident = null; updateMode(); if (state.previousFocus?.isConnected) state.previousFocus.focus(); }

async function investigateIncident() {
    if (!state.sessionValid || !state.selectedIncident) return;
    const action=byId("investigate-button"); action.disabled=true; action.textContent="Generating report…";
    try { await api(`/api/incidents/${encodeURIComponent(state.selectedIncident.incident_id)}/investigate`, { method: "POST", body: {}, auth: true }); showNotice("Investigation report created and added to the local audit trail.", "success"); await loadDashboard(); }
    catch (error) { showNotice(`Investigation failed: ${error.message}`, "error"); }
    finally { action.textContent="Generate investigation report"; updateMode(); }
}

function setTheme(theme) { document.documentElement.dataset.theme=theme; localStorage.setItem("sentinelmesh-theme",theme); byId("theme-toggle").setAttribute("aria-label",`Switch to ${theme === "dark" ? "light" : "dark"} theme`); }
byId("token-form").addEventListener("submit", unlock); byId("refresh-button").addEventListener("click", loadDashboard);
byId("theme-toggle").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
byId("drawer-close").addEventListener("click", closeDrawer); byId("drawer-backdrop").addEventListener("click", closeDrawer); byId("investigate-button").addEventListener("click", investigateIncident);
document.addEventListener("keydown", event => { if (event.key === "Escape" && !byId("evidence-drawer").hidden) closeDrawer(); });
document.querySelectorAll(".sort-button").forEach(control => control.addEventListener("click", () => { const table=control.closest("table").id === "incident-table" ? "incidents" : "findings"; const current=state.sort[table]; state.sort[table]=[control.dataset.sort, current[0] === control.dataset.sort && current[1] === "asc" ? "desc" : "asc"]; table === "incidents" ? renderIncidents() : renderFindings(); renderSortControls(); }));
const savedTheme=localStorage.getItem("sentinelmesh-theme"); if (savedTheme === "light" || savedTheme === "dark") setTheme(savedTheme); else { document.documentElement.dataset.theme=matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"; setTheme(document.documentElement.dataset.theme); }
updateMode(); loadDashboard();
