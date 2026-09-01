"use strict";

const DATA_URL = "./data/metrics.json";
const SVG_NS = "http://www.w3.org/2000/svg";
const number = new Intl.NumberFormat("en-US");
let snapshotState = null;
let chartHours = 168;

const byId = (id) => document.getElementById(id);
const setText = (id, value) => { const node = byId(id); if (node) node.textContent = value; };
const node = (tag, className, text) => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
};
const svgNode = (tag, attributes = {}) => {
  const element = document.createElementNS(SVG_NS, tag);
  Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, value));
  return element;
};
const formatCount = (value) => number.format(Number(value || 0));
const formatDate = (value, options = {}) => {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Unknown";
  return new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short", ...options }).format(date);
};
const shortTime = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "—" : date.toISOString().slice(11, 16);
};
const compactDate = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "—" : new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short", timeZone: "UTC" }).format(date);
};

function renderChart() {
  const host = byId("pulse-chart");
  host.replaceChildren();
  const rows = (snapshotState?.hourly || []).slice(-chartHours);
  if (!rows.length) {
    host.append(node("p", "empty-state", "No time-series observations available."));
    return;
  }
  const width = 1000, height = 390, left = 34, right = 12, top = 20, bottom = 40;
  const plotWidth = width - left - right, plotHeight = height - top - bottom;
  const maximum = Math.max(1, ...rows.flatMap((row) => [row.sessions, row.auth, row.commands]));
  const svg = svgNode("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": `Sessions, login attempts, and commands over ${chartHours} hours` });
  const defs = svgNode("defs");
  const gradient = svgNode("linearGradient", { id: "area-gradient", x1: "0", y1: "0", x2: "0", y2: "1" });
  gradient.append(svgNode("stop", { offset: "0%", "stop-color": "#9e83ff", "stop-opacity": ".22" }), svgNode("stop", { offset: "100%", "stop-color": "#9e83ff", "stop-opacity": "0" }));
  defs.append(gradient); svg.append(defs);
  for (let step = 0; step <= 4; step += 1) {
    const y = top + (plotHeight * step / 4);
    svg.append(svgNode("line", { x1: left, x2: width - right, y1: y, y2: y, stroke: "rgba(225,217,239,.09)", "stroke-width": "1" }));
    const label = svgNode("text", { x: 0, y: y + 3, fill: "#625b6c", "font-size": "9", "font-family": "monospace" });
    label.textContent = String(Math.round(maximum * (1 - step / 4))); svg.append(label);
  }
  const point = (row, index, key) => {
    const x = left + (rows.length === 1 ? 0 : index * plotWidth / (rows.length - 1));
    const y = top + plotHeight - (Number(row[key] || 0) / maximum) * plotHeight;
    return [x, y];
  };
  const makePath = (key) => rows.map((row, index) => `${index ? "L" : "M"}${point(row, index, key).join(" ")}`).join(" ");
  const sessionsPath = makePath("sessions");
  const finalX = point(rows.at(-1), rows.length - 1, "sessions")[0];
  svg.append(svgNode("path", { d: `${sessionsPath} L${finalX} ${top + plotHeight} L${left} ${top + plotHeight} Z`, fill: "url(#area-gradient)" }));
  [["sessions", "#9e83ff", 2.2], ["auth", "#73a9ff", 1.6], ["commands", "#ff708d", 1.6]].forEach(([key, color, stroke]) => {
    svg.append(svgNode("path", { d: makePath(key), fill: "none", stroke: color, "stroke-width": stroke, "stroke-linejoin": "round", "stroke-linecap": "round" }));
  });
  const labelIndexes = [...new Set([0, Math.floor((rows.length - 1) / 2), rows.length - 1])];
  labelIndexes.forEach((index) => {
    const x = point(rows[index], index, "sessions")[0];
    const label = svgNode("text", { x, y: height - 10, fill: "#625b6c", "font-size": "9", "font-family": "monospace", "text-anchor": index === 0 ? "start" : index === rows.length - 1 ? "end" : "middle" });
    label.textContent = chartHours === 24 ? `${compactDate(rows[index].bucket)} ${shortTime(rows[index].bucket)}` : compactDate(rows[index].bucket);
    svg.append(label);
  });
  host.append(svg);
}

function renderStream(events) {
  const list = byId("event-stream"); list.replaceChildren();
  (events || []).slice(0, 14).forEach((event) => {
    const item = node("li", event.severity);
    const time = node("time", "", shortTime(event.time)); time.dateTime = event.time;
    const body = node("div");
    body.append(node("strong", "", `${event.country_code} · ${event.ip} · ${event.event}`));
    body.append(node("code", "", event.detail || event.protocol));
    item.append(time, body); list.append(item);
  });
}

function renderSources(sources, query = "") {
  const body = byId("source-rows"); body.replaceChildren();
  const term = query.trim().toLowerCase();
  const filtered = (sources || []).filter((source) => [source.ip, source.country, source.city, source.organization, source.asn].join(" ").toLowerCase().includes(term));
  setText("source-count", `${formatCount(filtered.length)} source${filtered.length === 1 ? "" : "s"}`);
  filtered.forEach((source) => {
    const row = document.createElement("tr");
    const sourceCell = node("td");
    sourceCell.append(node("span", "source-ip", `${source.flag || "◌"} ${source.ip}`), node("span", "source-location", `${source.city}, ${source.country}`));
    const network = node("td");
    network.append(node("span", "network-name", source.organization), node("span", "network-asn", source.asn ? `AS${source.asn}` : "ASN unresolved"));
    const timing = node("td");
    timing.append(node("span", "source-time", `first ${formatDate(source.first_seen, { year: undefined })}`), node("span", "source-time", `last ${formatDate(source.last_seen, { year: undefined })}`));
    [source.sessions, source.auth_attempts, source.commands, source.downloads].forEach((value) => row.append());
    row.append(sourceCell, network, timing, node("td", "number-cell", formatCount(source.sessions)), node("td", "number-cell", formatCount(source.auth_attempts)), node("td", "number-cell", formatCount(source.commands)), node("td", "number-cell", formatCount(source.downloads)));
    body.append(row);
  });
}

function renderRankedList(id, rows) {
  const host = byId(id); host.replaceChildren();
  const maximum = Math.max(1, ...(rows || []).map((row) => Number(row.count || 0)));
  (rows || []).forEach((row) => {
    const line = node("div", "rank-row");
    const track = node("span", "rank-track");
    const fill = node("i"); fill.style.width = `${Math.max(2, Number(row.count || 0) / maximum * 100)}%`; track.append(fill);
    line.append(node("code", "", row.value), track, node("strong", "", formatCount(row.count))); host.append(line);
  });
}

function renderCommands(commands, query = "") {
  const host = byId("command-rows"); host.replaceChildren();
  const term = query.trim().toLowerCase();
  (commands || []).filter((item) => `${item.command} ${(item.families || []).join(" ")} ${(item.techniques || []).join(" ")}`.toLowerCase().includes(term)).forEach((item) => {
    const row = node("div", "command-row");
    row.append(node("strong", "", `${formatCount(item.count)}×`), node("code", "", item.command), node("span", "", (item.families || []).join(" · ")));
    const techniques = node("span", "technique-links");
    (item.techniques || []).forEach((id) => {
      const link = node("a", "", id);
      link.href = `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
      link.target = "_blank"; link.rel = "noopener noreferrer";
      techniques.append(link);
    });
    if (!techniques.childNodes.length) techniques.textContent = "—";
    row.append(techniques); host.append(row);
  });
}

function renderMitre(items) {
  const host = byId("mitre-grid"); host.replaceChildren();
  (items || []).forEach((item, index) => {
    const card = node("article", "mitre-card reveal");
    const header = node("header"); header.append(node("span", "", item.id), node("span", "", `${formatCount(item.count)}×`));
    card.append(header, node("h4", "", item.name), node("p", "", item.tactic));
    const evidence = node("div", "mitre-evidence");
    (item.evidence || []).forEach((value) => evidence.append(node("code", "", `↳ ${value}`)));
    card.append(evidence); card.style.transitionDelay = `${Math.min(index, 5) * 55}ms`; host.append(card);
  });
  observeReveals();
}

function renderArtifacts(items) {
  const body = byId("artifact-rows"); body.replaceChildren();
  const empty = byId("artifact-empty"); empty.hidden = Boolean(items?.length);
  document.querySelector(".artifact-table-wrap").hidden = !items?.length;
  (items || []).forEach((item) => {
    const row = document.createElement("tr");
    const correlation = node("td", "classification");
    const finding = item.classification || {};
    if (finding.status === "known") {
      correlation.append(node("strong", "", finding.label), node("small", "", `${finding.basis === "consensus" ? "Consensus" : "Third-party"} label · ${finding.provider}`));
    } else if (finding.status === "unknown") {
      correlation.append(node("strong", "", "No family label returned"), node("small", "", finding.provider || "Hash provider"));
    } else {
      correlation.append(node("strong", "", "Correlation unavailable"), node("small", "", finding.provider ? `${finding.provider} unavailable` : "Hash lookup not configured"));
    }
    if (finding.retrieved_at) correlation.append(node("time", "", `checked ${formatDate(finding.retrieved_at, { year: undefined })}`));
    const technique = node("a", "artifact-technique", (item.techniques || []).join(", ") || "—");
    if (item.techniques?.[0]) {
      technique.href = `https://attack.mitre.org/techniques/${item.techniques[0].replace(".", "/")}/`;
      technique.target = "_blank"; technique.rel = "noopener noreferrer";
    }
    const techniqueCell = node("td"); techniqueCell.append(technique);
    row.append(
      node("td", "artifact-url", item.url || "Malformed reference withheld"),
      node("td", "hash", item.sha256 || "Unavailable"),
      techniqueCell,
      correlation,
      node("td", "number-cell", formatCount(item.count)),
      node("td", "", formatDate(item.last_seen, { year: undefined })),
    );
    body.append(row);
  });
}

function drawConstellation(sources) {
  const canvas = byId("source-canvas");
  const context = canvas.getContext("2d");
  let points = [], frame = 0;
  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
  function resize() {
    const rect = canvas.getBoundingClientRect(), ratio = Math.min(devicePixelRatio || 1, 2);
    canvas.width = Math.round(rect.width * ratio); canvas.height = Math.round(rect.height * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    points = (sources || []).filter((source) => Number.isFinite(source.latitude) && Number.isFinite(source.longitude)).map((source, index) => ({
      source, x: 42 + ((source.longitude + 180) / 360) * Math.max(1, rect.width - 84), y: 72 + ((90 - source.latitude) / 180) * Math.max(1, rect.height - 145), phase: index * .73
    }));
  }
  function paint() {
    const rect = canvas.getBoundingClientRect(); context.clearRect(0, 0, rect.width, rect.height);
    context.strokeStyle = "rgba(205,192,224,.065)"; context.lineWidth = 1;
    for (let i = 1; i < 7; i += 1) { const x = i * rect.width / 7; context.beginPath(); context.moveTo(x, 62); context.lineTo(x, rect.height - 42); context.stroke(); }
    for (let i = 1; i < 5; i += 1) { const y = 62 + i * (rect.height - 104) / 5; context.beginPath(); context.moveTo(35, y); context.lineTo(rect.width - 35, y); context.stroke(); }
    const origin = { x: 42 + ((72.8777 + 180) / 360) * Math.max(1, rect.width - 84), y: 72 + ((90 - 19.076) / 180) * Math.max(1, rect.height - 145) };
    points.forEach((point) => {
      context.beginPath(); context.moveTo(origin.x, origin.y); const midX = (origin.x + point.x) / 2, rise = Math.min(85, Math.abs(origin.x - point.x) * .15); context.quadraticCurveTo(midX, Math.min(origin.y, point.y) - rise, point.x, point.y); context.strokeStyle = "rgba(158,131,255,.12)"; context.stroke();
      const pulse = reducedMotion ? 0 : (Math.sin(frame / 28 + point.phase) + 1) * 2;
      context.beginPath(); context.arc(point.x, point.y, 3 + pulse, 0, Math.PI * 2); context.fillStyle = "rgba(255,112,141,.22)"; context.fill();
      context.beginPath(); context.arc(point.x, point.y, 2.2, 0, Math.PI * 2); context.fillStyle = "#ff708d"; context.fill();
    });
    context.beginPath(); context.arc(origin.x, origin.y, 4, 0, Math.PI * 2); context.fillStyle = "#65d7b0"; context.fill();
    frame += 1; if (!reducedMotion) requestAnimationFrame(paint);
  }
  resize(); paint();
  window.addEventListener("resize", resize, { passive: true });
  canvas.addEventListener("pointermove", (event) => {
    const rect = canvas.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top;
    const nearest = points.map((point) => ({ point, distance: Math.hypot(point.x - x, point.y - y) })).sort((a,b) => a.distance - b.distance)[0];
    if (!nearest || nearest.distance > 20) return;
    byId("source-focus").replaceChildren(node("small", "", `${nearest.point.source.flag || "◌"} ${nearest.point.source.country}`), node("strong", "", `${nearest.point.source.ip} · ${formatCount(nearest.point.source.sessions)} sessions`));
  });
  setText("constellation-label", points.length ? `${points.length} enriched signals` : "Geolocation pending");
}

function renderSnapshot(snapshot) {
  if (snapshot.schema_version !== "3.0") throw new Error(`Unsupported telemetry schema ${snapshot.schema_version || "missing"}`);
  snapshotState = snapshot;
  const summary = snapshot.summary || {}, sensor = snapshot.sensor || {}, quality = snapshot.data_quality || {};
  setText("generated-at", formatDate(snapshot.generated_at));
  setText("window-label", `${compactDate(snapshot.window?.start)} — ${compactDate(snapshot.window?.end)}`);
  setText("sensor-label", `${sensor.platform || "Cowrie"} / ${sensor.region || "unknown"}`);
  const endpoint = sensor.public_endpoint;
  const endpointMeta = byId("endpoint-meta");
  if (endpoint?.host && endpointMeta) {
    const services = (endpoint.services || []).map((service) => `${service.protocol}/${service.port}`).join(" · ");
    setText("endpoint-label", `${endpoint.host} · ${services}`);
    endpointMeta.hidden = false;
  }
  [["metric-sessions", summary.sessions], ["metric-sources", summary.unique_sources], ["metric-auth", summary.auth_attempts], ["metric-commands", summary.commands], ["metric-downloads", summary.downloads], ["metric-techniques", summary.attack_techniques]].forEach(([id, value]) => setText(id, formatCount(value)));
  renderChart(); renderStream(snapshot.recent); renderSources(snapshot.sources); renderRankedList("username-list", snapshot.credentials?.usernames); renderRankedList("password-list", snapshot.credentials?.passwords); renderCommands(snapshot.commands); renderMitre(snapshot.mitre); renderArtifacts(snapshot.artifacts); drawConstellation(snapshot.sources);
  setText("provenance-copy", `${snapshot.provenance?.collection || "Live deception sensor"}. ${snapshot.provenance?.interpretation || "Observations are indicative, not attribution."}`);
  [["quality-events", quality.events_published], ["quality-operator", quality.operator_events_excluded], ["quality-private", quality.non_public_events_excluded], ["quality-redactions", quality.content_redactions], ["quality-invalid", quality.invalid_lines], ["quality-family-lookups", quality.family_lookups], ["quality-family-failures", quality.family_failures], ["quality-schema", snapshot.schema_version]].forEach(([id, value]) => setText(id, formatCount(value)));
}

function observeReveals() {
  const observer = new IntersectionObserver((entries, active) => entries.forEach((entry) => { if (entry.isIntersecting) { entry.target.classList.add("visible"); active.unobserve(entry.target); } }), { threshold: .08 });
  document.querySelectorAll(".reveal:not(.visible)").forEach((element) => observer.observe(element));
}

async function loadDashboard() {
  try {
    const response = await fetch(`${DATA_URL}?v=${Date.now()}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`telemetry request returned HTTP ${response.status}`);
    renderSnapshot(await response.json());
  } catch (error) {
    const banner = byId("dashboard-error"); banner.textContent = `Greyfield snapshot unavailable: ${error.message}`; banner.hidden = false;
  }
}

document.querySelectorAll("[data-hours]").forEach((button) => button.addEventListener("click", () => {
  chartHours = Number(button.dataset.hours); document.querySelectorAll("[data-hours]").forEach((item) => item.classList.toggle("active", item === button)); renderChart();
}));
byId("source-search").addEventListener("input", (event) => renderSources(snapshotState?.sources, event.target.value));
byId("command-search").addEventListener("input", (event) => renderCommands(snapshotState?.commands, event.target.value));
observeReveals(); loadDashboard();
