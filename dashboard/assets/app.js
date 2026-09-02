"use strict";

const DATA_URL = "./data/metrics.json";
const SVG_NS = "http://www.w3.org/2000/svg";
const number = new Intl.NumberFormat("en-US");
const HOME_LIMITS = { events: 10, sources: 12, credentials: 10, commands: 12, artifacts: 6 };
const COLORS = { sessions: "#9e83ff", auth: "#73a9ff", commands: "#ff708d" };
const SERIES_LABELS = { sessions: "Sessions", auth: "Auth", commands: "Commands" };
const COUNTRY_MAP_URL = "./assets/countries-110m.json";

let snapshotState = null;
let chartHours = 24;
const visibleSeries = new Set(["sessions", "auth", "commands"]);

const byId = (id) => document.getElementById(id);
const setText = (id, value) => { const element = byId(id); if (element) element.textContent = value; };
const node = (tag, className, text) => { const element = document.createElement(tag); if (className) element.className = className; if (text !== undefined) element.textContent = text; return element; };
const svgNode = (tag, attributes = {}) => { const element = document.createElementNS(SVG_NS, tag); Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, value)); return element; };
const formatCount = (value) => number.format(Number(value || 0));
const formatDate = (value, options = {}) => { const date = new Date(value); if (Number.isNaN(date.valueOf())) return "Unknown"; return new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short", ...options }).format(date); };
const shortTime = (value) => { const date = new Date(value); return Number.isNaN(date.valueOf()) ? "—" : date.toISOString().slice(11, 16); };
const compactDate = (value) => { const date = new Date(value); return Number.isNaN(date.valueOf()) ? "—" : new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short", timeZone: "UTC" }).format(date); };
const evidenceValue = (item) => typeof item === "string" ? item : item?.value || "Unavailable";

let countryRingsPromise = null;

function decodeCountryRings(topology) {
  const transform = topology.transform || { scale: [1, 1], translate: [0, 0] }, cache = new Map();
  const decodeArc = (index) => {
    const reversed = index < 0, key = reversed ? ~index : index;
    if (!cache.has(key)) {
      let x = 0, y = 0;
      cache.set(key, topology.arcs[key].map(([dx, dy]) => {
        x += dx; y += dy;
        return [x * transform.scale[0] + transform.translate[0], y * transform.scale[1] + transform.translate[1]];
      }));
    }
    const coordinates = cache.get(key);
    return reversed ? [...coordinates].reverse() : coordinates;
  };
  const join = (indices) => indices.flatMap((index, position) => decodeArc(index).slice(position ? 1 : 0));
  const rings = [];
  (topology.objects?.countries?.geometries || []).forEach((geometry) => {
    const polygons = geometry.type === "Polygon" ? [geometry.arcs] : geometry.type === "MultiPolygon" ? geometry.arcs : [];
    polygons.forEach((polygon) => polygon.forEach((ring) => rings.push(join(ring))));
  });
  return rings;
}

function loadCountryRings() {
  if (!countryRingsPromise) countryRingsPromise = fetch(COUNTRY_MAP_URL, { cache: "force-cache" })
    .then((response) => { if (!response.ok) throw new Error(`map request returned HTTP ${response.status}`); return response.json(); })
    .then(decodeCountryRings)
    .catch(() => []);
  return countryRingsPromise;
}

function niceCeiling(value) { if (value <= 1) return 1; const padded = value * 1.12, power = 10 ** Math.floor(Math.log10(padded)), unit = padded / power; return (unit <= 2 ? 2 : unit <= 5 ? 5 : 10) * power; }

function renderChart() {
  const host = byId("pulse-chart"); host.replaceChildren(); const detailed = chartHours === 24 && snapshotState?.five_minute?.length, rows = (detailed ? snapshotState.five_minute : snapshotState?.hourly || []).slice(-(detailed ? 288 : chartHours)), active = [...visibleSeries];
  if (!rows.length || !active.length) { host.append(node("p", "empty-state", active.length ? "No time-series observations available." : "Select a series to display.")); return; }
  const width = 1000, height = 390, left = 42, right = 16, top = 22, bottom = 42, plotWidth = width - left - right, plotHeight = height - top - bottom;
  const maximum = niceCeiling(Math.max(0, ...rows.flatMap((row) => active.map((key) => Number(row[key] || 0)))));
  const svg = svgNode("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": `${active.map((key) => SERIES_LABELS[key]).join(", ")} by ${detailed ? "five-minute" : "hourly"} event time over ${chartHours} hours` });
  const defs = svgNode("defs"), gradient = svgNode("linearGradient", { id: "area-gradient", x1: "0", y1: "0", x2: "0", y2: "1" }); gradient.append(svgNode("stop", { offset: "0%", "stop-color": "#9e83ff", "stop-opacity": ".20" }), svgNode("stop", { offset: "100%", "stop-color": "#9e83ff", "stop-opacity": "0" })); defs.append(gradient); svg.append(defs);
  for (let step = 0; step <= 4; step += 1) { const y = top + plotHeight * step / 4; svg.append(svgNode("line", { x1: left, x2: width - right, y1: y, y2: y, stroke: "rgba(225,217,239,.09)" })); const label = svgNode("text", { x: 0, y: y + 3, fill: "#625b6c", "font-size": "9", "font-family": "monospace" }); label.textContent = String(Math.round(maximum * (1 - step / 4))); svg.append(label); }
  const point = (row, index, key) => [left + (rows.length === 1 ? 0 : index * plotWidth / (rows.length - 1)), top + plotHeight - Number(row[key] || 0) / maximum * plotHeight];
  const makePath = (key) => rows.map((row, index) => `${index ? "L" : "M"}${point(row, index, key).join(" ")}`).join(" ");
  if (visibleSeries.has("sessions")) { const path = makePath("sessions"), finalX = point(rows.at(-1), rows.length - 1, "sessions")[0]; svg.append(svgNode("path", { d: `${path} L${finalX} ${top + plotHeight} L${left} ${top + plotHeight} Z`, fill: "url(#area-gradient)" })); }
  active.forEach((key) => svg.append(svgNode("path", { d: makePath(key), fill: "none", stroke: COLORS[key], "stroke-width": key === "sessions" ? 2.2 : 1.7, "stroke-linejoin": "round", "stroke-linecap": "round" })));
  [...new Set([0, Math.floor((rows.length - 1) / 2), rows.length - 1])].forEach((index) => { const x = point(rows[index], index, active[0])[0], label = svgNode("text", { x, y: height - 10, fill: "#625b6c", "font-size": "9", "font-family": "monospace", "text-anchor": index === 0 ? "start" : index === rows.length - 1 ? "end" : "middle" }); label.textContent = chartHours === 24 ? `${compactDate(rows[index].bucket)} ${shortTime(rows[index].bucket)}` : compactDate(rows[index].bucket); svg.append(label); });
  const guide = svgNode("line", { y1: top, y2: top + plotHeight, stroke: "rgba(240,237,245,.22)", "stroke-dasharray": "3 5", hidden: "" }); svg.append(guide); host.append(svg);
  const tooltip = node("div", "chart-tooltip"); tooltip.hidden = true; host.append(tooltip);
  const update = (event) => { const rect = host.getBoundingClientRect(), ratio = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width)), index = Math.round(ratio * (rows.length - 1)), row = rows[index], x = left + (rows.length === 1 ? 0 : index * plotWidth / (rows.length - 1)); guide.removeAttribute("hidden"); guide.setAttribute("x1", x); guide.setAttribute("x2", x); tooltip.replaceChildren(node("time", "", formatDate(row.bucket)), ...active.map((key) => node("span", key, `${SERIES_LABELS[key]} ${formatCount(row[key])}`))); tooltip.hidden = false; tooltip.style.left = `${Math.min(78, Math.max(8, ratio * 100))}%`; };
  svg.addEventListener("pointermove", update); svg.addEventListener("pointerdown", update); svg.addEventListener("pointerleave", () => { tooltip.hidden = true; guide.setAttribute("hidden", ""); });
}

function renderStream(events) { const list = byId("event-stream"); list.replaceChildren(); (events || []).slice(0, HOME_LIMITS.events).forEach((event) => { const item = node("li", event.severity), time = node("time", "", shortTime(event.time)), body = node("div"); time.dateTime = event.time; body.append(node("strong", "", `${event.country_code} · ${event.ip} · ${event.event}`), node("code", "", event.detail || event.protocol)); item.append(time, body); list.append(item); }); }

function renderSources(sources, query = "") {
  const body = byId("source-rows"); body.replaceChildren(); const term = query.trim().toLowerCase(), filtered = (sources || []).filter((source) => [source.ip, source.country, source.city, source.organization, source.asn].join(" ").toLowerCase().includes(term)), shown = filtered.slice(0, HOME_LIMITS.sources);
  setText("source-count", `${formatCount(shown.length)} of ${formatCount(filtered.length)} sources`); const viewAll = byId("source-view-all"); if (viewAll) viewAll.href = `./evidence.html?section=sources${term ? `&query=${encodeURIComponent(query.trim())}` : ""}`;
  shown.forEach((source) => { const row = document.createElement("tr"), sourceCell = node("td"), network = node("td"), timing = node("td"); sourceCell.append(node("span", "source-ip", `${source.flag || "◌"} ${source.ip}`), node("span", "source-location", `${source.city}, ${source.country}`)); network.append(node("span", "network-name", source.organization), node("span", "network-asn", source.asn ? `AS${source.asn}` : "ASN unresolved")); timing.append(node("span", "source-time", `first ${formatDate(source.first_seen, { year: undefined })}`), node("span", "source-time", `last ${formatDate(source.last_seen, { year: undefined })}`)); row.append(sourceCell, network, timing, node("td", "number-cell", formatCount(source.sessions)), node("td", "number-cell", formatCount(source.auth_attempts)), node("td", "number-cell", formatCount(source.commands)), node("td", "number-cell", formatCount(source.downloads))); body.append(row); });
}

function renderRankedList(id, rows, limit = HOME_LIMITS.credentials) { const host = byId(id); host.replaceChildren(); const visible = (rows || []).slice(0, limit), maximum = Math.max(1, ...visible.map((row) => Number(row.count || 0))); visible.forEach((row) => { const line = node("div", "rank-row"), track = node("span", "rank-track"), fill = node("i"); fill.style.width = `${Math.max(2, Number(row.count || 0) / maximum * 100)}%`; track.append(fill); line.append(node("code", "", row.value), track, node("strong", "", formatCount(row.count))); host.append(line); }); }

function makeExpandable(element) { element.tabIndex = 0; element.setAttribute("role", "button"); element.setAttribute("aria-expanded", "false"); const toggle = () => { const expanded = element.classList.toggle("expanded"); element.setAttribute("aria-expanded", String(expanded)); }; element.addEventListener("click", (event) => { if (!event.target.closest("a")) toggle(); }); element.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); toggle(); } }); }

function renderCommands(commands, query = "") { const host = byId("command-rows"); host.replaceChildren(); const term = query.trim().toLowerCase(); (commands || []).filter((item) => `${item.command} ${(item.families || []).join(" ")} ${(item.techniques || []).join(" ")}`.toLowerCase().includes(term)).slice(0, HOME_LIMITS.commands).forEach((item) => { const row = node("div", "command-row"), command = node("code", "command-value", item.command); if (item.truncated) command.dataset.truncated = "Publisher safety limit reached"; row.append(node("strong", "", `${formatCount(item.count)}×`), command, node("span", "", (item.families || []).join(" · "))); const techniques = node("span", "technique-links"); (item.techniques || []).forEach((id) => { const link = node("a", "", id); link.href = `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`; link.target = "_blank"; link.rel = "noopener noreferrer"; techniques.append(link); }); if (!techniques.childNodes.length) techniques.textContent = "—"; row.append(techniques); makeExpandable(row); host.append(row); }); }

function renderMitre(items) { const host = byId("mitre-grid"); host.replaceChildren(); (items || []).forEach((item, index) => { const card = node("article", "mitre-card reveal"), header = node("header"); header.append(node("span", "", item.id), node("span", "", `${formatCount(item.count)}×`)); card.append(header, node("h4", "", item.name), node("p", "", item.tactic)); const evidence = node("div", "mitre-evidence"); (item.evidence || []).forEach((entry) => evidence.append(node("code", "", `↳ ${evidenceValue(entry)}`))); card.append(evidence); card.style.transitionDelay = `${Math.min(index, 5) * 55}ms`; makeExpandable(card); host.append(card); }); observeReveals(); }

function renderTransferIntelligence(snapshot) { const host = byId("transfer-intelligence"); if (!host) return; const artifacts = snapshot.artifacts || [], providers = artifacts.flatMap((item) => item.correlation?.providers || (item.classification?.provider ? [{ name: item.classification.provider, status: item.classification.status }] : [])), correlated = artifacts.filter((item) => item.correlation?.status === "correlated" || item.classification?.status === "known").length; host.replaceChildren(); const copy = node("div"); copy.append(node("p", "overline", "T1105 / Transfer intelligence"), node("h3", "", "Payload context without execution"), node("p", "", "Hashes are correlated through provider reports only. Greyfield never uploads, downloads, rescans, or executes captured files.")); const facts = node("dl", "transfer-facts"); [["Observed artifacts", artifacts.length], ["Correlated hashes", correlated], ["Provider records", providers.length], ["Provider state", providers.length ? "Available" : "Awaiting API activation"]].forEach(([label, value]) => { const row = node("div"); row.append(node("dt", "", label), node("dd", "", String(value))); facts.append(row); }); host.append(copy, facts); }

function artifactCategory(item) {
  const correlation = item.correlation, providers = correlation?.providers || [];
  if (providers.some((provider) => provider.status === "correlated" && (provider.name !== "VirusTotal" || Number(provider.malicious || 0) > 0))) return "Provider-detected";
  if (correlation?.status === "correlated") return "Provider-observed";
  if (correlation?.status === "not-found") return "No provider record";
  if (correlation?.status === "partial") return "Partial provider coverage";
  if (item.classification?.status === "known") return "Provider-detected";
  if (item.classification?.status === "unknown") return "No provider record";
  return "Correlation unavailable";
}

function renderCorrelation(item) { const cell = node("td", "classification"), correlation = item.correlation; if (!correlation) { const finding = item.classification || {}; cell.append(node("strong", "", finding.status === "known" ? (finding.label || "Provider-detected") : finding.status === "unknown" ? "No provider record" : "Correlation unavailable"), node("small", "", finding.provider ? `${finding.provider} · legacy snapshot` : "Hash lookup not configured")); return cell; } cell.append(node("strong", "", artifactCategory(item))); if (!(correlation.providers || []).length) cell.append(node("small", "", "Provider keys not configured or no cached response")); (correlation.providers || []).forEach((provider) => { const line = node("small", "provider-result", `${provider.name}: ${provider.label || provider.status}`); if (provider.name === "VirusTotal" && provider.malicious !== null) line.textContent += ` · ${provider.malicious} malicious / ${provider.suspicious} suspicious`; cell.append(line); if (provider.retrieved_at) cell.append(node("time", "", `checked ${formatDate(provider.retrieved_at, { year: undefined })}`)); }); return cell; }

function renderArtifacts(items) { const body = byId("artifact-rows"); body.replaceChildren(); const visible = (items || []).slice(0, HOME_LIMITS.artifacts), empty = byId("artifact-empty"); empty.hidden = Boolean(visible.length); document.querySelector(".artifact-table-wrap").hidden = !visible.length; visible.forEach((item) => { const row = document.createElement("tr"), technique = node("a", "artifact-technique", (item.techniques || []).join(", ") || "—"); if (item.techniques?.[0]) { technique.href = `https://attack.mitre.org/techniques/${item.techniques[0].replace(".", "/")}/`; technique.target = "_blank"; technique.rel = "noopener noreferrer"; } const techniqueCell = node("td"); techniqueCell.append(technique); row.append(node("td", "artifact-url", item.url || "Malformed reference withheld"), node("td", "hash", item.sha256 || "Unavailable"), techniqueCell, renderCorrelation(item), node("td", "number-cell", formatCount(item.count)), node("td", "", formatDate(item.last_seen, { year: undefined }))); body.append(row); }); }


function createGlobe(sources) {
  const canvas = byId("source-canvas"), context = canvas.getContext("2d"), focus = byId("source-focus"), controls = byId("globe-source-controls");
  const validSources = (sources || []).filter((source) => Number.isFinite(source.latitude) && Number.isFinite(source.longitude));
  let width = 0, height = 0, radius = 0, points = [], countryRings = [], rotationLon = -30, centerLat = 15, dragging = false, moved = false, last = null, pinned = null, hover = null, frame = 0, visible = true;
  const radians = (value) => value * Math.PI / 180;
  const project = (lon, lat) => {
    const lambda = radians(lon - rotationLon), phi = radians(lat), phi0 = radians(centerLat);
    const visibility = Math.sin(phi0) * Math.sin(phi) + Math.cos(phi0) * Math.cos(phi) * Math.cos(lambda);
    return { x: width / 2 + radius * Math.cos(phi) * Math.sin(lambda), y: height / 2 - radius * (Math.cos(phi0) * Math.sin(phi) - Math.sin(phi0) * Math.cos(phi) * Math.cos(lambda)), visible: visibility > 0 };
  };
  function pathCoordinates(coordinates) {
    context.beginPath(); let previous = null;
    coordinates.forEach(([lon, lat]) => {
      const point = project(lon, lat), discontinuity = previous && Math.hypot(point.x - previous.x, point.y - previous.y) > radius * .24;
      if (!point.visible || discontinuity) { previous = point.visible ? point : null; if (point.visible) context.moveTo(point.x, point.y); return; }
      if (!previous) context.moveTo(point.x, point.y); else context.lineTo(point.x, point.y); previous = point;
    });
    context.stroke();
  }
  function draw() {
    frame = 0;
    if (!visible || document.hidden || !width || !height) return;
    context.clearRect(0, 0, width, height);
    const cx = width / 2, cy = height / 2, glow = context.createRadialGradient(cx - radius * .25, cy - radius * .28, radius * .06, cx, cy, radius);
    glow.addColorStop(0, "rgba(119,91,165,.20)"); glow.addColorStop(.72, "rgba(18,15,25,.88)"); glow.addColorStop(1, "rgba(5,4,8,.98)");
    context.beginPath(); context.arc(cx, cy, radius, 0, Math.PI * 2); context.fillStyle = glow; context.fill(); context.strokeStyle = "rgba(225,217,239,.18)"; context.stroke();
    context.save(); context.beginPath(); context.arc(cx, cy, radius, 0, Math.PI * 2); context.clip();
    context.lineWidth = .65; context.strokeStyle = "rgba(205,192,224,.055)";
    for (let lat = -60; lat <= 60; lat += 30) pathCoordinates(Array.from({ length: 121 }, (_, index) => [-180 + index * 3, lat]));
    for (let lon = -180; lon < 180; lon += 30) pathCoordinates(Array.from({ length: 61 }, (_, index) => [lon, -90 + index * 3]));
    context.lineWidth = .9; context.strokeStyle = "rgba(190,179,210,.28)"; countryRings.forEach(pathCoordinates);
    points = validSources.map((source) => ({ source, ...project(source.longitude, source.latitude) })).filter((point) => point.visible);
    points.forEach((point) => {
      const selected = point.source.ip === (pinned || hover), size = Math.min(6, 2.4 + Math.log2(Number(point.source.sessions || 0) + 1) * .55);
      context.beginPath(); context.arc(point.x, point.y, selected ? size + 7 : size + 3, 0, Math.PI * 2); context.fillStyle = selected ? "rgba(255,112,141,.30)" : "rgba(255,112,141,.14)"; context.fill();
      context.beginPath(); context.arc(point.x, point.y, selected ? size + 1 : size, 0, Math.PI * 2); context.fillStyle = "#ff708d"; context.fill();
    });
    context.restore();
  }
  function requestDraw() { if (!frame && visible && !document.hidden) frame = requestAnimationFrame(draw); }
  function resize() {
    const rect = canvas.getBoundingClientRect(), ratio = Math.min(devicePixelRatio || 1, 2);
    width = rect.width; height = rect.height; radius = Math.max(100, Math.min(width, height) * .39); canvas.width = Math.round(width * ratio); canvas.height = Math.round(height * ratio); context.setTransform(ratio, 0, 0, ratio, 0, 0); requestDraw();
  }
  function nearest(event) {
    const rect = canvas.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top;
    return points.map((point) => ({ point, distance: Math.hypot(point.x - x, point.y - y) })).sort((a, b) => a.distance - b.distance)[0];
  }
  function showSource(source) {
    if (!source) { focus.replaceChildren(node("small", "", "Right-drag to rotate or select a signal"), node("strong", "", "Public source details appear here")); return; }
    const protocols = (source.protocols || []).map((protocol) => typeof protocol === "string" ? protocol : protocol.value).filter(Boolean).join(" / ") || "protocol unresolved";
    const title = node("strong", "", `${source.flag || "◌"} ${source.ip}`), meta = node("span", "", `${source.city}, ${source.country} · ${source.asn ? `AS${source.asn}` : "ASN unresolved"}`), activity = node("span", "", `${formatCount(source.sessions)} sessions · ${formatCount(source.auth_attempts)} auth · ${formatCount(source.commands)} commands · ${formatCount(source.downloads)} artifacts`), timing = node("span", "", `${protocols} · ${formatDate(source.first_seen)} — ${formatDate(source.last_seen)}`), link = node("a", "", "Open source evidence ↗");
    link.href = `./evidence.html?section=sources&query=${encodeURIComponent(source.ip)}`; focus.replaceChildren(node("small", "", source.organization || "Unresolved network"), title, meta, activity, timing, link);
  }
  canvas.addEventListener("contextmenu", (event) => event.preventDefault());
  canvas.addEventListener("pointerdown", (event) => {
    moved = false;
    const rotateGesture = event.pointerType !== "mouse" || event.button === 2;
    if (!rotateGesture) return;
    event.preventDefault(); dragging = true; last = { x: event.clientX, y: event.clientY }; canvas.classList.add("dragging"); canvas.setPointerCapture(event.pointerId);
  });
  canvas.addEventListener("pointermove", (event) => {
    if (dragging && last) { const dx = event.clientX - last.x, dy = event.clientY - last.y; if (Math.abs(dx) + Math.abs(dy) > 2) moved = true; rotationLon -= dx * .35; centerLat = Math.max(-55, Math.min(55, centerLat + dy * .2)); last = { x: event.clientX, y: event.clientY }; requestDraw(); return; }
    if (event.buttons !== 0) moved = true;
    const candidate = nearest(event); hover = candidate && candidate.distance <= 36 ? candidate.point.source.ip : null; if (!pinned) showSource(candidate && candidate.distance <= 36 ? candidate.point.source : null); requestDraw();
  });
  const stopDragging = () => { dragging = false; last = null; canvas.classList.remove("dragging"); };
  canvas.addEventListener("pointerup", (event) => {
    if (!moved && (event.pointerType !== "mouse" || event.button === 0)) {
      const candidate = nearest(event);
      if (candidate && candidate.distance <= 36) { pinned = candidate.point.source.ip; showSource(candidate.point.source); }
      else { pinned = null; showSource(null); }
    }
    stopDragging(); requestDraw();
  });
  canvas.addEventListener("pointercancel", stopDragging);
  canvas.addEventListener("pointerleave", () => { if (!dragging) { hover = null; if (!pinned) showSource(null); requestDraw(); } });
  controls.replaceChildren(); validSources.forEach((source) => { const button = node("button", "", `Select ${source.ip}, ${source.city}, ${source.country}`); button.type = "button"; button.addEventListener("focus", () => { pinned = source.ip; rotationLon = source.longitude; centerLat = Math.max(-55, Math.min(55, source.latitude)); showSource(source); requestDraw(); }); controls.append(button); });
  byId("globe-reset")?.addEventListener("click", () => { rotationLon = -30; centerLat = 15; pinned = null; hover = null; showSource(null); requestDraw(); });
  new ResizeObserver(resize).observe(canvas); new IntersectionObserver(([entry]) => { visible = Boolean(entry?.isIntersecting); if (visible) requestDraw(); }, { rootMargin: "100px" }).observe(canvas); document.addEventListener("visibilitychange", () => { if (!document.hidden && visible) requestDraw(); });
  const loadMap = () => loadCountryRings().then((rings) => { countryRings = rings; requestDraw(); });
  resize(); if ("requestIdleCallback" in window) requestIdleCallback(loadMap, { timeout: 1200 }); else setTimeout(loadMap, 250); setText("constellation-label", `${validSources.length} geolocated sources`);
}

function restoreHashPosition() {
  if (!location.hash) return;
  let id;
  try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
  const target = byId(id);
  if (target) requestAnimationFrame(() => requestAnimationFrame(() => target.scrollIntoView({ block: "start" })));
}

function renderSnapshot(snapshot) { if (!["3.0", "4.0", "5.0"].includes(snapshot.schema_version)) throw new Error(`Unsupported telemetry schema ${snapshot.schema_version || "missing"}`); snapshotState = snapshot; const summary = snapshot.summary || {}, sensor = snapshot.sensor || {}, quality = snapshot.data_quality || {}, sources = snapshot.sources || [], artifacts = snapshot.artifacts || [], coverage = snapshot.coverage || {}; setText("generated-at", formatDate(snapshot.generated_at)); setText("window-label", `${compactDate(snapshot.window?.start)} — ${compactDate(snapshot.window?.end)}`); setText("sensor-label", `${sensor.platform || "Cowrie"} / ${sensor.region || "unknown"}`); const endpoint = sensor.public_endpoint, endpointMeta = byId("endpoint-meta"); if (endpoint?.host && endpointMeta) { setText("endpoint-label", `${endpoint.host} · ${(endpoint.services || []).map((service) => `${service.protocol}/${service.port}`).join(" · ")}`); endpointMeta.hidden = false; } [["metric-sessions", summary.sessions], ["metric-sources", summary.unique_sources], ["metric-auth", summary.auth_attempts], ["metric-commands", summary.commands], ["metric-downloads", summary.downloads], ["metric-techniques", summary.attack_techniques]].forEach(([id, value]) => setText(id, formatCount(value))); renderChart(); renderStream(snapshot.recent); renderSources(sources); renderRankedList("username-list", snapshot.credentials?.usernames); renderRankedList("password-list", snapshot.credentials?.passwords); renderCommands(snapshot.commands); renderMitre(snapshot.mitre); renderTransferIntelligence(snapshot); renderArtifacts(artifacts); createGlobe(sources); setText("provenance-copy", `${snapshot.provenance?.collection || "Live deception sensor"}. ${snapshot.provenance?.interpretation || "Observations are indicative, not attribution."}`); const detected = artifacts.filter((item) => artifactCategory(item) === "Provider-detected").length, countries = new Set(sources.map((source) => source.country_code).filter((value) => value && value !== "ZZ")).size, networks = new Set(sources.map((source) => source.asn).filter(Boolean)).size; [["quality-events", quality.events_published], ["quality-sources", summary.unique_sources], ["quality-accepted", summary.accepted_logins], ["quality-commands", summary.commands], ["quality-artifacts", summary.downloads], ["quality-redactions", quality.content_redactions], ["quality-operator", quality.operator_events_excluded], ["quality-private", quality.non_public_events_excluded], ["quality-countries", countries], ["quality-networks", networks], ["quality-provider-detected", detected], ["quality-artifact-coverage", `${coverage.artifacts?.published ?? artifacts.length} / ${coverage.artifacts?.observed ?? artifacts.length}`]].forEach(([id, value]) => setText(id, typeof value === "string" ? value : formatCount(value))); restoreHashPosition(); }
function observeReveals() { const observer = new IntersectionObserver((entries, active) => entries.forEach((entry) => { if (entry.isIntersecting) { entry.target.classList.add("visible"); active.unobserve(entry.target); } }), { threshold: .08 }); document.querySelectorAll(".reveal:not(.visible)").forEach((element) => observer.observe(element)); }
async function loadDashboard() { try { const response = await fetch(`${DATA_URL}?v=${Date.now()}`, { cache: "no-store" }); if (!response.ok) throw new Error(`telemetry request returned HTTP ${response.status}`); renderSnapshot(await response.json()); } catch (error) { const banner = byId("dashboard-error"); banner.textContent = `Greyfield snapshot unavailable: ${error.message}`; banner.hidden = false; } }
document.querySelectorAll("[data-hours]").forEach((button) => button.addEventListener("click", () => { chartHours = Number(button.dataset.hours); document.querySelectorAll("[data-hours]").forEach((item) => item.classList.toggle("active", item === button)); renderChart(); }));
document.querySelectorAll("[data-series]").forEach((button) => button.addEventListener("click", () => { const key = button.dataset.series; if (visibleSeries.has(key) && visibleSeries.size > 1) visibleSeries.delete(key); else visibleSeries.add(key); const active = visibleSeries.has(key); button.classList.toggle("active", active); button.setAttribute("aria-pressed", String(active)); renderChart(); }));
byId("source-search")?.addEventListener("input", (event) => renderSources(snapshotState?.sources, event.target.value)); byId("command-search")?.addEventListener("input", (event) => renderCommands(snapshotState?.commands, event.target.value)); observeReveals(); loadDashboard();
