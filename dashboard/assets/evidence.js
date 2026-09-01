"use strict";

const DATA_URL = "./data/metrics.json";
const PAGE_SIZE = 25;
const number = new Intl.NumberFormat("en-US");
const byId = (id) => document.getElementById(id);
const node = (tag, className, text) => { const element = document.createElement(tag); if (className) element.className = className; if (text !== undefined) element.textContent = text; return element; };
const formatCount = (value) => number.format(Number(value || 0));
const formatDate = (value) => { const date = new Date(value); return Number.isNaN(date.valueOf()) ? "Unknown" : new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" }).format(date); };
const evidenceValue = (item) => typeof item === "string" ? item : item?.value || "Unavailable";
let snapshot = null;
let section = "sources";
let query = "";
let page = 1;

const SECTION_META = {
  sources: ["Network evidence", "Source infrastructure"],
  credentials: ["Credential pressure", "Attempted credentials"],
  commands: ["Post-access activity", "Observed commands"],
  mitre: ["Analytical mapping", "MITRE ATT&CK evidence"],
  artifacts: ["Payload transfer", "Artifact correlation"],
};

function normalizedRows() {
  if (!snapshot) return [];
  if (section === "sources") return (snapshot.sources || []).map((item) => ({ ...item, _search: [item.ip, item.country, item.city, item.organization, item.asn].join(" ") }));
  if (section === "credentials") return [
    ...(snapshot.credentials?.usernames || []).map((item) => ({ ...item, kind: "Username", _search: `username ${item.value}` })),
    ...(snapshot.credentials?.passwords || []).map((item) => ({ ...item, kind: "Password", _search: `password ${item.value}` })),
  ];
  if (section === "commands") return (snapshot.commands || []).map((item) => ({ ...item, _search: [item.command, ...(item.families || []), ...(item.techniques || [])].join(" ") }));
  if (section === "mitre") return (snapshot.mitre || []).map((item) => ({ ...item, _search: [item.id, item.name, item.tactic, ...(item.evidence || []).map(evidenceValue)].join(" ") }));
  return (snapshot.artifacts || []).map((item) => ({ ...item, _search: [item.url, item.sha256, item.correlation?.status, ...(item.correlation?.providers || []).flatMap((provider) => [provider.name, provider.label, ...(provider.tags || [])])].join(" ") }));
}

function renderSource(item) {
  const article = node("article", "evidence-record source-record");
  article.append(node("strong", "record-primary", `${item.flag || "◌"} ${item.ip}`), node("span", "record-secondary", `${item.city}, ${item.country} · ${item.asn ? `AS${item.asn}` : "ASN unresolved"} · ${item.organization}`));
  const facts = node("dl", "record-facts"); [["Sessions", item.sessions], ["Auth", item.auth_attempts], ["Accepted", item.accepted], ["Commands", item.commands], ["Artifacts", item.downloads], ["Protocols", (item.protocols || []).join(", ")], ["First", formatDate(item.first_seen)], ["Last", formatDate(item.last_seen)]].forEach(([label, value]) => { const row = node("div"); row.append(node("dt", "", label), node("dd", "", String(value))); facts.append(row); }); article.append(facts); return article;
}
function renderCredential(item) { const article = node("article", "evidence-record compact-record"); article.append(node("span", "record-kind", item.kind), node("code", "record-primary", item.value), node("strong", "record-count", `${formatCount(item.count)}×`)); return article; }
function renderCommand(item) { const article = node("article", "evidence-record command-record"); article.append(node("strong", "record-count", `${formatCount(item.count)}×`), node("code", "record-command", item.command)); const meta = node("div", "record-tags"); (item.families || []).forEach((value) => meta.append(node("span", "", value))); (item.techniques || []).forEach((value) => meta.append(node("span", "technique", value))); if (item.truncated) meta.append(node("span", "warning", "Publisher safety limit reached")); article.append(meta); return article; }
function renderMitre(item) { const article = node("article", "evidence-record mitre-record"); const heading = node("header"); heading.append(node("span", "technique", item.id), node("strong", "", item.name), node("span", "record-count", `${formatCount(item.count)}×`)); article.append(heading, node("small", "", item.tactic)); const evidence = node("div", "full-evidence-list"); (item.evidence || []).forEach((entry) => evidence.append(node("code", "", `${formatCount(typeof entry === "string" ? 1 : entry.count)}×  ${evidenceValue(entry)}`))); article.append(evidence); return article; }
function renderArtifact(item) { const article = node("article", "evidence-record artifact-record"); article.append(node("code", "record-primary", item.url || "Malformed transfer reference withheld"), node("code", "record-hash", item.sha256 || "SHA-256 unavailable")); const facts = node("dl", "record-facts"); [["Count", item.count], ["First", formatDate(item.first_seen)], ["Last", formatDate(item.last_seen)], ["ATT&CK", (item.techniques || []).join(", ")], ["Correlation", item.correlation?.status || item.classification?.status || "unavailable"]].forEach(([label, value]) => { const row = node("div"); row.append(node("dt", "", label), node("dd", "", String(value))); facts.append(row); }); article.append(facts); const providers = node("div", "provider-list"); (item.correlation?.providers || []).forEach((provider) => { const card = node("div", "provider-card"); card.append(node("strong", "", provider.name), node("span", "", provider.label || provider.status)); if (provider.name === "VirusTotal" && provider.malicious !== null) card.append(node("small", "", `${provider.malicious} malicious · ${provider.suspicious} suspicious · ${provider.harmless} harmless · ${provider.undetected} undetected`)); if (provider.retrieved_at) card.append(node("time", "", formatDate(provider.retrieved_at))); if (provider.report_url) { const link = node("a", "", "Open provider report ↗"); link.href = provider.report_url; link.target = "_blank"; link.rel = "noopener noreferrer"; card.append(link); } providers.append(card); }); if (!providers.childNodes.length) providers.append(node("p", "empty-state", "No provider correlation is available for this hash.")); article.append(providers); return article; }

function coverageForSection(total) {
  if (section === "credentials") { const usernames = snapshot.coverage?.usernames, passwords = snapshot.coverage?.passwords; if (!usernames || !passwords) return { observed: total, published: total, truncated: false }; return { observed: usernames.observed + passwords.observed, published: usernames.published + passwords.published, truncated: usernames.truncated || passwords.truncated }; }
  const key = section === "mitre" ? null : section; return key && snapshot.coverage?.[key] ? snapshot.coverage[key] : { observed: total, published: total, truncated: false };
}
function updateUrl() { const params = new URLSearchParams(); params.set("section", section); if (query) params.set("query", query); if (page > 1) params.set("page", String(page)); history.replaceState(null, "", `?${params}`); }
function render() {
  const [kicker, title] = SECTION_META[section]; byId("evidence-kicker").textContent = kicker; byId("evidence-title").textContent = title;
  document.querySelectorAll("[data-section]").forEach((button) => { const active = button.dataset.section === section; button.classList.toggle("active", active); button.setAttribute("aria-pressed", String(active)); });
  const all = normalizedRows(), term = query.trim().toLowerCase(), filtered = all.filter((item) => !term || item._search.toLowerCase().includes(term));
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE)); page = Math.min(page, pages); const visible = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), host = byId("evidence-results"); host.replaceChildren();
  const renderer = { sources: renderSource, credentials: renderCredential, commands: renderCommand, mitre: renderMitre, artifacts: renderArtifact }[section]; visible.forEach((item) => host.append(renderer(item))); if (!visible.length) host.append(node("p", "empty-state", "No reviewed evidence matches this filter."));
  const boundary = coverageForSection(all.length); byId("evidence-total").textContent = `${formatCount(filtered.length)} matching records`; byId("evidence-coverage").textContent = boundary.truncated ? `${formatCount(boundary.published)} of ${formatCount(boundary.observed)} distinct records published at the safety boundary` : `${formatCount(boundary.published)} reviewed records published`;
  byId("page-status").textContent = `Page ${page} of ${pages}`; byId("page-previous").disabled = page <= 1; byId("page-next").disabled = page >= pages; updateUrl();
}
async function load() { try { const response = await fetch(`${DATA_URL}?v=${Date.now()}`, { cache: "no-store" }); if (!response.ok) throw new Error(`telemetry request returned HTTP ${response.status}`); snapshot = await response.json(); if (!["3.0", "4.0"].includes(snapshot.schema_version)) throw new Error(`unsupported telemetry schema ${snapshot.schema_version}`); byId("evidence-generated").textContent = formatDate(snapshot.generated_at); byId("evidence-schema").textContent = snapshot.schema_version; byId("evidence-window").textContent = `${formatDate(snapshot.window?.start)} — ${formatDate(snapshot.window?.end)}`; render(); } catch (error) { const banner = byId("evidence-error"); banner.textContent = `Evidence snapshot unavailable: ${error.message}`; banner.hidden = false; } }
const params = new URLSearchParams(location.search); if (SECTION_META[params.get("section")]) section = params.get("section"); query = params.get("query") || ""; { const requestedPage = Number(params.get("page") || 1); page = Number.isFinite(requestedPage) ? Math.max(1, Math.floor(requestedPage)) : 1; } byId("evidence-search").value = query;
document.querySelectorAll("[data-section]").forEach((button) => button.addEventListener("click", () => { section = button.dataset.section; page = 1; render(); })); byId("evidence-search").addEventListener("input", (event) => { query = event.target.value; page = 1; render(); }); byId("page-previous").addEventListener("click", () => { page -= 1; render(); scrollTo({ top: byId("evidence-results").offsetTop - 120, behavior: "smooth" }); }); byId("page-next").addEventListener("click", () => { page += 1; render(); scrollTo({ top: byId("evidence-results").offsetTop - 120, behavior: "smooth" }); });
document.querySelectorAll(".reveal").forEach((element) => element.classList.add("visible")); load();
