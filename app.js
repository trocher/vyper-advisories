"use strict";

const REPO = "vyperlang/vyper";
const PACKAGE = "vyper";
const API = "https://api.github.com";
const CACHE_TTL_MS = 15 * 60 * 1000; // unauthenticated API: 60 requests/hour/IP
const CACHE_PREFIX = "vyper-ghsa:v1:";

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const SEV_LETTER = { critical: "C", high: "H", medium: "M", low: "L", unknown: "?" };

const $ = (sel) => document.querySelector(sel);

const state = {
  advisories: [],   // normalized advisories
  versions: [],     // all known versions, ascending
  shown: [],        // versions displayed as columns
  sevOn: new Set(SEVERITIES),
  showPre: false,
  sort: "fix",
  query: "",
  selected: null,   // selected version object
  fetchedAt: null,
};

/* ------------------------------------------------------------------------ */
/* GitHub fetching with a small localStorage cache                          */
/* ------------------------------------------------------------------------ */

function nextLink(res) {
  const link = res.headers.get("Link");
  if (!link) return null;
  const m = link.split(",").map((s) => s.match(/<([^>]+)>;\s*rel="next"/)).find(Boolean);
  return m ? m[1] : null;
}

async function fetchAllPages(path) {
  let url = API + path;
  const out = [];
  while (url) {
    const res = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
    if (!res.ok) {
      const err = new Error(`GitHub API ${res.status} for ${path}`);
      err.status = res.status;
      if (res.headers.get("X-RateLimit-Remaining") === "0") {
        const reset = Number(res.headers.get("X-RateLimit-Reset")) * 1000;
        err.message = `GitHub API rate limit reached (60 requests/hour without a token). Resets at ${new Date(reset).toLocaleTimeString()}.`;
      }
      throw err;
    }
    out.push(...(await res.json()));
    url = nextLink(res);
  }
  return out;
}

async function cachedFetch(path, force) {
  const key = CACHE_PREFIX + path;
  let cached = null;
  try { cached = JSON.parse(localStorage.getItem(key)); } catch { /* ignore */ }
  if (!force && cached && Date.now() - cached.t < CACHE_TTL_MS) return cached;
  try {
    const data = await fetchAllPages(path);
    const entry = { t: Date.now(), data };
    try { localStorage.setItem(key, JSON.stringify(entry)); } catch { /* quota: ignore */ }
    return entry;
  } catch (e) {
    if (cached) { cached.stale = e.message; return cached; } // serve stale data rather than nothing
    throw e;
  }
}

/* ------------------------------------------------------------------------ */
/* Versions (PEP 440 subset: X.Y.Z[{a,b,rc}N], also "-beta.N" tag style)    */
/* ------------------------------------------------------------------------ */

const PRE_RANK = { a: 0, b: 1, rc: 2 };

function parseVersion(s) {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.]?(a|alpha|b|beta|c|rc|pre|preview)[-.]?(\d*))?$/i.exec(String(s).trim());
  if (!m) return null;
  const nums = [Number(m[1]), Number(m[2] || 0), Number(m[3] || 0)];
  let pre = null;
  if (m[4]) {
    const t = m[4].toLowerCase();
    const kind = t.startsWith("a") ? "a" : t.startsWith("b") ? "b" : "rc";
    pre = [kind, Number(m[5] || 0)];
  }
  const base = nums.join(".");
  return { nums, pre, base, key: base + (pre ? pre[0] + pre[1] : "") };
}

function cmpVersion(a, b) {
  for (let i = 0; i < 3; i++) if (a.nums[i] !== b.nums[i]) return a.nums[i] - b.nums[i];
  if (!a.pre && !b.pre) return 0;
  if (!a.pre) return 1; // final > any pre-release
  if (!b.pre) return -1;
  if (a.pre[0] !== b.pre[0]) return PRE_RANK[a.pre[0]] - PRE_RANK[b.pre[0]];
  return a.pre[1] - b.pre[1];
}

// "<= 0.3.1", ">= 0.2.9, < 0.3.10", "= 0.3.0" -> [[op, version], ...]
function parseRange(range) {
  if (!range || !range.trim()) return [];
  return range.split(",").map((part) => {
    const m = /^\s*(>=|<=|==|!=|>|<|=)?\s*(\S+)\s*$/.exec(part);
    const v = m && parseVersion(m[2]);
    if (!v) throw new Error(`unparseable version range: ${range}`);
    return [m[1] || "=", v];
  });
}

function satisfies(v, constraints) {
  return constraints.every(([op, c]) => {
    const r = cmpVersion(v, c);
    switch (op) {
      case ">=": return r >= 0;
      case "<=": return r <= 0;
      case ">": return r > 0;
      // PEP 440: "<V" excludes pre-releases of V itself (unless V is a pre-release)
      case "<": return r < 0 && !(v.pre && !c.pre && v.base === c.base);
      case "!=": return r !== 0;
      default: return r === 0;
    }
  });
}

function buildVersions(tags, releases) {
  const byKey = new Map();
  const add = (name, date, url) => {
    const v = parseVersion(name);
    if (!v) return;
    const prev = byKey.get(v.key);
    if (prev) {
      prev.date = prev.date || date;
      prev.url = prev.url || url;
      if (name.startsWith("v") && !prev.tag.startsWith("v")) prev.tag = name;
      return;
    }
    byKey.set(v.key, { ...v, tag: name, date, url });
  };
  for (const r of releases) if (!r.draft) add(r.tag_name, r.published_at, r.html_url);
  for (const t of tags) add(t.name, null, null);
  const versions = [...byKey.values()].sort(cmpVersion);
  const finals = new Set(versions.filter((v) => !v.pre).map((v) => v.base));
  for (const v of versions) {
    v.label = v.key;
    // A pre-release is "superseded" once its final version exists; pre-releases of
    // never-finalized versions (0.1.0 betas, upcoming releases) stay visible by default.
    v.superseded = !!v.pre && finals.has(v.base);
    if (!v.url) v.url = `https://github.com/${REPO}/releases/tag/${encodeURIComponent(v.tag)}`;
  }
  return versions;
}

/* ------------------------------------------------------------------------ */
/* Advisories                                                               */
/* ------------------------------------------------------------------------ */

function normalizeAdvisory(a) {
  const vulns = (a.vulnerabilities || []).filter(
    (v) => v.package && v.package.name && v.package.name.toLowerCase() === PACKAGE,
  );
  const ranges = [];
  const patched = [];
  let parseError = null;
  for (const v of vulns) {
    try { ranges.push(parseRange(v.vulnerable_version_range)); } catch (e) { parseError = e.message; }
    if (v.patched_versions) patched.push(...v.patched_versions.split(",").map((s) => s.trim()).filter(Boolean));
  }
  const sev = SEVERITIES.includes(a.severity) ? a.severity : "unknown";
  const score =
    (a.cvss_severities && a.cvss_severities.cvss_v4 && a.cvss_severities.cvss_v4.score) ||
    (a.cvss_severities && a.cvss_severities.cvss_v3 && a.cvss_severities.cvss_v3.score) ||
    (a.cvss && a.cvss.score) || null;
  return {
    id: a.ghsa_id,
    cve: a.cve_id,
    url: a.html_url,
    summary: a.summary || "",
    severity: sev,
    score,
    published: a.published_at,
    rangeText: vulns.map((v) => v.vulnerable_version_range).join(" | ") || "(none listed)",
    ranges,
    patched,
    parseError,
    cwes: (a.cwes || []).map((c) => c.cwe_id),
  };
}

function affects(adv, v) {
  return adv.ranges.some((r) => satisfies(v, r));
}

/* ------------------------------------------------------------------------ */
/* Rendering                                                                */
/* ------------------------------------------------------------------------ */

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "style") e.style.cssText = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) e.append(c);
  return e;
}

function badge(sev) {
  return el("span", { class: `badge sev-${sev}`, "aria-label": sev }, SEV_LETTER[sev]);
}

function visibleAdvisories() {
  const q = state.query.trim().toLowerCase();
  return state.advisories.filter((a) => {
    if (!state.sevOn.has(a.severity)) return false;
    if (!q) return true;
    return [a.id, a.cve, a.summary, a.rangeText, ...a.cwes].some((s) => s && s.toLowerCase().includes(q));
  });
}

// contiguous runs of affected column indices: [[start, end], ...] (inclusive)
function runs(adv, cols) {
  const out = [];
  let start = -1;
  cols.forEach((v, i) => {
    const hit = affects(adv, v);
    if (hit && start < 0) start = i;
    if (!hit && start >= 0) { out.push([start, i - 1]); start = -1; }
  });
  if (start >= 0) out.push([start, cols.length - 1]);
  return out;
}

function sortRows(rows) {
  const by = {
    fix: (a, b) => (a.end - b.end) || (a.start - b.start) || (SEV_RANK[b.adv.severity] - SEV_RANK[a.adv.severity]),
    severity: (a, b) => (SEV_RANK[b.adv.severity] - SEV_RANK[a.adv.severity]) || (a.end - b.end) || (a.start - b.start),
    published: (a, b) => (b.adv.published || "").localeCompare(a.adv.published || ""),
  }[state.sort];
  return rows.sort(by);
}

function renderStats() {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const a of state.advisories) counts[a.severity]++;
  const box = $("#stats");
  box.replaceChildren(
    el("div", { class: "stat" }, el("b", {}, String(state.advisories.length)), "advisories"),
    ...SEVERITIES.filter((s) => counts[s]).map((s) =>
      el("div", { class: "stat" }, badge(s), el("b", {}, String(counts[s])), s)),
  );
}

function renderSevFilters() {
  const present = new Set(state.advisories.map((a) => a.severity));
  $("#sev-filters").replaceChildren(
    ...SEVERITIES.filter((s) => present.has(s)).map((s) =>
      el("button", {
        type: "button",
        class: "sev-toggle",
        "aria-pressed": String(state.sevOn.has(s)),
        onclick: () => {
          state.sevOn.has(s) ? state.sevOn.delete(s) : state.sevOn.add(s);
          render();
        },
      }, el("span", { class: `swatch sev-${s}` }), s)),
  );
}

function renderChart() {
  const cols = state.versions.filter((v) => state.showPre || !v.superseded);
  state.shown = cols;
  const n = cols.length;
  const chart = $("#chart");
  chart.style.setProperty("--cols", n);

  const advs = visibleAdvisories();
  const colAt = (i) => i + 2; // grid column (1 = label)

  // ---- header: series bands, version labels, per-version counts ----
  const head = el("div", { class: "head grid" });
  head.append(el("div", { class: "corner" },
    el("div", {}, `${advs.length} advisories × ${n} versions`),
    el("div", {}, "advisories affecting version ↓")));

  const seriesOf = (v) => `${v.nums[0]}.${v.nums[1]}`;
  let i = 0;
  while (i < n) {
    let j = i;
    while (j + 1 < n && seriesOf(cols[j + 1]) === seriesOf(cols[i])) j++;
    head.append(el("div", { class: "series", style: `grid-column:${colAt(i)} / ${colAt(j) + 1}`, title: "v" + seriesOf(cols[i]) },
      (j - i >= 1 ? "v" : "") + seriesOf(cols[i])));
    i = j + 1;
  }

  const hits = cols.map((v) => advs.filter((a) => affects(a, v)));
  const maxHits = Math.max(1, ...hits.map((h) => h.length));
  cols.forEach((v, c) => {
    const sel = state.selected && state.selected.key === v.key;
    head.append(el("button", {
      type: "button",
      class: `vlabel${v.pre ? " pre" : ""}${sel ? " selected" : ""}`,
      style: `grid-column:${colAt(c)}`,
      "data-col": c,
      title: `${v.tag}${v.date ? " · released " + v.date.slice(0, 10) : ""}`,
      onclick: () => selectVersion(v),
    }, v.label));

    const bySev = SEVERITIES.map((s) => [s, hits[c].filter((a) => a.severity === s).length]).filter(([, k]) => k);
    const stack = el("div", { class: "stack" },
      ...bySev.slice().reverse().map(([s, k]) =>
        el("span", { class: `sev-${s}`, style: `height:${Math.max(2, Math.round((k / maxHits) * 34) - 1)}px` })));
    head.append(el("div", {
      class: "count",
      style: `grid-column:${colAt(c)}`,
      "data-col": c,
      title: `${v.label}: ${hits[c].length} advisories` + (bySev.length ? " (" + bySev.map(([s, k]) => `${k} ${s}`).join(", ") + ")" : ""),
      onclick: () => selectVersion(v),
    }, stack, el("span", { class: "n" }, String(hits[c].length))));
  });

  // ---- body ----
  const body = el("div", { class: "body" });
  const stripes = el("div", { class: "stripes grid" });
  cols.forEach((v, c) => {
    const series = seriesOf(v);
    const first = c === 0 || seriesOf(cols[c - 1]) !== series;
    const altSeries = (v.nums[0] * 100 + v.nums[1]) % 2 === 1;
    const sel = state.selected && state.selected.key === v.key;
    stripes.append(el("div", {
      class: `stripe${altSeries ? " alt" : ""}${first ? " series-start" : ""}${sel ? " selected" : ""}`,
      style: `grid-column:${colAt(c)}`,
      "data-col": c,
    }));
  });
  body.append(stripes);

  let rows = advs.map((adv) => {
    const r = runs(adv, cols);
    return { adv, runs: r, start: r.length ? r[0][0] : n, end: r.length ? r[r.length - 1][1] : n };
  });
  rows = sortRows(rows);

  for (const { adv, runs: rr } of rows) {
    const dim = state.selected && !affects(adv, state.selected);
    const row = el("div", { class: `row grid${dim ? " dim" : ""}`, "data-id": adv.id });
    row.append(el("a", {
      class: "label", href: adv.url, target: "_blank", rel: "noopener", "data-id": adv.id,
    }, badge(adv.severity), el("span", { class: "id" }, adv.id), el("span", { class: "summary" }, adv.summary)));

    for (const [s, e] of rr) {
      const span = e - s + 1;
      const open = e === n - 1 && !adv.patched.length; // still affects the latest version
      const text = open
        ? (span >= 9 ? `${adv.rangeText} · unpatched` : span >= 4 ? "unpatched" : "")
        : (span >= 4 ? adv.rangeText : "");
      row.append(el("a", {
        class: `bar sev-${adv.severity}${open ? " open" : ""}`,
        href: adv.url, target: "_blank", rel: "noopener", "data-id": adv.id,
        style: `grid-column:${colAt(s)} / span ${span}`,
        "aria-label": `${adv.id} (${adv.severity}) affects ${cols[s].label} – ${cols[e].label}${open ? ", unpatched" : ""}`,
      }, text));
    }
    if (rr.length) {
      const last = rr[rr.length - 1][1];
      if (last + 1 < n) {
        row.append(el("span", {
          class: `fix${adv.patched.length ? "" : " unpatched"}`,
          style: `grid-column:${colAt(last + 1)} / span ${Math.min(8, n - last - 1)}`,
        }, adv.patched.length ? "→ " + adv.patched.join(", ") : "unpatched"));
      }
    } else {
      row.append(el("span", { class: "fix", style: `grid-column:${colAt(0)} / span ${Math.min(20, n)}` },
        adv.parseError ? `could not parse range: ${adv.rangeText}` : `no displayed version in range ${adv.rangeText}`));
    }
    body.append(row);
  }

  chart.replaceChildren(head, body);
  $("#chart-wrap").hidden = false;
  $("#hint").hidden = false;
}

function renderDetail() {
  const box = $("#detail");
  const v = state.selected;
  if (!v) { box.hidden = true; return; }
  const list = bySeverity(state.advisories.filter((a) => affects(a, v)));
  const counts = severityCounts(list);
  box.hidden = false;
  box.replaceChildren(
    el("div", { class: "actions" },
      el("button", { type: "button", class: "btn", onclick: (e) => copyMarkdown(versionMarkdown(v), e.currentTarget) }, "copy MD"),
      el("button", { type: "button", class: "btn", onclick: () => downloadMarkdown(versionMarkdown(v), `vyper-${v.label}-advisories.md`) }, "download .md"),
      el("button", { type: "button", class: "btn", onclick: () => selectVersion(null) }, "clear ✕")),
    el("h2", {}, `vyper ${v.label}`),
    el("div", { class: "meta" },
      list.length
        ? `affected by ${list.length} advisor${list.length === 1 ? "y" : "ies"}: ` + counts
        : "no known advisories affect this version",
      v.date ? ` · released ${v.date.slice(0, 10)}` : "",
      " · ", el("a", { href: v.url, target: "_blank", rel: "noopener" }, "release")),
    list.length ? el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "severity"), el("th", {}, "advisory"), el("th", {}, "summary"), el("th", {}, "affected"), el("th", {}, "patched"))),
      el("tbody", {}, ...list.map((a) => el("tr", {},
        el("td", { class: "sev" }, badge(a.severity), a.severity + (a.score ? ` (${a.score})` : "")),
        el("td", {}, el("a", { href: a.url, target: "_blank", rel: "noopener" }, a.id), a.cve ? el("div", {}, a.cve) : null),
        el("td", {}, a.summary),
        el("td", {}, a.rangeText),
        el("td", {}, a.patched.join(", ") || "—"))))) : null,
  );
}

/* ------------------------------------------------------------------------ */
/* Markdown export                                                          */
/* ------------------------------------------------------------------------ */

const bySeverity = (list) => list.slice().sort((a, b) =>
  (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || (b.published || "").localeCompare(a.published || ""));

// "2 high, 9 medium, 15 low"
function severityCounts(list) {
  return SEVERITIES.map((s) => [s, list.filter((a) => a.severity === s).length])
    .filter(([, k]) => k).map(([s, k]) => `${k} ${s}`).join(", ");
}

// same order as the chart's current sort
function sortForExport(list) {
  if (state.sort === "severity") return bySeverity(list);
  if (state.sort === "published") return list.slice().sort((a, b) => (b.published || "").localeCompare(a.published || ""));
  const fixed = (a) => (a.patched.length ? parseVersion(a.patched[0]) : null);
  return list.slice().sort((a, b) => {
    const fa = fixed(a), fb = fixed(b);
    if (!fa || !fb) return (fa ? -1 : 0) - (fb ? -1 : 0) || SEV_RANK[b.severity] - SEV_RANK[a.severity];
    return cmpVersion(fa, fb) || SEV_RANK[b.severity] - SEV_RANK[a.severity];
  });
}

const mdCell = (s) => String(s || "").replace(/\r?\n/g, " ").replace(/\|/g, "\\|").trim();
const capital = (s) => s.charAt(0).toUpperCase() + s.slice(1);

function markdownTable(list) {
  const rows = list.map((a) => [
    capital(a.severity) + (a.score ? ` (${a.score})` : ""),
    `[${a.id}](${a.url})`,
    a.cve || "",
    mdCell(a.summary),
    "`" + a.rangeText.replace(/`/g, "") + "`",
    a.patched.join(", ") || "not patched",
    (a.published || "").slice(0, 10),
  ].join(" | "));
  return [
    "| Severity | Advisory | CVE | Summary | Affected versions | Patched in | Published |",
    "|---|---|---|---|---|---|---|",
    ...rows.map((r) => `| ${r} |`),
  ].join("\n");
}

function sourceLine() {
  const date = (state.fetchedAt || new Date()).toISOString().slice(0, 10);
  return `Source: [${REPO} security advisories](https://github.com/${REPO}/security/advisories), fetched from the GitHub API on ${date}.`;
}

function listMarkdown() {
  const list = sortForExport(visibleAdvisories());
  const filters = [];
  if (state.sevOn.size < new Set(state.advisories.map((a) => a.severity)).size) {
    filters.push("severity: " + SEVERITIES.filter((s) => state.sevOn.has(s)).join(", "));
  }
  if (state.query.trim()) filters.push(`search: "${state.query.trim()}"`);
  return [
    "# Vyper security advisories",
    "",
    `${list.length} published advisor${list.length === 1 ? "y" : "ies"}` + (list.length ? ` (${severityCounts(list)})` : "") + ".",
    filters.length ? `Filters: ${filters.join("; ")}.` : null,
    "",
    sourceLine(),
    "",
    list.length ? markdownTable(list) : "_No advisories match the current filters._",
    "",
  ].filter((l) => l !== null).join("\n");
}

function versionMarkdown(v) {
  const list = bySeverity(state.advisories.filter((a) => affects(a, v)));
  const rel = `[${v.label}](${v.url})` + (v.date ? ` (released ${v.date.slice(0, 10)})` : "");
  return [
    `# Vyper ${v.label}: known security advisories`,
    "",
    list.length
      ? `Vyper ${rel} is affected by **${list.length}** published advisor${list.length === 1 ? "y" : "ies"}: ${severityCounts(list)}.`
      : `No published advisory affects Vyper ${rel}.`,
    "",
    sourceLine(),
    "",
    list.length ? markdownTable(list) : null,
    "",
  ].filter((l) => l !== null).join("\n");
}

async function copyMarkdown(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // clipboard API unavailable (e.g. insecure context): fall back to a hidden textarea
    const ta = el("textarea", { style: "position:fixed;opacity:0" }, text);
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  if (button) {
    const label = button.textContent;
    button.textContent = "copied ✓";
    setTimeout(() => { button.textContent = label; }, 1500);
  }
}

function downloadMarkdown(text, filename) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/markdown;charset=utf-8" }));
  const a = el("a", { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ------------------------------------------------------------------------ */
/* Theme                                                                    */
/* ------------------------------------------------------------------------ */

const THEME_KEY = "vyper-ghsa:theme"; // also read by the inline script in index.html

function renderThemeToggle() {
  const light = document.documentElement.dataset.theme === "light";
  $("#theme-toggle").textContent = light ? "☾ dark" : "☀ light";
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_KEY, next); } catch { /* ignore */ }
  renderThemeToggle();
}

function render() {
  renderSevFilters();
  renderChart();
  renderDetail();
}

/* ------------------------------------------------------------------------ */
/* Interaction                                                              */
/* ------------------------------------------------------------------------ */

function selectVersion(v) {
  state.selected = state.selected && v && state.selected.key === v.key ? null : v;
  const hash = state.selected ? "#v=" + encodeURIComponent(state.selected.label) : " ";
  history.replaceState(null, "", hash === " " ? location.pathname + location.search : hash);
  $("#version-input").value = state.selected ? state.selected.label : "";
  renderChart();
  renderDetail();
  if (state.selected) {
    const c = state.shown.findIndex((x) => x.key === state.selected.key);
    const wrap = $("#chart-wrap");
    if (c >= 0) {
      const col = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--col-w"));
      const label = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--label-w"));
      const x = c * col;
      const visible = wrap.clientWidth - label;
      if (x < wrap.scrollLeft || x > wrap.scrollLeft + visible - col) wrap.scrollLeft = Math.max(0, x - visible / 2);
    }
  }
}

function findVersion(text) {
  const v = parseVersion(text);
  if (!v) return null;
  return state.versions.find((x) => x.key === v.key) || { ...v, label: v.key, tag: text, url: `https://github.com/${REPO}/releases` };
}

function tooltipFor(adv) {
  return el("div", {},
    el("h3", {}, badge(adv.severity), " ", adv.id),
    el("p", { style: "margin:0 0 8px" }, adv.summary),
    el("dl", {},
      el("dt", {}, "severity"), el("dd", {}, adv.severity + (adv.score ? ` · CVSS ${adv.score}` : "")),
      adv.cve ? [el("dt", {}, "CVE"), el("dd", {}, adv.cve)] : null,
      el("dt", {}, "affected"), el("dd", {}, adv.rangeText),
      el("dt", {}, "patched"), el("dd", {}, adv.patched.join(", ") || "not yet patched"),
      el("dt", {}, "published"), el("dd", {}, (adv.published || "").slice(0, 10)),
      adv.cwes.length ? [el("dt", {}, "CWE"), el("dd", {}, adv.cwes.join(", "))] : null));
}

function setupInteraction() {
  const tip = $("#tooltip");
  const chart = $("#chart");
  const byId = () => new Map(state.advisories.map((a) => [a.id, a]));
  let index = null;
  let hoverCol = null;

  const setHoverCol = (c) => {
    if (c === hoverCol) return;
    chart.querySelectorAll(".stripe.hover").forEach((s) => s.classList.remove("hover"));
    hoverCol = c;
    if (c !== null) {
      const s = chart.querySelector(`.stripe[data-col="${c}"]`);
      if (s) s.classList.add("hover");
    }
  };

  chart.addEventListener("mousemove", (ev) => {
    const target = ev.target.closest(".bar, .label");
    if (target) {
      index = index || byId();
      const adv = index.get(target.dataset.id);
      if (adv) {
        tip.replaceChildren(tooltipFor(adv));
        tip.hidden = false;
        const pad = 14;
        const r = tip.getBoundingClientRect();
        let x = ev.clientX + pad;
        let y = ev.clientY + pad;
        if (x + r.width > window.innerWidth - 8) x = ev.clientX - r.width - pad;
        if (y + r.height > window.innerHeight - 8) y = ev.clientY - r.height - pad;
        tip.style.left = Math.max(8, x) + "px";
        tip.style.top = Math.max(8, y) + "px";
      }
    } else {
      tip.hidden = true;
    }
    const colEl = ev.target.closest("[data-col]");
    if (colEl) return setHoverCol(colEl.dataset.col);
    // derive column from pointer position inside the timeline area
    const rect = chart.getBoundingClientRect();
    const css = getComputedStyle(document.documentElement);
    const labelW = parseFloat(css.getPropertyValue("--label-w"));
    const colW = parseFloat(css.getPropertyValue("--col-w"));
    const wrap = $("#chart-wrap").getBoundingClientRect();
    const xIn = ev.clientX - rect.left - labelW;
    if (ev.clientX - wrap.left < labelW || xIn < 0) return setHoverCol(null);
    const c = Math.floor(xIn / colW);
    setHoverCol(c < state.shown.length ? String(c) : null);
  });
  chart.addEventListener("mouseleave", () => { tip.hidden = true; setHoverCol(null); });
  $("#chart-wrap").addEventListener("scroll", () => { tip.hidden = true; }, { passive: true });

  $("#show-pre").addEventListener("change", (e) => { state.showPre = e.target.checked; renderChart(); });
  $("#sort").addEventListener("change", (e) => { state.sort = e.target.value; renderChart(); });
  $("#search").addEventListener("input", (e) => { state.query = e.target.value; renderChart(); });
  $("#version-input").addEventListener("change", (e) => {
    const v = e.target.value.trim() ? findVersion(e.target.value) : null;
    if (e.target.value.trim() && !v) { e.target.setCustomValidity("not a version"); e.target.reportValidity(); return; }
    e.target.setCustomValidity("");
    if (v && v.superseded && !state.showPre) { state.showPre = true; $("#show-pre").checked = true; }
    state.selected = null;
    selectVersion(v);
  });
  $("#refresh").addEventListener("click", (e) => { e.preventDefault(); load(true); });
  $("#md-copy").addEventListener("click", (e) => copyMarkdown(listMarkdown(), e.currentTarget));
  $("#md-download").addEventListener("click", () => downloadMarkdown(listMarkdown(), "vyper-advisories.md"));
  $("#theme-toggle").addEventListener("click", toggleTheme);
  renderThemeToggle();
}

/* ------------------------------------------------------------------------ */
/* Boot                                                                     */
/* ------------------------------------------------------------------------ */

async function load(force = false) {
  const status = $("#status");
  status.hidden = false;
  status.classList.remove("error");
  status.textContent = "Loading advisories from GitHub…";
  try {
    const [adv, tags, rels] = await Promise.all([
      cachedFetch(`/repos/${REPO}/security-advisories?state=published&per_page=100`, force),
      cachedFetch(`/repos/${REPO}/tags?per_page=100`, force),
      cachedFetch(`/repos/${REPO}/releases?per_page=100`, force),
    ]);
    state.advisories = adv.data.map(normalizeAdvisory);
    state.versions = buildVersions(tags.data, rels.data);
    state.fetchedAt = new Date(Math.min(adv.t, tags.t, rels.t));
    const stale = adv.stale || tags.stale || rels.stale;
    $("#fetched").textContent = `data fetched ${state.fetchedAt.toLocaleString()}${stale ? " (stale: " + stale + ")" : ""}`;
    $("#version-list").replaceChildren(...state.versions.slice().reverse().map((v) => el("option", { value: v.label })));

    const m = /^#v=(.+)$/.exec(location.hash);
    if (m) {
      const v = findVersion(decodeURIComponent(m[1]));
      if (v) {
        if (v.superseded) { state.showPre = true; $("#show-pre").checked = true; }
        state.selected = v;
        $("#version-input").value = v.label;
      }
    }
    status.hidden = true;
    renderStats();
    render();
  } catch (e) {
    console.error(e);
    status.classList.add("error");
    status.textContent = "Could not load data from GitHub: " + e.message;
  }
}

setupInteraction();
load();
