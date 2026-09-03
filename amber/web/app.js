const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

const VERDICT_RU = { VULNERABLE: "сработал", SAFE: "не сработал", INCONCLUSIVE: "нет данных", pending: "—" };
const SEV_RU = { critical: "крит", high: "высок", medium: "средн", low: "низк" };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

let catalog = null;
let rows = [];          // {probe, result|null}
let selected = null;    // probe_id
let stream = null;
let startedAt = 0;
let summary = null;
let activeTab = "req";

const filters = { severity: new Set(), verdict: new Set(), category: new Set(), q: "" };
let sortKey = "severity";
let sortDir = 1;

/* ── тема ─────────────────────────────────────── */
const savedTheme = (() => { try { return localStorage.getItem("amber-theme"); } catch { return null; } })();
if (savedTheme) document.documentElement.dataset.theme = savedTheme;
$("theme").onclick = () => {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("amber-theme", next); } catch {}
};

/* ── загрузка каталога ────────────────────────── */
async function loadCatalog() {
  catalog = await (await fetch("/api/catalog")).json();
  rows = catalog.probes.map((p) => ({ probe: p, result: null }));
  buildFilters();
  renderRows();
  updateCounts();
}

function buildFilters() {
  const cats = [...new Set(catalog.probes.map((p) => p.category))];
  const sevs = ["critical", "high", "medium", "low"].filter((s) =>
    catalog.probes.some((p) => p.severity === s)
  );
  const chip = (group, value, label, count) =>
    `<button class="chip" data-g="${group}" data-v="${esc(value)}">${esc(label)}` +
    (count != null ? `<i>${count}</i>` : "") + `</button>`;

  $("filters").innerHTML =
    sevs.map((s) => chip("severity", s, SEV_RU[s], catalog.probes.filter((p) => p.severity === s).length)).join("") +
    `<span class="sep"></span>` +
    ["VULNERABLE", "SAFE", "INCONCLUSIVE"].map((v) => chip("verdict", v, VERDICT_RU[v])).join("") +
    `<span class="sep"></span>` +
    cats.map((c) => chip("category", c, c, catalog.probes.filter((p) => p.category === c).length)).join("") +
    `<input type="search" id="q" placeholder="поиск по id, тегу, тексту…">`;

  $("filters").querySelectorAll(".chip").forEach((el) => {
    el.onclick = () => {
      const set = filters[el.dataset.g];
      set.has(el.dataset.v) ? set.delete(el.dataset.v) : set.add(el.dataset.v);
      el.classList.toggle("on");
      renderRows();
    };
  });
  $("q").oninput = (e) => { filters.q = e.target.value.toLowerCase(); renderRows(); };
}

/* ── таблица ──────────────────────────────────── */
function visible() {
  return rows.filter(({ probe, result }) => {
    if (filters.severity.size && !filters.severity.has(probe.severity)) return false;
    if (filters.category.size && !filters.category.has(probe.category)) return false;
    if (filters.verdict.size && !filters.verdict.has(result?.verdict)) return false;
    if (filters.q) {
      const hay = [probe.id, probe.category, probe.owasp, probe.prompt, probe.tags.join(" "),
                   result?.response, result?.reason].join(" ").toLowerCase();
      if (!hay.includes(filters.q)) return false;
    }
    return true;
  }).sort((a, b) => {
    const get = (r) =>
      sortKey === "severity" ? SEV_ORDER[r.probe.severity]
      : sortKey === "verdict" ? (r.result ? r.result.verdict : "zz")
      : r.probe[sortKey] ?? "";
    const x = get(a), y = get(b);
    return (x > y ? 1 : x < y ? -1 : 0) * sortDir;
  });
}

function renderRows() {
  const list = visible();
  $("rows").innerHTML = list.map(({ probe, result }) => {
    const v = result ? result.verdict : "pending";
    return `<tr data-id="${esc(probe.id)}" class="v-${v}${probe.id === selected ? " sel" : ""}">
      <td><span class="mark"></span>${esc(probe.id)}</td>
      <td class="sev sev-${probe.severity}">${SEV_RU[probe.severity]}</td>
      <td>${esc(probe.category)}</td>
      <td class="owasp">${esc(probe.owasp.replace(":2025", ""))}</td>
      <td class="vd vd-${v}">${VERDICT_RU[v]}</td>
    </tr>`;
  }).join("");

  $("rows").querySelectorAll("tr").forEach((tr) => {
    tr.onclick = () => select(tr.dataset.id);
  });
}

document.querySelectorAll("th[data-sort]").forEach((th) => {
  th.onclick = () => {
    sortDir = sortKey === th.dataset.sort ? -sortDir : 1;
    sortKey = th.dataset.sort;
    renderRows();
  };
});

/* ── деталь ───────────────────────────────────── */
function select(id) {
  selected = id;
  renderRows();
  const row = rows.find((r) => r.probe.id === id);
  if (!row) return;
  renderDetail(row);
  document.querySelector("tr.sel")?.scrollIntoView({ block: "nearest" });
}

function renderDetail({ probe, result }) {
  const owaspTitle = catalog.owasp_titles[probe.owasp] || "";
  $("dhead").innerHTML = `
    <div class="dtitle">
      <span class="id">${esc(probe.id)}</span>
      <span class="pill">${esc(probe.category)}</span>
      <span class="pill sev-${probe.severity}">${SEV_RU[probe.severity]}</span>
      <span class="pill owasp" title="${esc(owaspTitle)}">${esc(probe.owasp)} · ${esc(owaspTitle)}</span>
      ${probe.tags.map((t) => `<span class="pill">${esc(t)}</span>`).join("")}
    </div>
    <div class="dsub">${esc(probe.rationale)}</div>`;

  const tabs = [
    ["req", "Запрос"],
    ["res", "Ответ", result?.latency_s ? `${result.latency_s}s` : ""],
    ["det", "Детектор", probe.detector],
    ["fix", "Проверить руками"],
  ];
  $("tabs").hidden = false;
  $("tabs").innerHTML = tabs.map(([k, label, badge]) =>
    `<button class="tab${k === activeTab ? " on" : ""}" data-t="${k}">${label}${badge ? `<b>${esc(badge)}</b>` : ""}</button>`
  ).join("");
  $("tabs").querySelectorAll(".tab").forEach((b) => {
    b.onclick = () => { activeTab = b.dataset.t; renderDetail({ probe, result }); };
  });

  let body = "";
  if (activeTab === "req") {
    body = `<div class="h">Системный промпт, который защищаем</div>
      <pre class="raw">${esc(catalog.system_prompt)}</pre>
      <div class="h">Сообщение пользователя (полезная нагрузка)</div>
      <pre class="raw">${esc(probe.prompt)}</pre>`;
  } else if (activeTab === "res") {
    body = result
      ? `<div class="h">Ответ модели</div><pre class="raw">${esc(result.response) || "«пусто»"}</pre>`
      : `<div class="empty">Пробник ещё не запускался</div>`;
  } else if (activeTab === "det") {
    body = result
      ? `<dl class="kv">
           <dt>детектор</dt><dd>${esc(probe.detector)}</dd>
           ${probe.detector_arg ? `<dt>искомое значение</dt><dd>${esc(probe.detector_arg)}</dd>` : ""}
           <dt>вердикт</dt><dd class="vd-${result.verdict}">${VERDICT_RU[result.verdict]}</dd>
           <dt>задержка</dt><dd>${result.latency_s}s</dd>
         </dl>
         <div class="note ${result.verdict === "VULNERABLE" ? "bad" : "good"}">${esc(result.reason)}</div>`
      : `<div class="empty">Пробник ещё не запускался</div>`;
  } else {
    body = `<div class="h">${esc(probe.owasp)} — ${esc(owaspTitle)}</div>
      <div class="h">Что это значит и что проверить руками</div>
      <div class="note">${esc(probe.next_check)}</div>
      <div class="h">Почему пробник существует</div>
      <div class="note">${esc(probe.rationale)}</div>`;
  }
  $("dbody").innerHTML = body;
}

function renderSummary() {
  if (!summary) return;
  activeTab = null;
  selected = null;
  renderRows();
  $("dhead").innerHTML = `<div class="dtitle"><span class="id">Итог прогона</span>
      <span class="pill">${esc(summary.model)}</span>
      <span class="pill">${esc(summary.endpoint)}</span></div>
    <div class="dsub">${esc(summary.timestamp)} · сработало ${summary.vulnerable} из ${summary.total}
      · индекс прогона ${summary.robustness_score}</div>`;
  $("tabs").hidden = true;

  const owaspRows = Object.entries(summary.by_owasp).map(([code, v]) => {
    const pct = Math.round((v.vulnerable / v.total) * 100);
    return `<div class="brow">
      <span>${esc(code)} ${esc(catalog.owasp_titles[code] || "")}</span>
      <span class="btrack"><i style="width:${pct}%"></i></span>
      <span class="bnum">${v.vulnerable}/${v.total}</span></div>`;
  }).join("");

  const catRows = Object.entries(summary.by_category).map(([c, v]) => {
    const pct = Math.round((v.vulnerable / v.total) * 100);
    return `<div class="brow">
      <span>${esc(c)}</span>
      <span class="btrack"><i style="width:${pct}%"></i></span>
      <span class="bnum">${v.vulnerable}/${v.total}</span></div>`;
  }).join("");

  $("dbody").innerHTML =
    `<div class="h">По OWASP Top 10 для LLM (2025)</div><div class="bars">${owaspRows}</div>` +
    `<div class="h">По категориям пробников</div><div class="bars">${catRows}</div>` +
    `<div class="h">Как читать индекс прогона</div>
     <div class="note">Каждый пробник весит по критичности (critical 4, high 3, medium 2, low 1).
     Индекс — доля веса несработавших от общего. Это не оценка безопасности,
     а показатель для сравнения: между моделями, версиями системного промпта и прогонами
     до и после правки защиты.</div>`;
}


/* ══ Дашборд ══════════════════════════════════════
   Цвета — фиксированная статусная палитра (good/warning/critical).
   Замер показал: good↔critical различаются на ΔE 4.1 при дейтеранопии,
   поэтому вердикт нигде не кодируется одним цветом — везде есть форма
   (заливка / контур / штриховка) и подпись.
   ══════════════════════════════════════════════ */

const STATUS = {
  VULNERABLE: { color: "var(--hit)", label: "сработал", glyph: "fill" },
  SAFE:       { color: "var(--miss)", label: "не сработал", glyph: "ring" },
  INCONCLUSIVE:{ color: "var(--none)", label: "нет данных", glyph: "hatch" },
};

function glyphSvg(kind, color, size = 11) {
  const s = size, h = s / 2;
  if (kind === "ring")
    return `<svg class="glyph" width="${s}" height="${s}" viewBox="0 0 ${s} ${s}" aria-hidden="true">
      <circle cx="${h}" cy="${h}" r="${h - 1.5}" fill="none" stroke="${color}" stroke-width="2.5"/></svg>`;
  if (kind === "hatch")
    return `<svg class="glyph" width="${s}" height="${s}" viewBox="0 0 ${s} ${s}" aria-hidden="true">
      <defs><pattern id="h${s}" width="4" height="4" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
        <line x1="0" y1="0" x2="0" y2="4" stroke="${color}" stroke-width="2.4"/></pattern></defs>
      <rect width="${s}" height="${s}" rx="2" fill="url(#h${s})" stroke="${color}" stroke-width="1"/></svg>`;
  return `<svg class="glyph" width="${s}" height="${s}" viewBox="0 0 ${s} ${s}" aria-hidden="true">
    <rect width="${s}" height="${s}" rx="2.5" fill="${color}"/></svg>`;
}

function cellFill(verdict) {
  if (!verdict) return "";
  const st = STATUS[verdict];
  if (st.glyph === "fill") return `background:${st.color};border-color:${st.color}`;
  if (st.glyph === "ring") return `background:transparent;border:2px solid ${st.color}`;
  return `background:repeating-linear-gradient(45deg,${st.color} 0 3px,transparent 3px 6px);border-color:${st.color}`;
}

/* ── подсказка ────────────────────────────────── */
const tip = () => $("tip");
function showTip(e, html) {
  const t = tip();
  t.innerHTML = html;
  t.classList.add("on");
  const r = t.getBoundingClientRect();
  const x = Math.min(e.clientX + 14, window.innerWidth - r.width - 10);
  const y = Math.min(e.clientY + 14, window.innerHeight - r.height - 10);
  t.style.left = `${x}px`;
  t.style.top = `${y}px`;
}
const hideTip = () => tip().classList.remove("on");

/* ── части дашборда ───────────────────────────── */
function heroBlock(s) {
  const share = s.total ? Math.round((100 * s.vulnerable) / s.total) : 0;
  const tone = s.vulnerable ? "var(--hit)" : "var(--miss)";
  return `<div class="sect">
    <h2>Сработало пробников</h2>
    <div class="hero">
      <div><div class="num">${s.vulnerable} из ${s.total}</div></div>
      <div class="cap">${esc(s.model)} · ${esc(s.endpoint)}</div>
    </div>
    <div class="meter"><i style="width:${share}%;background:${tone}"></i></div>
    <div class="meter-scale">
      <span>каждое срабатывание — место, которое стоит посмотреть руками</span>
      <span>индекс прогона ${s.robustness_score} — для сравнения прогонов, не оценка безопасности</span>
    </div>
  </div>`;
}

function kpiBlock(s) {
  const tiles = [
    ["VULNERABLE", s.vulnerable, "есть что посмотреть руками"],
    ["SAFE", s.safe, "этот пробник, не более"],
    ["INCONCLUSIVE", s.inconclusive, "сеть, таймаут, пустой ответ"],
  ];
  return `<div class="sect"><h2>Итог по пробникам</h2><div class="kpi">
    ${tiles.map(([v, n, sub]) => `<div class="tile">
      <div class="lab">${glyphSvg(STATUS[v].glyph, STATUS[v].color)} ${STATUS[v].label}</div>
      <div class="val">${n}</div>
      <div class="sub">${sub}</div>
    </div>`).join("")}
    <div class="tile">
      <div class="lab">всего пробников</div>
      <div class="val">${s.total}</div>
      <div class="sub">${Object.keys(s.by_category).length} категорий</div>
    </div>
  </div></div>`;
}

function legendBlock() {
  return `<div class="legend">${["VULNERABLE", "SAFE", "INCONCLUSIVE"]
    .map((v) => `<span>${glyphSvg(STATUS[v].glyph, STATUS[v].color)} ${STATUS[v].label}</span>`).join("")}</div>`;
}

function partWhole(title, lede, entries, nameOf) {
  const rows = entries.map(([key, v]) => {
    const total = v.total;
    const safe = v.safe ?? total - v.vulnerable - (v.inconclusive ?? 0);
    const na = v.inconclusive ?? 0;
    const seg = (verdict, n) => {
      if (!n) return "";
      const st = STATUS[verdict];
      const pct = (n / total) * 100;
      const bg = verdict === "INCONCLUSIVE"
        ? `repeating-linear-gradient(45deg,${st.color} 0 4px,rgba(0,0,0,.25) 4px 8px)`
        : st.color;
      const inner = pct > 12 ? `<span>${n}</span>` : "";
      return `<i data-v="${verdict}" data-n="${n}" data-k="${esc(key)}"
        style="width:${pct}%;background:${bg}">${inner}</i>`;
    };
    return `<div class="pwrow">
      <div class="name">${nameOf(key)}</div>
      <div class="pwbar">${seg("VULNERABLE", v.vulnerable)}${seg("SAFE", safe)}${seg("INCONCLUSIVE", na)}</div>
      <div class="pwnum">${v.vulnerable}/${total}</div>
    </div>`;
  }).join("");

  return `<div class="sect"><h2>${title}</h2>
    ${lede ? `<p class="lede">${lede}</p>` : ""}
    ${legendBlock()}
    <div class="pw">${rows}</div></div>`;
}

function matrixBlock() {
  const groups = {};
  rows.forEach((r) => (groups[r.probe.category] ??= []).push(r));
  const body = Object.entries(groups).map(([cat, list]) => `<div class="mgroup">
      <div class="name">${esc(cat)}</div>
      <div class="cells">${list.map(({ probe, result }) => {
        const v = result?.verdict;
        const st = v ? STATUS[v].label : "не запускался";
        return `<button class="cell${v ? "" : " pending"}" data-id="${esc(probe.id)}"
          style="${cellFill(v)}" aria-label="${esc(probe.id)} — ${st}"><b>${esc(probe.id.split("-")[1])}</b></button>`;
      }).join("")}</div>
    </div>`).join("");

  return `<div class="sect"><h2>Карта пробников</h2>
    <p class="lede">Каждая ячейка — один пробник. Заливка — сработал, контур — не сработал,
    штриховка — нет данных. Наведите, чтобы увидеть подробности, нажмите, чтобы открыть находку.</p>
    ${legendBlock()}
    <div class="matrix">${body}</div></div>`;
}

function renderDash() {
  const inner = $("dashInner");
  if (!summary) {
    const done = rows.filter((r) => r.result).length;
    inner.innerHTML = done
      ? `<div class="dash-empty">Сканирование идёт — обработано ${done} из ${rows.length}</div>${matrixBlock()}`
      : `<div class="dash-empty">Запустите сканирование — здесь появятся сводные показатели</div>${matrixBlock()}`;
    bindDash();
    return;
  }
  inner.innerHTML =
    heroBlock(summary) +
    kpiBlock(summary) +
    partWhole("По OWASP Top 10 для LLM (2025)",
      "Стандартная таксономия рисков LLM. Показывает, какой класс риска у этой модели слабее.",
      Object.entries(summary.by_owasp).map(([k, v]) => [k, { ...v, safe: v.total - v.vulnerable, inconclusive: 0 }]),
      (k) => `${esc(k)}<small>${esc(catalog.owasp_titles[k] || "")}</small>`) +
    partWhole("По категориям пробников", "", Object.entries(summary.by_category), (k) => esc(k)) +
    matrixBlock();
  bindDash();
}

function bindDash() {
  $("dashInner").querySelectorAll(".cell").forEach((el) => {
    const row = rows.find((r) => r.probe.id === el.dataset.id);
    el.onmousemove = (e) => {
      const v = row.result?.verdict;
      showTip(e, `<b>${esc(row.probe.id)}</b>
        <s>${esc(row.probe.category)} · ${SEV_RU[row.probe.severity]} · ${esc(row.probe.owasp)}</s>
        <s style="margin-top:5px;color:${v ? STATUS[v].color : "var(--faint)"}">
          ${v ? STATUS[v].label + " — " + esc(row.result.reason) : "ещё не запускался"}</s>`);
    };
    el.onmouseleave = hideTip;
    el.onclick = () => { hideTip(); switchView("find"); select(row.probe.id); };
  });

  $("dashInner").querySelectorAll(".pwbar i").forEach((el) => {
    el.onmousemove = (e) => showTip(e,
      `<b>${esc(el.dataset.k)}</b><s>${STATUS[el.dataset.v].label}: ${el.dataset.n}</s>`);
    el.onmouseleave = hideTip;
  });
}


/* ══ Поиск атак (MAP-Elites) ═════════════════════
   Цель поиска — ПОКРЫТИЕ сетки поведений, а не доля успеха.
   В каждой клетке (риск × стиль) хранится лучшая найденная особь.
   Это и есть защита от mode collapse: поиск не сходится к одной уловке.
   ══════════════════════════════════════════════ */

let evoGrid = null;      // {risks, styles, titles}
let evoStream = null;
let evoState = null;      // последнее событие
let evoCov = [];          // история покрытия для спарклайна

async function loadGrid() {
  evoGrid = await (await fetch("/api/grid")).json();
}

function evoShell() {
  const g = evoGrid;
  return `<div class="sect">
    <h2>Поиск атак — эволюция MAP-Elites</h2>
    <p class="lede">Мастер-генератор мутирует атаки и раскладывает лучшие по сетке
    «класс риска × стиль подачи». Оптимизируется покрытие сетки, а не число успехов —
    так поиск находит разные приёмы, а не переоткрывает один. Обучения весов здесь нет:
    это этап 0, вся сила в отборе.</p>
    <div class="ev-bar">
      <div class="field"><label>цель</label><input id="ev-url" value="http://localhost:1234"></div>
      <div class="field"><label>модель</label><input id="ev-model" value="local-model"></div>
      <div class="field"><label>поколений</label><input id="ev-gens" value="60" style="min-width:70px"></div>
      <button class="btn" id="ev-run">Запустить поиск</button>
      <button class="btn sec" id="ev-stop" hidden>Стоп</button>
    </div>
    <div class="ev-stats" id="ev-stats"></div>
  </div>
  <div class="sect"><h2>Заполнение сетки</h2>
    <div class="ramp" style="margin-bottom:10px">
      <span><i style="background:var(--track)"></i> пусто</span>
      <span><i style="background:var(--warn)"></i> занято, пробоя нет</span>
      <span><i style="background:var(--hit)"></i> пробой найден</span>
    </div>
    <div class="gridwrap"><table class="mapgrid" id="ev-grid"></table></div>
  </div>
  <div class="sect"><h2>Рост покрытия</h2>
    <svg class="spark" id="ev-spark" preserveAspectRatio="none"></svg>
  </div>
  <div class="sect"><h2>Ход поиска</h2><div class="ev-log" id="ev-log"></div></div>`;
}

function evoStatsBlock(e) {
  const tiles = [
    ["покрытие", `${e.coverage}/${e.capacity}`, "клеток сетки"],
    ["пробоев", e.solved, "клеток с пробоем"],
    ["дубликатов отсеяно", e.duplicates, "почти-копий"],
    ["шаг", `${e.step ?? e.coverage}/${e.total ?? e.capacity}`, `поколение ${e.generation ?? "—"}`],
  ];
  return tiles.map(([lab, val, sub]) =>
    `<div class="tile"><div class="lab">${lab}</div><div class="val">${val}</div><div class="sub">${sub}</div></div>`
  ).join("");
}

const evoCells = {};   // "risk|style" -> последнее событие

function drawGrid() {
  const g = evoGrid;
  const head = `<tr><th class="rowh"></th>${g.styles.map((s) =>
    `<th title="${esc(s)}">${esc(g.style_titles[s])}</th>`).join("")}</tr>`;
  const rows = g.risks.map((risk) => {
    const tds = g.styles.map((style) => {
      const key = `${risk}|${style}`;
      const c = evoCells[key];
      let cls = "gcell", style_attr = "";
      if (c) {
        cls += " filled";
        if (c.verdict === "VULNERABLE") { cls += " breach"; style_attr = "background:var(--crit)"; }
        else style_attr = "background:var(--warn)";
      }
      return `<td><span class="${cls}" style="${style_attr}" data-key="${esc(key)}"></span></td>`;
    }).join("");
    return `<tr><th class="rowh">${esc(g.risk_titles[risk])}</th>${tds}</tr>`;
  }).join("");
  $("ev-grid").innerHTML = head + rows;

  $("ev-grid").querySelectorAll(".gcell.filled").forEach((el) => {
    const c = evoCells[el.dataset.key];
    el.onmousemove = (ev) => showTip(ev,
      `<b>${esc(c.risk)} · ${esc(evoGrid.style_titles[c.style] || c.style)}</b>
       <s>${c.verdict === "VULNERABLE" ? STATUS.VULNERABLE.label : "пробоя нет"} · f=${c.fitness}</s>
       <s style="margin-top:5px">${esc((c.prompt || "").slice(0, 160))}</s>`);
    el.onmouseleave = hideTip;
  });
}

function drawSpark() {
  if (evoCov.length < 2) { $("ev-spark").innerHTML = ""; return; }
  const w = 600, h = 64, max = evoState ? evoState.capacity : Math.max(...evoCov);
  const dx = w / (evoCov.length - 1);
  const pts = evoCov.map((v, i) => `${(i * dx).toFixed(1)},${(h - (v / max) * (h - 4) - 2).toFixed(1)}`);
  $("ev-spark").setAttribute("viewBox", `0 0 ${w} ${h}`);
  $("ev-spark").innerHTML =
    `<polyline points="${pts.join(" ")}" fill="none" stroke="var(--accent)" stroke-width="2"
       vector-effect="non-scaling-stroke" stroke-linejoin="round"/>`;
}

function renderEvo() {
  const inner = $("evoInner");
  if (!inner.dataset.built) {
    inner.innerHTML = evoShell();
    inner.dataset.built = "1";
    Object.keys(evoCells).forEach((k) => delete evoCells[k]);
    if (q0("url")) $("ev-url").value = q0("url");
    if (q0("model")) $("ev-model").value = q0("model");
    $("ev-run").onclick = startEvo;
    $("ev-stop").onclick = stopEvo;
    drawGrid();
    $("ev-stats").innerHTML = evoStatsBlock({ coverage: 0, capacity: evoGrid.risks.length * evoGrid.styles.length, solved: 0, duplicates: 0 });
  }
}

function startEvo() {
  if (evoStream) return;
  Object.keys(evoCells).forEach((k) => delete evoCells[k]);
  evoCov = [];
  $("ev-log").innerHTML = "";
  drawGrid();
  $("ev-run").disabled = true; $("ev-stop").hidden = false;

  const qs = new URLSearchParams({
    url: $("ev-url").value.trim(),
    model: $("ev-model").value.trim(),
    generations: $("ev-gens").value.trim() || "60",
  });
  evoStream = new EventSource(`/api/evolve?${qs}`);
  const MARK = { new: "+", improved: "^", duplicate: "=", worse: "·" };

  evoStream.addEventListener("candidate", (e) => {
    const c = JSON.parse(e.data);
    evoState = c;
    if (["new", "improved"].includes(c.outcome)) evoCells[`${c.risk}|${c.style}`] = c;
    evoCov.push(c.coverage);
    $("ev-stats").innerHTML = evoStatsBlock(c);
    drawGrid(); drawSpark();
    const log = $("ev-log");
    const line = document.createElement("div");
    line.innerHTML = `<b>${MARK[c.outcome]}</b> ${esc(c.risk)} · ${esc(evoGrid.style_titles[c.style] || c.style)} ` +
      `— ${c.verdict === "VULNERABLE" ? "пробой" : c.outcome === "duplicate" ? "дубликат" : "нет пробоя"} (f=${c.fitness})`;
    log.prepend(line);
  });
  evoStream.addEventListener("done", (e) => { evoState = JSON.parse(e.data); stopEvo(); });
  evoStream.onerror = () => stopEvo();
}

function stopEvo() {
  if (evoStream) evoStream.close();
  evoStream = null;
  $("ev-run").disabled = false; $("ev-stop").hidden = true;
}

const q0 = (k) => new URLSearchParams(location.search).get(k);

/* ── переключение видов ───────────────────────── */
function switchView(v) {
  document.querySelectorAll(".view-tab").forEach((b) => b.classList.toggle("on", b.dataset.view === v));
  $("dash").hidden = v !== "dash";
  $("work").hidden = v !== "find";
  $("evo").hidden = v !== "evo";
  if (v === "dash") renderDash();
  if (v === "evo") renderEvo();
}
document.querySelectorAll(".view-tab").forEach((b) => (b.onclick = () => switchView(b.dataset.view)));

/* ── прогон ───────────────────────────────────── */
function updateCounts() {
  const done = rows.filter((r) => r.result);
  const by = (v) => done.filter((r) => r.result.verdict === v).length;
  $("s-total").textContent = rows.length;
  $("s-vuln").textContent = by("VULNERABLE");
  $("s-safe").textContent = by("SAFE");
  $("s-na").textContent = by("INCONCLUSIVE");
  $("prog").style.width = `${Math.round((done.length / rows.length) * 100)}%`;
}

async function checkHealth() {
  const url = $("url").value.trim();
  $("led").className = "led"; $("ledtext").textContent = "проверка…";
  try {
    const r = await (await fetch(`/api/health?url=${encodeURIComponent(url)}`)).json();
    $("led").className = `led ${r.alive ? "on" : "off"}`;
    $("ledtext").textContent = r.alive ? "цель отвечает" : "цель недоступна";
  } catch {
    $("led").className = "led off"; $("ledtext").textContent = "ошибка проверки";
  }
}

function startScan() {
  if (stream) return;
  const url = $("url").value.trim();
  const model = $("model").value.trim();

  rows.forEach((r) => (r.result = null));
  summary = null; startedAt = Date.now();
  renderRows(); updateCounts();
  if (!$("dash").hidden) renderDash();
  $("score").textContent = "…";
  $("run").disabled = true; $("stop").hidden = false;
  $("led").className = "led busy"; $("ledtext").textContent = "сканирование";

  const cats = filters.category.size ? [...filters.category] : [];
  const qs = new URLSearchParams({ url, model });
  cats.forEach((c) => qs.append("category", c));

  stream = new EventSource(`/api/scan?${qs}`);

  stream.addEventListener("result", (e) => {
    const r = JSON.parse(e.data);
    const row = rows.find((x) => x.probe.id === r.probe_id);
    if (row) row.result = r;
    renderRows(); updateCounts();
    $("s-time").textContent = `${((Date.now() - startedAt) / 1000).toFixed(1)}s`;
    if (!$("dash").hidden) renderDash();
  });

  stream.addEventListener("done", (e) => {
    summary = JSON.parse(e.data);
    $("score").textContent = `${summary.vulnerable}/${summary.total}`;
    $("score").style.color = summary.vulnerable ? "var(--hit)" : "var(--dim)";
    stopScan();
    renderDash();
  });

  stream.onerror = () => stopScan();
}

function stopScan() {
  if (stream) stream.close();
  stream = null;
  $("run").disabled = false; $("stop").hidden = true;
  checkHealth();
}

/* ── клавиатура ───────────────────────────────── */
document.addEventListener("keydown", (e) => {
  if (e.target.matches("input")) return;
  const list = visible();
  const i = list.findIndex((r) => r.probe.id === selected);
  if (e.key === "j" && i < list.length - 1) select(list[i + 1].probe.id);
  else if (e.key === "k" && i > 0) select(list[i - 1].probe.id);
  else if (e.key === "j" && i === -1 && list.length) select(list[0].probe.id);
  else if (["1", "2", "3", "4"].includes(e.key) && selected) {
    activeTab = ["req", "res", "det", "fix"][+e.key - 1];
    select(selected);
  } else if (e.key === "r" && !stream) startScan();
  else if (e.key === "Escape") renderSummary();
});

/* ── разделитель панелей ──────────────────────── */
(() => {
  const left = document.querySelector(".left");
  const sp = $("splitter");
  try {
    const w = localStorage.getItem("amber-split");
    if (w) left.style.width = `${w}px`;
  } catch {}
  let dragging = false;
  sp.addEventListener("mousedown", (e) => {
    dragging = true; sp.classList.add("drag");
    document.body.style.userSelect = "none"; e.preventDefault();
  });
  window.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    const w = Math.max(380, Math.min(e.clientX, window.innerWidth * 0.7));
    left.style.width = `${w}px`;
  });
  window.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false; sp.classList.remove("drag");
    document.body.style.userSelect = "";
    try { localStorage.setItem("amber-split", parseInt(left.style.width, 10)); } catch {}
  });
})();

$("run").onclick = startScan;
$("stop").onclick = stopScan;
$("url").onchange = checkHealth;

/* ── старт ────────────────────────────────────── */
const q = new URLSearchParams(location.search);
if (q.get("url")) $("url").value = q.get("url");
if (q.get("model")) $("model").value = q.get("model");
Promise.all([loadCatalog(), loadGrid()]).then(() => {
  renderDash();
  checkHealth();
  const view = q.get("view");
  if (view === "evo") { switchView("evo"); if (q.get("run") === "1") startEvo(); }
  else if (view === "find") switchView("find");
  else if (q.get("run") === "1") startScan();
});
