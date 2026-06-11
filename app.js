// ════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════

const AUTH_USERS_KEY = "mb:auth:users";
const SESSION_KEY    = "mb:session";
const LAST_USER_KEY  = "mb:last-user";

function loadUsers() {
  try { return JSON.parse(localStorage.getItem(AUTH_USERS_KEY)) || {}; }
  catch { return {}; }
}
function hashPassLegacy(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
  return h.toString(36);
}
async function hashPass(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 200000 },
    key, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
}
async function tryLogin(username, password) {
  const u = loadUsers()[username.toLowerCase()];
  if (!u) return false;
  if (u.salt) return u.pass === await hashPass(password, u.salt);
  if (u.pass !== hashPassLegacy(password)) return false;
  const salt = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join("");
  const users = loadUsers();
  users[username.toLowerCase()].pass = await hashPass(password, salt);
  users[username.toLowerCase()].salt = salt;
  localStorage.setItem(AUTH_USERS_KEY, JSON.stringify(users));
  return true;
}
async function createAccount(username, password) {
  const users = loadUsers(), key = username.toLowerCase();
  if (users[key]) return "Ya existe.";
  const salt = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join("");
  const pass = await hashPass(password, salt);
  users[key] = { displayName: username, pass, salt };
  localStorage.setItem(AUTH_USERS_KEY, JSON.stringify(users));
  return null;
}
function getSession() {
  try {
    const s = JSON.parse(localStorage.getItem(SESSION_KEY));
    if (!s || !loadUsers()[s.user]) return null;
    const expiry = new Date(s.created || s.date);
    expiry.setDate(expiry.getDate() + 30);
    if (new Date() > expiry) return null;
    return s.user;
  } catch { return null; }
}
function saveSession(user) {
  localStorage.setItem(SESSION_KEY, JSON.stringify({ user: user.toLowerCase(), created: new Date().toISOString() }));
  localStorage.setItem(LAST_USER_KEY, user.toLowerCase());
}
function clearSession() { localStorage.removeItem(SESSION_KEY); }
function getLastUser()  { const u = localStorage.getItem(LAST_USER_KEY); return u && loadUsers()[u] ? u : null; }

// ── Passkeys (Face ID) ────────────────────────────────────
function passkeyKey(u) { return `mb:${u}:passkey-id`; }
function hasPasskey(u)  { return !!localStorage.getItem(passkeyKey(u)); }
function removePasskey(u){ localStorage.removeItem(passkeyKey(u)); }
function savePasskeyId(u, rawId) {
  localStorage.setItem(passkeyKey(u), btoa(String.fromCharCode(...new Uint8Array(rawId))));
}
function loadPasskeyId(u) {
  const b = localStorage.getItem(passkeyKey(u));
  return b ? Uint8Array.from(atob(b), c => c.charCodeAt(0)).buffer : null;
}
function isBioSupported() { return !!(window.PublicKeyCredential && navigator.credentials); }
async function isPlatformAvailable() {
  if (!isBioSupported()) return false;
  try { return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); }
  catch { return false; }
}
async function registerPasskey(username) {
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: "Gastos", id: location.hostname },
    user: { id: Uint8Array.from(username, c => c.charCodeAt(0)), name: username, displayName: username },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "preferred" },
    timeout: 60000,
  }});
  savePasskeyId(username, cred.rawId);
  return true;
}
async function verifyPasskey(username) {
  const credId = loadPasskeyId(username);
  if (!credId) throw new Error("Sin passkey");
  const assertion = await navigator.credentials.get({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: location.hostname,
    allowCredentials: [{ id: credId, type: "public-key" }],
    userVerification: "required", timeout: 60000,
  }});
  return assertion !== null;
}

// ════════════════════════════════════════════════════════════
// SUPABASE SYNC
// ════════════════════════════════════════════════════════════

const SUPA_CREDS_KEY = "mb:supabase:creds";
const LAST_SYNC_KEY = "mb:supabase:last-sync";

function getBundledSupaCreds() {
  const cfg = window.GASTOS_SUPABASE_CONFIG || {};
  const url = (cfg.url || "").trim().replace(/\/$/, "");
  const key = (cfg.anonKey || cfg.key || "").trim();
  const table = cleanTableName(cfg.table || "sync_data");
  return url && key && table ? { url, key, table, bundled: true } : null;
}
function getSupaCreds() {
  try {
    const bundled = getBundledSupaCreds();
    if (bundled) return bundled;
    const creds = JSON.parse(localStorage.getItem(SUPA_CREDS_KEY)) || {};
    return { ...creds, table: creds.table || "sync_data" };
  }
  catch { return getBundledSupaCreds() || {}; }
}
function cleanTableName(table) {
  const value = (table || "sync_data").trim();
  return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value) ? value : "";
}
function saveSupaCreds(url, key, table) {
  const tableName = cleanTableName(table);
  if (!tableName) throw new Error("El nombre de tabla solo puede usar letras, números y guion bajo.");
  localStorage.setItem(SUPA_CREDS_KEY, JSON.stringify({
    url: url.trim().replace(/\/$/, ""),
    key: key.trim(),
    table: tableName,
  }));
}
function supaConfigured() { const { url, key, table } = getSupaCreds(); return !!(url && key && table); }
function supaHeaders() {
  const { key } = getSupaCreds();
  return { "Content-Type": "application/json", "apikey": key, "Authorization": `Bearer ${key}` };
}
function syncKeys() {
  return [KEY.expenses, KEY.income, KEY.budgets, KEY.recurring, KEY.settings, KEY.loans, KEY.accounts, KEY.goals];
}
function saveLastSync() {
  localStorage.setItem(LAST_SYNC_KEY, new Date().toISOString());
  renderLastSync();
}
function renderLastSync() {
  const el = document.getElementById("lastSyncLabel");
  if (!el) return;
  const last = localStorage.getItem(LAST_SYNC_KEY);
  if (!last) {
    el.textContent = "Todavia no se sincronizo en este dispositivo.";
    return;
  }
  el.textContent = "Ultima sincronizacion: " + new Date(last).toLocaleString("es");
}
function supaTableSql(table) {
  const tableName = cleanTableName(table) || "sync_data";
  return `-- AVISO DE SEGURIDAD: La anon key de Supabase es pública. Cualquiera
-- que la tenga puede leer y escribir esta tabla. Para uso privado,
-- usa un proyecto de Supabase exclusivo o migrá a Supabase Auth.

create table if not exists public.${tableName} (
  user_key text primary key,
  data jsonb not null,
  synced_at timestamptz not null default now()
);

alter table public.${tableName} enable row level security;

drop policy if exists "allow anon sync" on public.${tableName};
create policy "allow anon sync"
on public.${tableName}
for all
to anon
using (true)
with check (true);`;
}
function renderSupabaseSql() {
  const sqlEl = document.getElementById("supabaseSql");
  const tableEl = document.getElementById("supabaseTable");
  if (!sqlEl || !tableEl) return;
  sqlEl.value = supaTableSql(tableEl.value);
}

async function syncUpload() {
  if (!supaConfigured()) throw new Error("Configura Supabase primero.");
  const { url, table } = getSupaCreds();
  const rows = syncKeys()
    .map(k => ({ user_key: k, data: load(k, null), synced_at: new Date().toISOString() }))
    .filter(r => r.data !== null);
  if (!rows.length) throw new Error("No hay datos locales para subir.");
  const res = await fetch(`${url}/rest/v1/${table}?on_conflict=user_key`, {
    method: "POST",
    headers: { ...supaHeaders(), "Prefer": "resolution=merge-duplicates" },
    body: JSON.stringify(rows),
  });
  if (!res.ok) throw new Error(`Error ${res.status}: ${await res.text()}`);
  saveLastSync();
}

async function syncDownload() {
  if (!supaConfigured()) throw new Error("Configurá la URL y clave primero.");
  const { url, table } = getSupaCreds();
  const keys = syncKeys();
  const keyFilter = keys.map(k => `"${k}"`).join(",");
  const res  = await fetch(`${url}/rest/v1/${table}?user_key=in.(${encodeURIComponent(keyFilter)})`, {
    headers: supaHeaders(),
  });
  if (!res.ok) throw new Error(`Error ${res.status}: ${await res.text()}`);
  const rows = await res.json();
  if (!rows.length) throw new Error("Sin datos remotos para este usuario.");
  rows.forEach(r => localStorage.setItem(r.user_key, JSON.stringify(r.data)));
  expenses  = load(KEY.expenses,  []);
  income    = load(KEY.income,    []);
  budgets   = load(KEY.budgets,   {});
  recurring = load(KEY.recurring, []);
  settings  = load(KEY.settings,  { currency: "BOB", locale: "es-BO" });
  loans     = load(KEY.loans,     []);
  accounts  = load(KEY.accounts,  []);
  goals     = load(KEY.goals,     []);
  renderAll();
  saveLastSync();
}

let _syncTimer = null;
let _cloudPullTimer = null;
let _syncing = false;
function autoSync() {
  clearTimeout(_syncTimer);
  _syncTimer = setTimeout(async () => {
    try { await syncUpload(); } catch { /* silent */ }
  }, 2000);
}
async function syncOnStart() {
  try { await syncDownload(); }
  catch (e) { if (!e.message.includes("Sin datos")) console.warn("Sync:", e.message); }
}
async function pullCloudChanges() {
  if (_syncing || !currentUser || !supaConfigured() || document.hidden) return;
  _syncing = true;
  try { await syncDownload(); }
  catch { /* silent */ }
  finally { _syncing = false; }
}
function startCloudPolling() {
  clearInterval(_cloudPullTimer);
  if (!supaConfigured()) return;
  _cloudPullTimer = setInterval(pullCloudChanges, 15000);
}
function getSetupUrl() {
  const { url, key, table } = getSupaCreds();
  if (!url || !key) return null;
  const encoded = btoa(JSON.stringify({ url, key, table: table || "sync_data" }));
  return `${location.origin}${location.pathname}?setup=${encoded}`;
}
function applySetupFromUrl() {
  const setup = new URLSearchParams(location.search).get("setup");
  if (!setup) return;
  try {
    const { url, key, table } = JSON.parse(atob(setup));
    if (url && key) { saveSupaCreds(url, key, table || "sync_data"); history.replaceState(null, "", location.pathname); }
  } catch { /* param inválido */ }
}

// ════════════════════════════════════════════════════════════
// DATA MODEL
// ════════════════════════════════════════════════════════════

const EXP_CATS = [
  { id: "Alquiler",      icon: "🏠" },
  { id: "Supermercado",  icon: "🛒" },
  { id: "Comida",        icon: "🍔" },
  { id: "Transporte",    icon: "🚌" },
  { id: "Universidad",   icon: "📚" },
  { id: "Servicios",     icon: "⚡" },
  { id: "Ocio",          icon: "🎉" },
  { id: "Salud",         icon: "💊" },
  { id: "Ropa",          icon: "👕" },
  { id: "Suscripciones", icon: "📱" },
  { id: "Otro",          icon: "📦" },
];
const INC_CATS = [
  { id: "Familiar",  icon: "💰" },
  { id: "Trabajo",   icon: "💼" },
  { id: "Beca",      icon: "🎓" },
  { id: "Freelance", icon: "💻" },
  { id: "Otro",      icon: "➕" },
];

let currentUser = "";
const KEY = {
  get expenses()  { return `mb:${currentUser}:expenses:v1`;  },
  get income()    { return `mb:${currentUser}:income:v1`;    },
  get budgets()   { return `mb:${currentUser}:budgets:v1`;   },
  get recurring() { return `mb:${currentUser}:recurring:v1`; },
  get settings()  { return `mb:${currentUser}:settings:v1`;  },
  get loans()     { return `mb:${currentUser}:loans:v1`;     },
  get accounts()  { return `mb:${currentUser}:accounts:v1`;  },
  get goals()     { return `mb:${currentUser}:goals:v1`;     },
};

let expenses  = [], income = [], budgets = {}, recurring = [], settings = {}, loans = [], accounts = [], goals = [];
let currentMonth = "";
let selectedExpCat = "Comida";
let selectedIncCat = "Familiar";
let addType = "expense";
let paymentModalLoanId = null;
let editingTxId   = null;
let editingTxType = null;

// ════════════════════════════════════════════════════════════
// UTILS
// ════════════════════════════════════════════════════════════

function load(key, def)      { try { return JSON.parse(localStorage.getItem(key)) ?? def; } catch { return def; } }
function persist(key, data)  { localStorage.setItem(key, JSON.stringify(data)); }
function todayIso()          { return new Date().toISOString().slice(0, 10); }
function sum(arr)            { return arr.reduce((t, x) => t + Number(x.amount), 0); }

function fmt(n) {
  return new Intl.NumberFormat(settings.locale || "es-BO", {
    style: "currency", currency: settings.currency || "BOB", maximumFractionDigits: 2,
  }).format(n);
}
function fmtDate(str) {
  const [y, m, d] = str.split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString("es", { day: "numeric", month: "short" });
}
function catIcon(id) {
  return (EXP_CATS.find(c => c.id === id) || INC_CATS.find(c => c.id === id) || { icon: "📦" }).icon;
}
function monthLabel(ym) {
  const [y, m] = ym.split("-").map(Number);
  const s = new Date(y, m - 1, 1).toLocaleDateString("es", { month: "long", year: "numeric" });
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function esc(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
function loanPending(l) {
  return Math.max(0, Number(l.amount) - l.repayments.reduce((t, r) => t + Number(r.amount), 0));
}
function getCurrencySymbol() {
  return { BOB:"Bs", ARS:"$", USD:"US$", CLP:"$", PEN:"S/", MXN:"$", COP:"$", UYU:"$", PYG:"₲" }[settings.currency || "BOB"] || "$";
}

// ════════════════════════════════════════════════════════════
// RENDER
// ════════════════════════════════════════════════════════════

function renderAll() {
  const mExp = expenses.filter(e => e.date.startsWith(currentMonth));
  const mInc = income.filter(i => i.date.startsWith(currentMonth));
  const totalExp = sum(mExp), totalInc = sum(mInc), balance = totalInc - totalExp;
  const daysSpent = new Set(mExp.map(e => e.date)).size || 1;
  const savPct = totalInc > 0 ? Math.max(0, Math.min(100, (balance / totalInc) * 100)) : 0;

  const balEl = document.getElementById("balanceAmt");
  balEl.textContent = fmt(balance);
  balEl.style.color = balance >= 0 ? "#86efac" : "#fca5a5";
  document.getElementById("incomeAmt").textContent  = fmt(totalInc);
  document.getElementById("expenseAmt").textContent = fmt(totalExp);
  document.getElementById("todayAmt").textContent   = fmt(sum(expenses.filter(e => e.date === todayIso())));
  document.getElementById("avgAmt").textContent     = fmt(totalExp / daysSpent);

  const savSec = document.getElementById("savingsSection");
  savSec.hidden = totalInc === 0;
  if (totalInc > 0) {
    document.getElementById("savingsPct").textContent = Math.round(savPct) + "%";
    const fill = document.getElementById("savingsFill");
    fill.style.width = savPct + "%";
    fill.style.background = savPct >= 20 ? "#86efac" : savPct >= 10 ? "#fcd34d" : "#fca5a5";
  }

  renderBudgets(mExp);
  renderDonut(mExp);
  renderMonthlyGoal(balance);
  renderTxList();
  renderLoans();
  renderTrends();
  renderNetWorth();
  renderGoals();
  renderBudgetAlerts(mExp);
  document.getElementById("addCurrSymbol").textContent = getCurrencySymbol();
}

function renderBudgets(mExp) {
  const panel = document.getElementById("budgetPanel");
  const container = document.getElementById("budgetBars");
  container.innerHTML = "";
  const rows = EXP_CATS.map(c => ({
    ...c,
    spent: sum(mExp.filter(e => e.category === c.id)),
    limit: Number(budgets[c.id] || 0),
  })).filter(r => r.spent > 0 || r.limit > 0).sort((a, b) => b.spent - a.spent);
  panel.hidden = rows.length === 0;
  rows.forEach(r => {
    const pct = r.limit > 0 ? Math.min((r.spent / r.limit) * 100, 100) : 0;
    const over = r.limit > 0 && r.spent > r.limit;
    const warn = r.limit > 0 && pct >= 80 && !over;
    const div = document.createElement("div");
    div.className = "budget-row";
    div.innerHTML = `
      <div class="budget-label">
        <span class="cat-left">${r.icon} ${r.id}</span>
        <span class="cat-right ${over ? "over" : ""}">${fmt(r.spent)}${r.limit > 0 ? " / " + fmt(r.limit) : ""}</span>
      </div>
      ${r.limit > 0 ? `<div class="budget-track"><div class="budget-fill ${over ? "over" : warn ? "warn" : ""}" style="width:${pct}%"></div></div>` : ""}`;
    container.append(div);
  });
}

function renderBudgetAlerts(mExp) {
  const banner = document.getElementById("budgetAlertBanner");
  if (!banner) return;
  const alerts = EXP_CATS.map(c => ({
    ...c,
    spent: sum(mExp.filter(e => e.category === c.id)),
    limit: Number(budgets[c.id] || 0),
  })).filter(r => r.limit > 0 && r.spent >= r.limit * 0.8);
  banner.hidden = alerts.length === 0;
  if (!alerts.length) return;
  const over = alerts.filter(a => a.spent > a.limit);
  const warn = alerts.filter(a => a.spent <= a.limit);
  let msgs = [];
  if (over.length) msgs.push(`${over.map(a => a.icon + " " + a.id).join(", ")}: excediste el presupuesto`);
  if (warn.length) msgs.push(`${warn.map(a => a.icon + " " + a.id).join(", ")}: cerca del límite`);
  banner.innerHTML = `<span class="alert-icon">${over.length ? "🚨" : "⚠️"}</span><span>${msgs.join(" · ")}</span>`;
  banner.className = "budget-alert-banner" + (over.length ? " over" : " warn");
}

const DONUT_COLORS = ["#be185d","#7c3aed","#ea580c","#d97706","#059669","#0891b2","#c026d3"];

function renderDonut(mExp) {
  const section = document.getElementById("donutSection");
  const total   = sum(mExp);
  section.hidden = false;
  document.getElementById("donutMonth").textContent = monthLabel(currentMonth);

  const svg = document.getElementById("donutSvg");
  svg.querySelectorAll(".donut-seg").forEach(el => el.remove());

  if (total === 0) {
    document.getElementById("donutMainPct").textContent = "—";
    document.getElementById("donutMainCat").textContent = "";
    document.getElementById("donutLegend").innerHTML = '<li class="donut-leg-empty">Sin gastos este mes</li>';
    return;
  }

  const byCat = {};
  mExp.forEach(e => { byCat[e.category] = (byCat[e.category] || 0) + Number(e.amount); });
  const segs = Object.entries(byCat)
    .map(([cat, amt]) => ({ cat, amt, pct: (amt / total) * 100 }))
    .sort((a, b) => b.amt - a.amt).slice(0, 7);

  const r = 45, circ = 2 * Math.PI * r;
  let accum = 0;
  segs.forEach((seg, i) => {
    const dash = (seg.pct / 100) * circ;
    const el   = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    el.setAttribute("class", "donut-seg");
    el.setAttribute("cx", "60"); el.setAttribute("cy", "60"); el.setAttribute("r", String(r));
    el.setAttribute("fill", "none");
    el.setAttribute("stroke", DONUT_COLORS[i % DONUT_COLORS.length]);
    el.setAttribute("stroke-width", "14");
    el.setAttribute("stroke-linecap", "round");
    el.setAttribute("stroke-dasharray", `${dash - 2} ${circ - dash + 2}`);
    el.setAttribute("stroke-dashoffset", String(-accum));
    el.setAttribute("transform", "rotate(-90 60 60)");
    svg.appendChild(el);
    accum += dash;
  });

  const top = segs[0];
  document.getElementById("donutMainPct").textContent = Math.round(top.pct) + "%";
  document.getElementById("donutMainCat").textContent = top.cat;
  document.getElementById("donutLegend").innerHTML = segs.map((s, i) => `
    <li class="donut-leg-item">
      <span class="donut-leg-dot" style="background:${DONUT_COLORS[i % DONUT_COLORS.length]}"></span>
      <span class="donut-leg-name">${esc(s.cat)}</span>
      <span class="donut-leg-pct">${Math.round(s.pct)}%</span>
    </li>`).join("");
}

function renderMonthlyGoal(balance) {
  const goal    = Number(settings.monthlyGoal || 0);
  const section = document.getElementById("goalSection");
  if (!goal) { section.hidden = true; return; }
  section.hidden = false;
  const saved = Math.max(0, balance);
  const pct   = Math.min(100, Math.max(0, (saved / goal) * 100));
  document.getElementById("goalPct").textContent    = Math.round(pct) + "%";
  document.getElementById("goalSaved").textContent  = fmt(saved) + " ahorrado";
  document.getElementById("goalTarget").textContent = "Meta: " + fmt(goal);
  const fill = document.getElementById("goalFill");
  fill.style.width      = pct + "%";
  fill.style.background = pct >= 100 ? "var(--income)" : pct >= 50 ? "#fcd34d" : "var(--primary)";
}

// ── Tendencias mensuales ──────────────────────────────────

function renderTrends() {
  const svg = document.getElementById("trendsSvg");
  if (!svg) return;
  const [cy, cm] = currentMonth.split("-").map(Number);
  const months = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date(cy, cm - 1 - i, 1);
    months.push(d.toISOString().slice(0, 7));
  }
  const data = months.map(m => ({
    label: new Date(m + "-01").toLocaleDateString("es", { month: "short" }),
    inc: sum(income.filter(i => i.date.startsWith(m))),
    exp: sum(expenses.filter(e => e.date.startsWith(m))),
  }));
  const maxVal = Math.max(...data.flatMap(d => [d.inc, d.exp]), 1);
  const W = 500, H = 120, padL = 4, padR = 4, padT = 10, padB = 24;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;
  const groupW = chartW / 6;
  const barW = Math.max(groupW * 0.3, 8);
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  let html = `<line x1="${padL}" y1="${padT + chartH}" x2="${W - padR}" y2="${padT + chartH}" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>`;
  data.forEach((d, i) => {
    const cx = padL + i * groupW + groupW / 2;
    const incX = cx - barW - 1;
    const expX = cx + 1;
    const incH = maxVal > 0 ? Math.max((d.inc / maxVal) * chartH, d.inc > 0 ? 3 : 0) : 0;
    const expH = maxVal > 0 ? Math.max((d.exp / maxVal) * chartH, d.exp > 0 ? 3 : 0) : 0;
    html += `<rect x="${incX.toFixed(1)}" y="${(padT + chartH - incH).toFixed(1)}" width="${barW.toFixed(1)}" height="${incH.toFixed(1)}" rx="2" fill="rgba(134,239,172,0.65)"/>`;
    html += `<rect x="${expX.toFixed(1)}" y="${(padT + chartH - expH).toFixed(1)}" width="${barW.toFixed(1)}" height="${expH.toFixed(1)}" rx="2" fill="rgba(252,165,165,0.65)"/>`;
    html += `<text x="${cx.toFixed(1)}" y="${H - 6}" text-anchor="middle" font-size="9" fill="rgba(255,255,255,0.38)">${d.label}</text>`;
  });
  svg.innerHTML = html;
}

// ── Patrimonio neto ───────────────────────────────────────

function renderNetWorth() {
  const section = document.getElementById("networthSection");
  if (!section) return;
  section.hidden = accounts.length === 0;
  if (!accounts.length) return;
  const assets      = accounts.filter(a => a.type === "asset").reduce((t, a) => t + Number(a.balance), 0);
  const liabilities = accounts.filter(a => a.type === "liability").reduce((t, a) => t + Number(a.balance), 0);
  const net = assets - liabilities;
  document.getElementById("nwAssets").textContent = fmt(assets);
  document.getElementById("nwLiabilities").textContent = fmt(liabilities);
  const nwEl = document.getElementById("nwTotal");
  nwEl.textContent = fmt(net);
  nwEl.style.color = net >= 0 ? "var(--income)" : "var(--expense)";
  const list = document.getElementById("accountsList");
  list.innerHTML = "";
  accounts.forEach(acc => {
    const isLia = acc.type === "liability";
    const div = document.createElement("div");
    div.className = "account-item";
    div.innerHTML = `
      <span class="acc-icon">${esc(acc.icon || (isLia ? "💳" : "🏦"))}</span>
      <span class="acc-name">${esc(acc.name)}</span>
      <span class="acc-bal ${isLia ? "expense" : "income"}">${isLia ? "−" : ""}${fmt(acc.balance)}</span>
      <button class="acc-del" type="button" title="Eliminar">✕</button>`;
    div.querySelector(".acc-del").addEventListener("click", () => {
      accounts = accounts.filter(a => a.id !== acc.id);
      persist(KEY.accounts, accounts);
      renderNetWorth(); autoSync();
    });
    list.append(div);
  });
}

// ── Metas múltiples ───────────────────────────────────────

function renderGoals() {
  const section = document.getElementById("goalsSection");
  if (!section) return;
  section.hidden = goals.length === 0;
  const list = document.getElementById("goalsList");
  list.innerHTML = "";
  goals.forEach(goal => {
    const saved = goal.saved || 0;
    const pct = goal.amount > 0 ? Math.min(100, (saved / goal.amount) * 100) : 0;
    const color = goal.color || "var(--primary)";
    const div = document.createElement("div");
    div.className = "goal-item";
    div.innerHTML = `
      <div class="goal-header">
        <div style="display:flex;align-items:center;gap:8px">
          <span class="goal-dot" style="background:${color}"></span>
          <span class="goal-name">${esc(goal.name)}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:0.78rem;color:var(--muted)">${Math.round(pct)}%</span>
          <button class="goal-del" type="button">✕</button>
        </div>
      </div>
      <div class="goal-amounts">
        <span>${fmt(saved)} ahorrado</span>
        <span>Meta: ${fmt(goal.amount)}</span>
      </div>
      <div class="goal-track"><div class="goal-fill" style="width:${pct}%;background:${color}"></div></div>
      <div class="goal-add-row">
        <input type="number" inputmode="decimal" min="0.01" step="0.01" class="goal-add-input field" placeholder="Agregar monto">
        <button class="btn-sm-pink goal-add-btn" type="button">+ Ahorro</button>
      </div>`;
    div.querySelector(".goal-del").addEventListener("click", () => {
      goals = goals.filter(g => g.id !== goal.id);
      persist(KEY.goals, goals); renderGoals(); autoSync();
    });
    div.querySelector(".goal-add-btn").addEventListener("click", () => {
      const inp = div.querySelector(".goal-add-input");
      const amount = Number(inp.value);
      if (!amount || amount <= 0) return;
      const idx = goals.findIndex(g => g.id === goal.id);
      if (idx !== -1) goals[idx].saved = (goals[idx].saved || 0) + amount;
      persist(KEY.goals, goals); inp.value = ""; renderGoals(); autoSync();
    });
    list.append(div);
  });
}

function renderTxList() {
  const fromVal   = document.getElementById("rangeFrom")?.value;
  const toVal     = document.getElementById("rangeTo")?.value;
  const filter    = document.getElementById("catFilter").value;
  const searchVal = (document.getElementById("txSearch")?.value || "").toLowerCase().trim();
  const list      = document.getElementById("txList");
  const empty     = document.getElementById("emptyMsg");
  const tpl       = document.getElementById("txTpl");

  const srcExp = fromVal && toVal
    ? expenses.filter(e => e.date >= fromVal && e.date <= toVal)
    : expenses.filter(e => e.date.startsWith(currentMonth));
  const srcInc = fromVal && toVal
    ? income.filter(i => i.date >= fromVal && i.date <= toVal)
    : income.filter(i => i.date.startsWith(currentMonth));

  const totalInc = sum(srcInc), totalExp = sum(srcExp), bal = totalInc - totalExp;
  const incEl = document.getElementById("rangeInc");
  const expEl = document.getElementById("rangeExp");
  const balEl = document.getElementById("rangeBal");
  if (incEl) incEl.textContent = fmt(totalInc);
  if (expEl) expEl.textContent = fmt(totalExp);
  if (balEl) {
    balEl.textContent = fmt(bal);
    balEl.style.color = bal >= 0 ? "var(--income)" : "var(--expense)";
  }

  const all = [
    ...srcExp.map(e => ({ ...e, type: "expense" })),
    ...srcInc.map(i => ({ ...i, type: "income" })),
  ].filter(tx => {
    if (filter === "all")     return true;
    if (filter === "_income") return tx.type === "income";
    return tx.category === filter;
  }).filter(tx => {
    if (!searchVal) return true;
    return (tx.note || "").toLowerCase().includes(searchVal) ||
           tx.category.toLowerCase().includes(searchVal) ||
           String(tx.amount).includes(searchVal);
  }).sort((a, b) => b.date.localeCompare(a.date) || b.createdAt - a.createdAt);

  list.innerHTML = "";
  empty.hidden = all.length > 0;

  all.forEach(tx => {
    const node = tpl.content.cloneNode(true);
    const icon = node.querySelector(".tx-icon");
    icon.textContent = catIcon(tx.category);
    if (tx.type === "income") icon.classList.add("income");
    node.querySelector(".tx-note").textContent = tx.note || tx.category;
    node.querySelector(".tx-meta").textContent = `${tx.category} · ${fmtDate(tx.date)}`;
    const amt = node.querySelector(".tx-amt");
    amt.textContent = (tx.type === "expense" ? "−" : "+") + fmt(tx.amount);
    amt.classList.add(tx.type);
    node.querySelector(".tx-edit").addEventListener("click", () => openEditTx(tx));
    node.querySelector(".tx-del").addEventListener("click", () => {
      if (tx.type === "expense") { expenses = expenses.filter(e => e.id !== tx.id); persist(KEY.expenses, expenses); }
      else                       { income   = income.filter(i => i.id !== tx.id);   persist(KEY.income, income); }
      renderAll(); autoSync();
    });
    list.append(node);
  });
}

function renderQuickItems() {
  const container = document.getElementById("quickItems");
  container.innerHTML = "";
  if (recurring.length === 0) {
    container.innerHTML = '<p style="color:var(--muted);font-size:.85rem;padding:20px 0;text-align:center">No hay gastos fijos. Configuralos en ⚙ para verlos acá.</p>';
    return;
  }
  const today = new Date().getDate();
  recurring.forEach(rec => {
    const sid   = `rec:${rec.id}:${currentMonth}`;
    const added = expenses.some(e => e.sourceId === sid);
    const dueDay = rec.dueDay ? Number(rec.dueDay) : null;
    let dueBadge = "";
    if (rec.paused) {
      dueBadge = `<span class="sub-badge paused">⏸ Pausado</span>`;
    } else if (dueDay) {
      const diff = dueDay - today;
      if (diff < 0 && !added) dueBadge = `<span class="sub-badge due">⚠ Venció día ${dueDay}</span>`;
      else if (diff >= 0 && diff <= 3) dueBadge = `<span class="sub-badge soon">🔔 Vence día ${dueDay}</span>`;
      else dueBadge = `<span class="sub-badge ok">· día ${dueDay}</span>`;
    }
    const div = document.createElement("div");
    div.className = "quick-item" + (added ? " done" : "") + (rec.paused ? " paused-item" : "");
    div.innerHTML = `
      <div class="qi-left">
        <span class="qi-icon">${catIcon(rec.category)}</span>
        <div>
          <div class="qi-name">${esc(rec.name)}</div>
          <div class="qi-cat">${rec.category}${added ? " · ✓ Ya registrado" : ""}${dueBadge}</div>
        </div>
      </div>
      <span class="qi-amt">${fmt(rec.amount)}</span>`;
    if (!added && !rec.paused) {
      div.addEventListener("click", () => {
        expenses.push({ id: crypto.randomUUID(), amount: rec.amount, category: rec.category,
          date: currentMonth + "-01", note: rec.name, createdAt: Date.now(), sourceId: sid });
        persist(KEY.expenses, expenses);
        renderAll(); autoSync();
      });
    }
    container.append(div);
  });
}

function renderLoans() {
  const list   = document.getElementById("loanList");
  const empty  = document.getElementById("loansEmpty");
  const banner = document.getElementById("loansOverview");
  const active = loans.filter(l => !l.settled && loanPending(l) > 0);

  list.innerHTML = "";
  empty.hidden = active.length > 0;
  if (active.length === 0) { banner.hidden = true; return; }

  const total = active.reduce((t, l) => t + loanPending(l), 0);
  banner.hidden = false;
  document.getElementById("loansCountLabel").textContent =
    active.length === 1 ? "1 deuda activa" : `${active.length} deudas activas`;
  document.getElementById("loansTotalAmt").textContent = fmt(total) + " pendientes";

  active.forEach(loan => {
    const repaid  = loan.repayments.reduce((t, r) => t + Number(r.amount), 0);
    const pending = loanPending(loan);
    const pct     = Math.min((repaid / Number(loan.amount)) * 100, 100);
    const div = document.createElement("div");
    div.className = "loan-item";
    div.innerHTML = `
      <div class="loan-main">
        <div class="loan-avatar">${esc(loan.person.charAt(0))}</div>
        <div class="loan-info">
          <strong class="loan-person">${esc(loan.person)}</strong>
          <span class="loan-detail">Prestado ${fmt(loan.amount)} · ${fmtDate(loan.date)}${loan.note ? " · " + esc(loan.note) : ""}</span>
          ${repaid > 0 ? `<span class="loan-repaid">Pagó ${fmt(repaid)}</span>` : ""}
        </div>
        <div class="loan-badge"><b>${fmt(pending)}</b><span>pendiente</span></div>
      </div>
      <div class="loan-prog"><div class="loan-prog-fill" style="width:${pct}%"></div></div>
      <div class="loan-btns">
        <button class="btn-loan-pay"    type="button">💵 Recibí pago</button>
        <button class="btn-loan-settle" type="button">Saldado ✓</button>
        <button class="btn-loan-del"    type="button">✕</button>
      </div>`;

    div.querySelector(".btn-loan-pay").addEventListener("click",    () => openPaymentModal(loan));
    div.querySelector(".btn-loan-settle").addEventListener("click", () => {
      const i = loans.findIndex(l => l.id === loan.id);
      if (i !== -1) { loans[i].settled = true; persist(KEY.loans, loans); renderLoans(); autoSync(); }
    });
    div.querySelector(".btn-loan-del").addEventListener("click",   () => {
      if (!confirm(`¿Eliminar la deuda de ${loan.person}?`)) return;
      loans = loans.filter(l => l.id !== loan.id);
      persist(KEY.loans, loans); renderLoans(); autoSync();
    });
    list.append(div);
  });
}

function openPaymentModal(loan) {
  paymentModalLoanId = loan.id;
  document.getElementById("paymentModalTitle").textContent   = `${loan.person} te pagó`;
  document.getElementById("paymentPendingAmt").textContent   = fmt(loanPending(loan));
  document.getElementById("paymentAmount").value = "";
  document.getElementById("paymentDate").value   = todayIso();
  document.getElementById("paymentModal").hidden = false;
  setTimeout(() => document.getElementById("paymentAmount").focus(), 50);
}
function closePaymentModal() {
  document.getElementById("paymentModal").hidden = true;
  paymentModalLoanId = null;
}

// ════════════════════════════════════════════════════════════
// NAVIGATION
// ════════════════════════════════════════════════════════════

let currentView = "inicio";

function showView(name) {
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.getElementById("view-" + name).classList.add("active");
  document.querySelectorAll(".bnav-btn[data-view]").forEach(b => {
    b.classList.toggle("active", b.dataset.view === name);
  });
  currentView = name;
  if (name === "fijos") renderQuickItems();
}

function openAddModal() {
  setAddType("expense");
  document.getElementById("addAmount").value = "";
  document.getElementById("addNote").value   = "";
  document.getElementById("addDate").value   = todayIso();
  document.getElementById("addCurrSymbol").textContent = getCurrencySymbol();
  document.getElementById("addModal").hidden = false;
  setTimeout(() => document.getElementById("addAmount").focus(), 60);
}
function closeAddModal() {
  document.getElementById("addModal").hidden = true;
  editingTxId = null;
  editingTxType = null;
}

function openEditTx(tx) {
  editingTxId   = tx.id;
  editingTxType = tx.type;
  setAddType(tx.type === "expense" ? "expense" : "income");
  if (tx.type === "expense") selectedExpCat = tx.category;
  else                       selectedIncCat = tx.category;
  rebuildAddChips();
  document.getElementById("addAmount").value = tx.amount;
  document.getElementById("addNote").value   = tx.note || "";
  document.getElementById("addDate").value   = tx.date;
  document.getElementById("addCurrSymbol").textContent = getCurrencySymbol();
  document.getElementById("addSaveBtn").textContent    = "Guardar cambios";
  document.getElementById("addSaveBtn").className      = "btn-pink";
  document.getElementById("addModal").hidden = false;
  setTimeout(() => document.getElementById("addAmount").focus(), 60);
}

function setAddType(type) {
  addType = type;
  const isExp = type === "expense";
  document.getElementById("addTypeExpense").classList.toggle("active", isExp);
  document.getElementById("addTypeIncome").classList.toggle("active",  !isExp);
  if (!editingTxId) {
    document.getElementById("addSaveBtn").textContent = isExp ? "Guardar gasto" : "Guardar ingreso";
    document.getElementById("addSaveBtn").className   = isExp ? "btn-pink" : "btn-success";
  }
  rebuildAddChips();
}
function rebuildAddChips() {
  const isExp = addType === "expense";
  const cats  = isExp ? EXP_CATS : INC_CATS;
  const sel   = isExp ? selectedExpCat : selectedIncCat;
  buildChips("addChips", cats, sel, id => {
    if (addType === "expense") selectedExpCat = id; else selectedIncCat = id;
    rebuildAddChips();
  });
}

// ════════════════════════════════════════════════════════════
// CHIPS & FILTERS
// ════════════════════════════════════════════════════════════

function buildChips(containerId, cats, selected, onPick) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";
  cats.forEach(c => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "chip" + (c.id === selected ? " on" : "");
    btn.textContent = c.icon + " " + c.id;
    btn.addEventListener("click", () => onPick(c.id));
    container.append(btn);
  });
}

function buildCatFilter() {
  const sel = document.getElementById("catFilter");
  const prev = sel.value;
  sel.innerHTML = '<option value="all">Todos</option><option value="_income">Ingresos</option>';
  EXP_CATS.forEach(c => {
    const o = document.createElement("option");
    o.value = c.id; o.textContent = c.icon + " " + c.id;
    sel.append(o);
  });
  if ([...sel.options].some(o => o.value === prev)) sel.value = prev;
}

// ════════════════════════════════════════════════════════════
// SETTINGS
// ════════════════════════════════════════════════════════════

function openSettings() {
  document.getElementById("settingsUserSub").textContent = `@${currentUser}`;
  document.getElementById("currencySelect").value = settings.currency || "BOB";
  document.getElementById("monthlyGoalInput").value = settings.monthlyGoal || "";
  const { url, key, table } = getSupaCreds();
  document.getElementById("supabaseUrl").value = url || "";
  document.getElementById("supabaseKey").value = key || "";
  document.getElementById("supabaseTable").value = table || "sync_data";
  document.getElementById("syncActiveBadge").hidden = !supaConfigured();
  document.getElementById("shareSetupBtn").hidden   = !supaConfigured();
  document.getElementById("globalConfigBadge").hidden = !getBundledSupaCreds();
  document.getElementById("syncStatus").hidden = true;
  renderSupabaseSql();
  renderLastSync();
  buildBudgetInputs();
  buildRecurringList();
  buildAccountsSettingsList();
  buildGoalsSettingsList();
  const recCat = document.getElementById("recCategory");
  recCat.innerHTML = EXP_CATS.map(c => `<option value="${c.id}">${c.icon} ${c.id}</option>`).join("");
  isPlatformAvailable().then(avail => {
    const hint  = document.getElementById("biometricHint");
    const setup = document.getElementById("setupBiometricBtn");
    const rem   = document.getElementById("removeBiometricBtn");
    if (!avail) { hint.textContent = "Face ID no disponible en este dispositivo."; setup.hidden = rem.hidden = true; return; }
    if (hasPasskey(currentUser)) { hint.textContent = "Face ID configurado."; setup.hidden = true; rem.hidden = false; }
    else                         { hint.textContent = "Configurá Face ID para entrar sin contraseña."; setup.hidden = false; rem.hidden = true; }
  });
  document.getElementById("settingsModal").hidden = false;
}

function closeSettings() {
  document.querySelectorAll("#budgetInputs input[data-cat]").forEach(inp => {
    budgets[inp.dataset.cat] = Number(inp.value) || 0;
  });
  persist(KEY.budgets, budgets);
  const cur = document.getElementById("currencySelect").value;
  const localeMap = { BOB:"es-BO", ARS:"es-AR", USD:"en-US", CLP:"es-CL", PEN:"es-PE", MXN:"es-MX", COP:"es-CO", UYU:"es-UY", PYG:"es-PY" };
  settings.currency    = cur; settings.locale = localeMap[cur] || "es";
  settings.monthlyGoal = Number(document.getElementById("monthlyGoalInput").value) || 0;
  persist(KEY.settings, settings);
  document.getElementById("settingsModal").hidden = true;
  renderAll(); autoSync();
}

function buildBudgetInputs() {
  const container = document.getElementById("budgetInputs");
  container.innerHTML = "";
  EXP_CATS.forEach(c => {
    const row = document.createElement("div");
    row.className = "budget-input-row";
    row.innerHTML = `<label>${c.icon} ${c.id}</label>
      <input type="number" min="0" step="0.01" inputmode="decimal" data-cat="${c.id}" value="${budgets[c.id] || 0}" placeholder="0">`;
    container.append(row);
  });
}

function buildRecurringList() {
  const container = document.getElementById("recurringList");
  container.innerHTML = "";
  if (!recurring.length) { container.innerHTML = '<p class="modal-hint" style="margin-bottom:4px">Sin gastos fijos.</p>'; return; }
  recurring.forEach(rec => {
    const div = document.createElement("div");
    div.className = "rec-item";
    const pausedText = rec.paused ? " · ⏸" : "";
    const dueText = rec.dueDay ? ` · día ${rec.dueDay}` : "";
    div.innerHTML = `<span>${catIcon(rec.category)} ${esc(rec.name)}${dueText}${pausedText}</span><span>${fmt(rec.amount)}</span><button class="rec-del" type="button">✕</button>`;
    div.querySelector(".rec-del").addEventListener("click", () => {
      recurring = recurring.filter(r => r.id !== rec.id);
      persist(KEY.recurring, recurring); buildRecurringList();
    });
    container.append(div);
  });
}

function buildAccountsSettingsList() {
  const container = document.getElementById("accountsSettingsList");
  if (!container) return;
  container.innerHTML = "";
  if (!accounts.length) { container.innerHTML = '<p class="modal-hint" style="margin-bottom:4px">Sin cuentas.</p>'; return; }
  accounts.forEach(acc => {
    const isLia = acc.type === "liability";
    const div = document.createElement("div");
    div.className = "rec-item";
    div.innerHTML = `<span>${esc(acc.icon || (isLia ? "💳" : "🏦"))} ${esc(acc.name)}</span><span class="${isLia ? "expense" : "income"}">${isLia ? "−" : ""}${fmt(acc.balance)}</span><button class="rec-del" type="button">✕</button>`;
    div.querySelector(".rec-del").addEventListener("click", () => {
      accounts = accounts.filter(a => a.id !== acc.id);
      persist(KEY.accounts, accounts);
      buildAccountsSettingsList(); renderNetWorth(); autoSync();
    });
    container.append(div);
  });
}

function buildGoalsSettingsList() {
  const container = document.getElementById("goalsSettingsList");
  if (!container) return;
  container.innerHTML = "";
  if (!goals.length) { container.innerHTML = '<p class="modal-hint" style="margin-bottom:4px">Sin metas.</p>'; return; }
  goals.forEach(goal => {
    const div = document.createElement("div");
    div.className = "rec-item";
    div.innerHTML = `<span style="display:flex;align-items:center;gap:6px"><span style="width:10px;height:10px;border-radius:2px;background:${goal.color || 'var(--primary)'}"></span>${esc(goal.name)}</span><span>${fmt(goal.amount)}</span><button class="rec-del" type="button">✕</button>`;
    div.querySelector(".rec-del").addEventListener("click", () => {
      goals = goals.filter(g => g.id !== goal.id);
      persist(KEY.goals, goals);
      buildGoalsSettingsList(); renderGoals(); autoSync();
    });
    container.append(div);
  });
}

function showSyncStatus(msg, type) {
  const el = document.getElementById("syncStatus");
  el.textContent = msg; el.className = "sync-msg " + type; el.hidden = false;
}

function exportCsv() {
  const all = [
    ...expenses.map(e => ({ ...e, tipo: "gasto" })),
    ...income.map(i => ({ ...i, tipo: "ingreso" })),
  ].sort((a, b) => a.date.localeCompare(b.date));
  const rows = all.map(tx => [tx.tipo, tx.date, tx.category, `"${String(tx.note||"").replaceAll('"','""')}"`, tx.amount]);
  const csv  = [["tipo","fecha","categoria","nota","monto"], ...rows].map(r => r.join(",")).join("\n");
  const url  = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  Object.assign(document.createElement("a"), { href: url, download: `gastos-${currentUser}-${todayIso()}.csv` }).click();
  URL.revokeObjectURL(url);
}

// ════════════════════════════════════════════════════════════
// APP START
// ════════════════════════════════════════════════════════════

function startApp(username) {
  currentUser  = username.toLowerCase();
  currentMonth = todayIso().slice(0, 7);
  expenses  = load(KEY.expenses,  []);
  income    = load(KEY.income,    []);
  budgets   = load(KEY.budgets,   {});
  recurring = load(KEY.recurring, []);
  settings  = load(KEY.settings,  { currency: "BOB", locale: "es-BO" });
  loans     = load(KEY.loans,     []);
  accounts  = load(KEY.accounts,  []);
  goals     = load(KEY.goals,     []);

  const themes = { "taisiña": "tais", "ikersiño": "iker" };
  document.body.dataset.theme = themes[currentUser] || "";

  document.getElementById("userInitial").textContent  = username.charAt(0).toUpperCase();
  document.getElementById("monthLabel").textContent   = monthLabel(currentMonth);
  document.getElementById("addDate").value            = todayIso();

  buildCatFilter();

  const rangeFromEl = document.getElementById("rangeFrom");
  const rangeToEl   = document.getElementById("rangeTo");
  if (rangeFromEl && !rangeFromEl.value) rangeFromEl.value = currentMonth + "-01";
  if (rangeToEl   && !rangeToEl.value)   rangeToEl.value   = todayIso();

  if (!startApp._listenersAttached) { attachAppListeners(); startApp._listenersAttached = true; }
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
  syncOnStart();
  startCloudPolling();

  const loginEl = document.getElementById("loginScreen");
  const appEl   = document.getElementById("appRoot");
  appEl.hidden  = false;
  appEl.classList.add("app-entering");
  appEl.addEventListener("animationend", () => appEl.classList.remove("app-entering"), { once: true });
  loginEl.classList.add("exit");
  loginEl.addEventListener("animationend", () => { loginEl.hidden = true; }, { once: true });

  showView("inicio");
  renderAll();
}

function attachAppListeners() {

  // Month nav
  document.getElementById("prevMonth").addEventListener("click", () => {
    const [y, m] = currentMonth.split("-").map(Number);
    currentMonth = new Date(y, m - 2, 1).toISOString().slice(0, 7);
    document.getElementById("monthLabel").textContent = monthLabel(currentMonth); renderAll();
  });
  document.getElementById("nextMonth").addEventListener("click", () => {
    const [y, m] = currentMonth.split("-").map(Number);
    currentMonth = new Date(y, m, 1).toISOString().slice(0, 7);
    document.getElementById("monthLabel").textContent = monthLabel(currentMonth); renderAll();
  });

  // Bottom nav
  document.querySelectorAll(".bnav-btn[data-view]").forEach(btn => {
    btn.addEventListener("click", () => showView(btn.dataset.view));
  });

  // FAB
  document.getElementById("fabBtn").addEventListener("click", openAddModal);

  // Add modal: type switch
  document.getElementById("addTypeExpense").addEventListener("click", () => setAddType("expense"));
  document.getElementById("addTypeIncome").addEventListener("click",  () => setAddType("income"));
  document.getElementById("sheetBackdrop").addEventListener("click",  closeAddModal);

  // Add modal: save
  document.getElementById("addSaveBtn").addEventListener("click", () => {
    const amount = Number(document.getElementById("addAmount").value);
    if (!amount || amount <= 0) return;
    const note = document.getElementById("addNote").value.trim();
    const date = document.getElementById("addDate").value;
    const cat  = addType === "expense" ? selectedExpCat : selectedIncCat;
    if (editingTxId) {
      if (editingTxType === "expense") {
        const idx = expenses.findIndex(e => e.id === editingTxId);
        if (idx !== -1) expenses[idx] = { ...expenses[idx], amount, category: cat, date, note };
        persist(KEY.expenses, expenses);
      } else {
        const idx = income.findIndex(i => i.id === editingTxId);
        if (idx !== -1) income[idx] = { ...income[idx], amount, category: cat, date, note };
        persist(KEY.income, income);
      }
    } else {
      if (addType === "expense") {
        expenses.push({ id: crypto.randomUUID(), amount, category: selectedExpCat, date, note, createdAt: Date.now() });
        persist(KEY.expenses, expenses);
      } else {
        income.push({ id: crypto.randomUUID(), amount, category: selectedIncCat, date, note, createdAt: Date.now() });
        persist(KEY.income, income);
      }
    }
    closeAddModal();
    renderAll(); autoSync();
  });

  // Category filter & search
  document.getElementById("catFilter").addEventListener("change", renderTxList);
  document.getElementById("txSearch")?.addEventListener("input", renderTxList);
  document.getElementById("exportBtn").addEventListener("click",  exportCsv);

  // Date range filter
  document.getElementById("rangeFrom").addEventListener("change", renderTxList);
  document.getElementById("rangeTo").addEventListener("change",   renderTxList);

  // Settings
  document.getElementById("settingsBtn").addEventListener("click",    openSettings);
  document.getElementById("closeSettings").addEventListener("click",  closeSettings);
  document.getElementById("settingsModal").addEventListener("click",  e => { if (e.target === e.currentTarget) closeSettings(); });
  document.getElementById("manageFixedBtn").addEventListener("click", openSettings);

  // Recurring form (fijos)
  document.getElementById("recurringForm").addEventListener("submit", e => {
    e.preventDefault();
    const name     = document.getElementById("recName").value.trim();
    const amount   = Number(document.getElementById("recAmount").value);
    const category = document.getElementById("recCategory").value;
    const dueDay   = Number(document.getElementById("recDueDay").value) || null;
    const paused   = document.getElementById("recPaused").value === "1";
    if (!name || !amount) return;
    recurring.push({ id: crypto.randomUUID(), name, amount, category, dueDay, paused });
    persist(KEY.recurring, recurring);
    document.getElementById("recName").value = "";
    document.getElementById("recAmount").value = "";
    document.getElementById("recDueDay").value = "";
    document.getElementById("recPaused").value = "0";
    buildRecurringList();
  });

  // Bank selector auto-fill
  document.getElementById("accBank")?.addEventListener("change", () => {
    const val = document.getElementById("accBank").value;
    if (!val) return;
    const [bankName, , bankType] = val.split("|");
    const nameEl = document.getElementById("accName");
    const typeEl = document.getElementById("accType");
    if (!nameEl.value) nameEl.value = bankName;
    typeEl.value = bankType || "asset";
  });

  // Account form
  document.getElementById("accountForm")?.addEventListener("submit", e => {
    e.preventDefault();
    const bankVal = document.getElementById("accBank").value;
    const name    = document.getElementById("accName").value.trim();
    const balance = Number(document.getElementById("accBalance").value);
    const type    = document.getElementById("accType").value;
    const icon    = bankVal ? bankVal.split("|")[1] : "🏦";
    if (!name || isNaN(balance)) return;
    accounts.push({ id: crypto.randomUUID(), name, balance, type, icon });
    persist(KEY.accounts, accounts);
    document.getElementById("accBank").value    = "";
    document.getElementById("accName").value    = "";
    document.getElementById("accBalance").value = "";
    buildAccountsSettingsList(); renderNetWorth(); autoSync();
  });

  // Goal form
  document.getElementById("goalForm")?.addEventListener("submit", e => {
    e.preventDefault();
    const name   = document.getElementById("goalName").value.trim();
    const amount = Number(document.getElementById("goalAmount").value);
    const color  = document.getElementById("goalColor").value;
    if (!name || !amount) return;
    goals.push({ id: crypto.randomUUID(), name, amount, color, saved: 0 });
    persist(KEY.goals, goals);
    document.getElementById("goalName").value   = "";
    document.getElementById("goalAmount").value = "";
    buildGoalsSettingsList(); renderGoals(); autoSync();
  });

  // Shortcuts to settings from inicio
  document.getElementById("addAccountBtn")?.addEventListener("click", openSettings);
  document.getElementById("addGoalBtnShortcut")?.addEventListener("click", openSettings);

  // Biometric
  document.getElementById("setupBiometricBtn").addEventListener("click", async () => {
    const btn  = document.getElementById("setupBiometricBtn");
    const hint = document.getElementById("biometricHint");
    btn.disabled = true; btn.style.opacity = ".6";
    try {
      await registerPasskey(currentUser);
      hint.textContent = "Face ID configurado.";
      btn.hidden = true; document.getElementById("removeBiometricBtn").hidden = false;
    } catch (err) {
      hint.textContent = err.name === "NotAllowedError" ? "Cancelado." : "Error: " + err.message;
    } finally { btn.disabled = false; btn.style.opacity = ""; }
  });

  document.getElementById("removeBiometricBtn").addEventListener("click", () => {
    if (!confirm("¿Quitar Face ID?")) return;
    removePasskey(currentUser);
    document.getElementById("biometricHint").textContent = "Configurá Face ID para entrar sin contraseña.";
    document.getElementById("setupBiometricBtn").hidden = false;
    document.getElementById("removeBiometricBtn").hidden = true;
  });

  document.getElementById("deleteAllBtn").addEventListener("click", () => {
    if (!confirm(`¿Borrar todos los datos de ${currentUser}?`)) return;
    expenses = []; income = []; budgets = {}; recurring = []; loans = []; accounts = []; goals = [];
    [KEY.expenses, KEY.income, KEY.budgets, KEY.recurring, KEY.settings, KEY.loans, KEY.accounts, KEY.goals].forEach(k => localStorage.removeItem(k));
    document.getElementById("settingsModal").hidden = true;
    renderAll();
  });

  document.getElementById("logoutBtn").addEventListener("click", () => {
    if (!confirm(`¿Cerrar sesión?`)) return;
    document.body.dataset.theme = "";
    clearSession(); location.reload();
  });

  // Loans
  document.getElementById("loansOverview").addEventListener("click", () => showView("deudas"));

  document.getElementById("addLoanToggle").addEventListener("click", () => {
    const form = document.getElementById("newLoanForm");
    form.hidden = !form.hidden;
    if (!form.hidden) {
      document.getElementById("loanDate").value = todayIso();
      document.getElementById("loanAmount").focus();
    }
  });

  document.getElementById("saveLoanBtn").addEventListener("click", () => {
    const amount = Number(document.getElementById("loanAmount").value);
    const person = document.getElementById("loanPerson").value.trim();
    const note   = document.getElementById("loanNote").value.trim();
    const date   = document.getElementById("loanDate").value;
    if (!amount || !person) return;
    loans.push({ id: crypto.randomUUID(), person, amount, date, note, createdAt: Date.now(), repayments: [], settled: false });
    persist(KEY.loans, loans);
    document.getElementById("loanAmount").value = "";
    document.getElementById("loanPerson").value = "";
    document.getElementById("loanNote").value   = "";
    document.getElementById("newLoanForm").hidden = true;
    renderLoans(); autoSync();
  });

  // Payment modal
  document.getElementById("closePaymentModal").addEventListener("click", closePaymentModal);
  document.getElementById("paymentModal").addEventListener("click", e => { if (e.target === e.currentTarget) closePaymentModal(); });

  document.getElementById("confirmPaymentBtn").addEventListener("click", () => {
    const amount = Number(document.getElementById("paymentAmount").value);
    const date   = document.getElementById("paymentDate").value;
    if (!amount || !paymentModalLoanId) return;
    const i = loans.findIndex(l => l.id === paymentModalLoanId);
    if (i === -1) { closePaymentModal(); return; }
    loans[i].repayments.push({ id: crypto.randomUUID(), amount, date, createdAt: Date.now() });
    if (loanPending(loans[i]) <= 0) loans[i].settled = true;
    persist(KEY.loans, loans);
    closePaymentModal(); renderLoans(); autoSync();
  });

  document.getElementById("settleFullBtn").addEventListener("click", () => {
    if (!paymentModalLoanId) return;
    const i = loans.findIndex(l => l.id === paymentModalLoanId);
    if (i !== -1) { loans[i].settled = true; persist(KEY.loans, loans); }
    closePaymentModal(); renderLoans(); autoSync();
  });

  // Supabase sync
  document.getElementById("saveSupabaseBtn").addEventListener("click", async () => {
    const url = document.getElementById("supabaseUrl").value;
    const key = document.getElementById("supabaseKey").value;
    const table = document.getElementById("supabaseTable").value;
    if (!url || !key || !table) { showSyncStatus("Completá URL, anon key y tabla.", "err"); return; }
    const btn = document.getElementById("saveSupabaseBtn");
    btn.disabled = true; btn.style.opacity = ".6";
    try {
      saveSupaCreds(url, key, table);
      renderSupabaseSql();
      document.getElementById("syncActiveBadge").hidden = false;
      await syncUpload();
      startCloudPolling();
      showSyncStatus("Conexión guardada y datos subidos.", "ok");
    } catch (err) {
      showSyncStatus(err.message, "err");
    } finally {
      btn.disabled = false; btn.style.opacity = "";
    }
  });
  document.getElementById("supabaseTable").addEventListener("input", renderSupabaseSql);
  document.getElementById("shareSetupBtn").addEventListener("click", async () => {
    const url = getSetupUrl();
    if (!url) return;
    if (navigator.share) {
      try { await navigator.share({ title: "Gastos — activar sincronización", url }); }
      catch { /* usuario canceló */ }
      return;
    }
    try {
      await navigator.clipboard.writeText(url);
      showSyncStatus("Link copiado. Abrílo en el otro dispositivo.", "ok");
    } catch {
      showSyncStatus("No se pudo copiar. Copiá la URL manualmente.", "err");
    }
  });
  document.getElementById("copySupabaseSqlBtn").addEventListener("click", async () => {
    const sql = document.getElementById("supabaseSql").value;
    try {
      await navigator.clipboard.writeText(sql);
      showSyncStatus("SQL copiado.", "ok");
    } catch {
      document.getElementById("supabaseSql").select();
      showSyncStatus("No pude copiarlo. Ya lo dejé seleccionado.", "ok");
    }
  });

  document.getElementById("syncUpBtn").addEventListener("click", async () => {
    const btn = document.getElementById("syncUpBtn");
    btn.disabled = true; btn.style.opacity = ".6";
    try   { await syncUpload(); startCloudPolling(); showSyncStatus("Datos subidos.", "ok"); }
    catch (err) { showSyncStatus("Error: " + err.message, "err"); }
    finally { btn.disabled = false; btn.style.opacity = ""; }
  });

  document.getElementById("syncDownBtn").addEventListener("click", async () => {
    if (!confirm("¿Reemplazar datos locales con los de Supabase?")) return;
    const btn = document.getElementById("syncDownBtn");
    btn.disabled = true; btn.style.opacity = ".6";
    try   { await syncDownload(); startCloudPolling(); showSyncStatus("Datos bajados.", "ok"); }
    catch (err) { showSyncStatus("Error: " + err.message, "err"); }
    finally { btn.disabled = false; btn.style.opacity = ""; }
  });
}

// ════════════════════════════════════════════════════════════
// LOGIN SCREEN
// ════════════════════════════════════════════════════════════

function showBiometricMode(username) {
  document.getElementById("passwordMode").hidden  = true;
  document.getElementById("biometricMode").hidden = false;
  document.getElementById("bioInitial").textContent = username.charAt(0).toUpperCase();
  document.getElementById("bioName").textContent    = username;
  document.getElementById("biometricError").hidden  = true;
}
function showPasswordMode() {
  document.getElementById("biometricMode").hidden = true;
  document.getElementById("passwordMode").hidden  = false;
}

document.getElementById("loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  const user = document.getElementById("loginUser").value.trim();
  const pass = document.getElementById("loginPass").value;
  if (!await tryLogin(user, pass)) { document.getElementById("loginError").hidden = false; return; }
  document.getElementById("loginError").hidden = true;
  saveSession(user); startApp(user);
});

document.getElementById("registerForm").addEventListener("submit", async e => {
  e.preventDefault();
  const user  = document.getElementById("regUser").value.trim();
  const pass  = document.getElementById("regPass").value;
  const pass2 = document.getElementById("regPass2").value;
  const errEl = document.getElementById("registerError");
  if (pass !== pass2) { errEl.textContent = "Las contraseñas no coinciden."; errEl.hidden = false; return; }
  if (pass.length < 4) { errEl.textContent = "Mínimo 4 caracteres."; errEl.hidden = false; return; }
  const err = await createAccount(user, pass);
  if (err) { errEl.textContent = err; errEl.hidden = false; return; }
  errEl.hidden = true;
  saveSession(user); startApp(user);
});
document.getElementById("showRegisterBtn").addEventListener("click", () => {
  document.getElementById("loginForm").hidden = true;
  document.getElementById("registerForm").hidden = false;
});
document.getElementById("showLoginBtn").addEventListener("click", () => {
  document.getElementById("registerForm").hidden = true;
  document.getElementById("loginForm").hidden = false;
});

document.getElementById("biometricBtn").addEventListener("click", async () => {
  const btn = document.getElementById("biometricBtn"), errEl = document.getElementById("biometricError");
  const last = getLastUser();
  if (!last) { showPasswordMode(); return; }
  btn.disabled = true; btn.style.opacity = ".6"; errEl.hidden = true;
  try   { await verifyPasskey(last); saveSession(last); startApp(last); }
  catch (err) {
    errEl.hidden = false;
    errEl.textContent = err.name === "NotAllowedError" ? "Cancelado." : "No se pudo verificar.";
  }
  finally { btn.disabled = false; btn.style.opacity = ""; }
});

document.getElementById("usePwdBtn").addEventListener("click", () => {
  const last = getLastUser();
  if (last) document.getElementById("loginUser").value = last;
  showPasswordMode();
});
document.getElementById("switchUserBtn").addEventListener("click", () => {
  document.getElementById("loginUser").value = "";
  showPasswordMode();
  document.getElementById("loginUser").focus();
});

// ════════════════════════════════════════════════════════════
// ENTRY POINT
// ════════════════════════════════════════════════════════════

(async function init() {
  const users = loadUsers();
  if (!users["taisiña"])  await createAccount("Taisiña",  "Taisonlybirdies1");
  if (!users["ikersiño"]) await createAccount("Ikersiño", "8790");

  applySetupFromUrl();
  const activeSession = getSession();
  if (activeSession) {
    startApp(activeSession);
  } else {
    const last = getLastUser();
    if (last && hasPasskey(last)) showBiometricMode(last);
    else { if (last) document.getElementById("loginUser").value = last; showPasswordMode(); }
  }
})();

window.addEventListener("focus", pullCloudChanges);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) pullCloudChanges();
});
