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

function hashPass(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

function tryLogin(username, password) {
  const users = loadUsers();
  const user  = users[username.toLowerCase()];
  return user && user.pass === hashPass(password);
}

function createAccount(username, password) {
  const users = loadUsers();
  const key   = username.toLowerCase();
  if (users[key]) return "Este usuario ya existe.";
  users[key] = { displayName: username, pass: hashPass(password) };
  localStorage.setItem(AUTH_USERS_KEY, JSON.stringify(users));
  return null;
}

// ── Session: valid only within the same calendar day ─────────
function getSession() {
  try {
    const s = JSON.parse(localStorage.getItem(SESSION_KEY));
    if (!s || !s.user || !s.date) return null;
    if (s.date !== todayIso()) return null;
    if (!loadUsers()[s.user]) return null;
    return s.user;
  } catch { return null; }
}

function saveSession(user) {
  localStorage.setItem(SESSION_KEY, JSON.stringify({
    user: user.toLowerCase(), date: todayIso(),
  }));
  localStorage.setItem(LAST_USER_KEY, user.toLowerCase());
}

function clearSession()  { localStorage.removeItem(SESSION_KEY); }
function getLastUser()   {
  const u = localStorage.getItem(LAST_USER_KEY);
  return u && loadUsers()[u] ? u : null;
}

// ── Passkeys (WebAuthn / Face ID) ─────────────────────────────
function passkeyStorageKey(user) { return `mb:${user}:passkey-id`; }
function hasPasskey(user)  { return !!localStorage.getItem(passkeyStorageKey(user)); }
function removePasskey(u)  { localStorage.removeItem(passkeyStorageKey(u)); }

function savePasskeyId(user, rawId) {
  localStorage.setItem(passkeyStorageKey(user),
    btoa(String.fromCharCode(...new Uint8Array(rawId))));
}

function loadPasskeyId(user) {
  const b64 = localStorage.getItem(passkeyStorageKey(user));
  if (!b64) return null;
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

function isBiometricSupported() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}

async function isPlatformAuthenticatorAvailable() {
  if (!isBiometricSupported()) return false;
  try { return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); }
  catch { return false; }
}

async function registerPasskey(username) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "Mi Bolsillo", id: location.hostname },
      user: {
        id: Uint8Array.from(username, c => c.charCodeAt(0)),
        name: username, displayName: username,
      },
      pubKeyCredParams: [
        { alg: -7, type: "public-key" },
        { alg: -257, type: "public-key" },
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        residentKey: "preferred",
      },
      timeout: 60000,
    },
  });
  savePasskeyId(username, cred.rawId);
  return true;
}

async function verifyPasskey(username) {
  const credId = loadPasskeyId(username);
  if (!credId) throw new Error("No passkey stored");
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: location.hostname,
      allowCredentials: [{ id: credId, type: "public-key" }],
      userVerification: "required",
      timeout: 60000,
    },
  });
  return assertion !== null;
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
};

let expenses  = [];
let income    = [];
let budgets   = {};
let recurring = [];
let settings  = {};
let loans     = [];   // { id, person, amount, date, note, createdAt, repayments:[], settled }

let currentMonth   = "";
let selectedExpCat = "Comida";
let selectedIncCat = "Familiar";

// ════════════════════════════════════════════════════════════
// UTILS
// ════════════════════════════════════════════════════════════

function load(key, def) {
  try { return JSON.parse(localStorage.getItem(key)) ?? def; }
  catch { return def; }
}
function persist(key, data) { localStorage.setItem(key, JSON.stringify(data)); }

function todayIso() { return new Date().toISOString().slice(0, 10); }

function fmt(n) {
  return new Intl.NumberFormat(settings.locale || "es-BO", {
    style: "currency", currency: settings.currency || "BOB", maximumFractionDigits: 2,
  }).format(n);
}

function fmtDate(str) {
  const [y, m, d] = str.split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString("es", { day: "numeric", month: "short" });
}

function sum(arr) { return arr.reduce((t, x) => t + Number(x.amount), 0); }

function catIcon(id) {
  return (EXP_CATS.find(c => c.id === id) || INC_CATS.find(c => c.id === id) || { icon: "📦" }).icon;
}

function monthLabel(ym) {
  const [y, m] = ym.split("-").map(Number);
  const s = new Date(y, m - 1, 1).toLocaleDateString("es", { month: "long", year: "numeric" });
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function loanPending(loan) {
  const repaid = loan.repayments.reduce((t, r) => t + Number(r.amount), 0);
  return Math.max(0, Number(loan.amount) - repaid);
}

// ════════════════════════════════════════════════════════════
// RENDER
// ════════════════════════════════════════════════════════════

function renderAll() {
  const mExp = expenses.filter(e => e.date.startsWith(currentMonth));
  const mInc = income.filter(i => i.date.startsWith(currentMonth));

  const totalExp   = sum(mExp);
  const totalInc   = sum(mInc);
  const balance    = totalInc - totalExp;
  const todayItems = expenses.filter(e => e.date === todayIso());
  const daysSpent  = new Set(mExp.map(e => e.date)).size || 1;
  const savingsPct = totalInc > 0 ? Math.max(0, Math.min(100, (balance / totalInc) * 100)) : 0;

  const balEl = document.getElementById("balanceAmt");
  balEl.textContent = fmt(balance);
  balEl.style.color = balance >= 0 ? "#fda4af" : "#fca5a5";

  document.getElementById("incomeAmt").textContent  = fmt(totalInc);
  document.getElementById("expenseAmt").textContent = fmt(totalExp);
  document.getElementById("todayAmt").textContent   = fmt(sum(todayItems));
  document.getElementById("avgAmt").textContent     = fmt(totalExp / daysSpent);

  const savSec = document.getElementById("savingsSection");
  savSec.hidden = totalInc === 0;
  if (totalInc > 0) {
    document.getElementById("savingsPct").textContent = Math.round(savingsPct) + "%";
    const fill = document.getElementById("savingsFill");
    fill.style.width = savingsPct + "%";
    fill.style.background = savingsPct >= 20 ? "#86efac"
      : savingsPct >= 10 ? "#fcd34d" : "#fca5a5";
  }

  renderBudgets(mExp);
  renderTxList(mExp, mInc);
  renderLoans();
}

// ── Budget bars ──────────────────────────────────────────────
function renderBudgets(mExp) {
  const panel     = document.getElementById("budgetPanel");
  const container = document.getElementById("budgetBars");
  container.innerHTML = "";

  const rows = EXP_CATS.map(c => ({
    ...c,
    spent: sum(mExp.filter(e => e.category === c.id)),
    limit: Number(budgets[c.id] || 0),
  })).filter(r => r.spent > 0 || r.limit > 0).sort((a, b) => b.spent - a.spent);

  panel.hidden = rows.length === 0;

  rows.forEach(r => {
    const pct  = r.limit > 0 ? Math.min((r.spent / r.limit) * 100, 100) : 0;
    const over = r.limit > 0 && r.spent > r.limit;
    const warn = r.limit > 0 && pct >= 80 && !over;
    const div  = document.createElement("div");
    div.className = "budget-row";
    div.innerHTML = `
      <div class="budget-label">
        <span class="cat-left">${r.icon} ${r.id}</span>
        <span class="cat-right ${over ? "over" : ""}">
          ${fmt(r.spent)}${r.limit > 0 ? " / " + fmt(r.limit) : ""}
        </span>
      </div>
      ${r.limit > 0 ? `<div class="budget-track"><div class="budget-fill ${over ? "over" : warn ? "warn" : ""}" style="width:${pct}%"></div></div>` : ""}
    `;
    container.append(div);
  });
}

// ── Transaction list ─────────────────────────────────────────
function renderTxList(mExp, mInc) {
  const filter = document.getElementById("catFilter").value;
  const list   = document.getElementById("txList");
  const empty  = document.getElementById("emptyMsg");
  const tpl    = document.getElementById("txTpl");

  const all = [
    ...mExp.map(e => ({ ...e, type: "expense" })),
    ...mInc.map(i => ({ ...i, type: "income" })),
  ]
    .filter(tx => {
      if (filter === "all")     return true;
      if (filter === "_income") return tx.type === "income";
      return tx.category === filter;
    })
    .sort((a, b) => b.date.localeCompare(a.date) || b.createdAt - a.createdAt);

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
    node.querySelector(".tx-del").addEventListener("click", () => {
      if (tx.type === "expense") { expenses = expenses.filter(e => e.id !== tx.id); persist(KEY.expenses, expenses); }
      else                       { income   = income.filter(i => i.id !== tx.id);   persist(KEY.income, income); }
      renderAll();
    });
    list.append(node);
  });
}

// ── Quick fixed items ────────────────────────────────────────
function renderQuickItems() {
  const container = document.getElementById("quickItems");
  container.innerHTML = "";

  if (recurring.length === 0) {
    container.innerHTML = '<p class="hint">No hay gastos fijos. Configuralos en ⚙ para verlos acá.</p>';
    return;
  }

  recurring.forEach(rec => {
    const sid   = `rec:${rec.id}:${currentMonth}`;
    const added = expenses.some(e => e.sourceId === sid);
    const div   = document.createElement("div");
    div.className = "quick-item" + (added ? " done" : "");
    div.innerHTML = `
      <div class="qi-left">
        <span class="qi-icon">${catIcon(rec.category)}</span>
        <div>
          <div class="qi-name">${esc(rec.name)}</div>
          <div class="qi-cat">${rec.category}${added ? " · ✓ Ya registrado" : ""}</div>
        </div>
      </div>
      <span class="qi-amt">${fmt(rec.amount)}</span>
    `;
    if (!added) {
      div.addEventListener("click", () => {
        expenses.push({ id: crypto.randomUUID(), amount: rec.amount, category: rec.category,
          date: currentMonth + "-01", note: rec.name, createdAt: Date.now(), sourceId: sid });
        persist(KEY.expenses, expenses);
        renderAll();
      });
    }
    container.append(div);
  });
}

// ── LOANS ────────────────────────────────────────────────────
function renderLoans() {
  const list  = document.getElementById("loanList");
  const empty = document.getElementById("loansEmpty");

  const active = loans.filter(l => !l.settled && loanPending(l) > 0);
  list.innerHTML = "";
  empty.hidden = active.length > 0;

  // Overview banner
  const banner = document.getElementById("loansOverview");
  if (active.length === 0) {
    banner.hidden = true;
  } else {
    const total = active.reduce((t, l) => t + loanPending(l), 0);
    banner.hidden = false;
    document.getElementById("loansCountLabel").textContent =
      active.length === 1 ? "1 préstamo activo" : `${active.length} préstamos activos`;
    document.getElementById("loansTotalAmt").textContent = fmt(total) + " pendientes";
  }

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
          <strong class="loan-person-name">${esc(loan.person)}</strong>
          <span class="loan-meta">Prestado ${fmt(loan.amount)} · ${fmtDate(loan.date)}${loan.note ? " · " + esc(loan.note) : ""}</span>
          ${repaid > 0 ? `<span class="loan-repaid-info">Pagó ${fmt(repaid)} hasta ahora</span>` : ""}
        </div>
        <div class="loan-pending-badge">
          <b>${fmt(pending)}</b>
          <span>pendiente</span>
        </div>
      </div>
      <div class="loan-progress">
        <div class="loan-progress-fill" style="width:${pct}%"></div>
      </div>
      <div class="loan-btns">
        <button class="btn-loan-pay" type="button">Registrar pago</button>
        <button class="btn-loan-settle" type="button">Saldado ✓</button>
        <button class="btn-loan-del" type="button">✕</button>
      </div>
      <div class="loan-pay-form" hidden>
        <input class="loan-pay-amount" type="number" inputmode="decimal"
               min="0.01" step="0.01" placeholder="Monto recibido" autocomplete="off">
        <input class="loan-pay-date" type="date" value="${todayIso()}">
        <div class="loan-pay-row">
          <button class="btn-confirm-pay btn-submit" type="button">Confirmar pago</button>
          <button class="btn-cancel-pay" type="button">Cancelar</button>
        </div>
      </div>
    `;

    const payForm = div.querySelector(".loan-pay-form");

    // Toggle pay form
    div.querySelector(".btn-loan-pay").addEventListener("click", () => {
      payForm.hidden = !payForm.hidden;
      if (!payForm.hidden) div.querySelector(".loan-pay-amount").focus();
    });

    div.querySelector(".btn-cancel-pay").addEventListener("click", () => {
      payForm.hidden = true;
    });

    // Confirm partial payment
    div.querySelector(".btn-confirm-pay").addEventListener("click", () => {
      const amount = Number(div.querySelector(".loan-pay-amount").value);
      const date   = div.querySelector(".loan-pay-date").value;
      if (!amount || amount <= 0) return;
      const idx = loans.findIndex(l => l.id === loan.id);
      if (idx === -1) return;
      loans[idx].repayments.push({ id: crypto.randomUUID(), amount, date, createdAt: Date.now() });
      if (loanPending(loans[idx]) <= 0) loans[idx].settled = true;
      persist(KEY.loans, loans);
      renderLoans();
    });

    // Mark fully settled
    div.querySelector(".btn-loan-settle").addEventListener("click", () => {
      const idx = loans.findIndex(l => l.id === loan.id);
      if (idx !== -1) { loans[idx].settled = true; persist(KEY.loans, loans); renderLoans(); }
    });

    // Delete loan
    div.querySelector(".btn-loan-del").addEventListener("click", () => {
      if (!confirm(`¿Eliminar el préstamo a ${loan.person}?`)) return;
      loans = loans.filter(l => l.id !== loan.id);
      persist(KEY.loans, loans);
      renderLoans();
    });

    list.append(div);
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
    btn.addEventListener("click", () => { onPick(c.id); buildChips(containerId, cats, c.id, onPick); });
    container.append(btn);
  });
}

function buildCatFilter() {
  const sel  = document.getElementById("catFilter");
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
  document.getElementById("currencySelect").value = settings.currency || "BOB";
  buildBudgetInputs();
  buildRecurringList();
  const recCat = document.getElementById("recCategory");
  recCat.innerHTML = EXP_CATS.map(c => `<option value="${c.id}">${c.icon} ${c.id}</option>`).join("");

  const hint      = document.getElementById("biometricHint");
  const setupBtn  = document.getElementById("setupBiometricBtn");
  const removeBtn = document.getElementById("removeBiometricBtn");
  isPlatformAuthenticatorAvailable().then(available => {
    if (!available) {
      hint.textContent = "Face ID / biometría no disponible en este dispositivo.";
      setupBtn.hidden = removeBtn.hidden = true; return;
    }
    if (hasPasskey(currentUser)) {
      hint.textContent = "Face ID configurado. Podés quitarlo si querés.";
      setupBtn.hidden = true; removeBtn.hidden = false;
    } else {
      hint.textContent = "Configurá Face ID para no ingresar tu contraseña cada día.";
      setupBtn.hidden = false; removeBtn.hidden = true;
    }
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
  settings.currency = cur;
  settings.locale   = localeMap[cur] || "es";
  persist(KEY.settings, settings);
  document.getElementById("settingsModal").hidden = true;
  renderAll();
}

function buildBudgetInputs() {
  const container = document.getElementById("budgetInputs");
  container.innerHTML = "";
  EXP_CATS.forEach(c => {
    const row = document.createElement("div");
    row.className = "budget-input-row";
    row.innerHTML = `<label>${c.icon} ${c.id}</label>
      <input type="number" min="0" step="0.01" inputmode="decimal"
             data-cat="${c.id}" value="${budgets[c.id] || 0}" placeholder="0">`;
    container.append(row);
  });
}

function buildRecurringList() {
  const container = document.getElementById("recurringList");
  container.innerHTML = "";
  if (recurring.length === 0) { container.innerHTML = '<p class="hint">Sin gastos fijos.</p>'; return; }
  recurring.forEach(rec => {
    const div = document.createElement("div");
    div.className = "rec-item";
    div.innerHTML = `<span>${catIcon(rec.category)} ${esc(rec.name)}</span><span>${fmt(rec.amount)}</span><button class="rec-del" type="button">✕</button>`;
    div.querySelector(".rec-del").addEventListener("click", () => {
      recurring = recurring.filter(r => r.id !== rec.id);
      persist(KEY.recurring, recurring); buildRecurringList();
    });
    container.append(div);
  });
}

// ═══ Export ═══════════════════════════════════════════════════
function exportCsv() {
  const all = [
    ...expenses.map(e => ({ ...e, tipo: "gasto" })),
    ...income.map(i => ({ ...i, tipo: "ingreso" })),
  ].sort((a, b) => a.date.localeCompare(b.date));
  const header = ["tipo","fecha","categoria","nota","monto"];
  const rows   = all.map(tx => [tx.tipo, tx.date, tx.category, `"${String(tx.note||"").replaceAll('"','""')}"`, tx.amount]);
  const csv    = [header, ...rows].map(r => r.join(",")).join("\n");
  const blob   = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url    = URL.createObjectURL(blob);
  Object.assign(document.createElement("a"), { href: url, download: `mi-bolsillo-${currentUser}-${todayIso()}.csv` }).click();
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

  document.getElementById("loginScreen").hidden = true;
  document.getElementById("appRoot").hidden      = false;

  document.getElementById("userInitial").textContent    = username.charAt(0).toUpperCase();
  document.getElementById("expDate").value              = todayIso();
  document.getElementById("incDate").value              = todayIso();
  document.getElementById("monthLabel").textContent     = monthLabel(currentMonth);

  buildCatFilter();
  buildChips("expChips", EXP_CATS, selectedExpCat, id => { selectedExpCat = id; });
  buildChips("incChips", INC_CATS, selectedIncCat, id => { selectedIncCat = id; });

  if (!startApp._listenersAttached) { attachAppListeners(); startApp._listenersAttached = true; }

  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
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

  // Tabs
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
    });
  });

  // Expense form
  document.getElementById("expenseForm").addEventListener("submit", e => {
    e.preventDefault();
    const amount = Number(document.getElementById("expAmount").value);
    if (!amount || amount <= 0) return;
    expenses.push({ id: crypto.randomUUID(), amount, category: selectedExpCat,
      date: document.getElementById("expDate").value,
      note: document.getElementById("expNote").value.trim(), createdAt: Date.now() });
    persist(KEY.expenses, expenses);
    document.getElementById("expAmount").value = document.getElementById("expNote").value = "";
    renderAll();
  });

  // Income form
  document.getElementById("incomeForm").addEventListener("submit", e => {
    e.preventDefault();
    const amount = Number(document.getElementById("incAmount").value);
    if (!amount || amount <= 0) return;
    income.push({ id: crypto.randomUUID(), amount, category: selectedIncCat,
      date: document.getElementById("incDate").value,
      note: document.getElementById("incNote").value.trim(), createdAt: Date.now() });
    persist(KEY.income, income);
    document.getElementById("incAmount").value = document.getElementById("incNote").value = "";
    renderAll();
  });

  document.getElementById("catFilter").addEventListener("change", renderAll);
  document.getElementById("exportBtn").addEventListener("click", exportCsv);

  // Settings
  document.getElementById("settingsBtn").addEventListener("click", openSettings);
  document.getElementById("closeSettings").addEventListener("click", closeSettings);
  document.getElementById("settingsModal").addEventListener("click", e => { if (e.target === e.currentTarget) closeSettings(); });
  document.getElementById("manageFixedBtn").addEventListener("click", openSettings);

  document.getElementById("recurringForm").addEventListener("submit", e => {
    e.preventDefault();
    const name     = document.getElementById("recName").value.trim();
    const amount   = Number(document.getElementById("recAmount").value);
    const category = document.getElementById("recCategory").value;
    if (!name || !amount) return;
    recurring.push({ id: crypto.randomUUID(), name, amount, category });
    persist(KEY.recurring, recurring);
    document.getElementById("recName").value = document.getElementById("recAmount").value = "";
    buildRecurringList();
  });

  document.getElementById("deleteAllBtn").addEventListener("click", () => {
    if (!confirm(`¿Borrar todos los datos de ${currentUser}? No se puede deshacer.`)) return;
    expenses = []; income = []; budgets = {}; recurring = []; loans = [];
    [KEY.expenses, KEY.income, KEY.budgets, KEY.recurring, KEY.settings, KEY.loans].forEach(k => localStorage.removeItem(k));
    document.getElementById("settingsModal").hidden = true;
    renderAll();
  });

  // Face ID setup
  document.getElementById("setupBiometricBtn").addEventListener("click", async () => {
    const btn = document.getElementById("setupBiometricBtn");
    const hint = document.getElementById("biometricHint");
    btn.disabled = true; btn.style.opacity = ".6";
    try {
      await registerPasskey(currentUser);
      hint.textContent = "Face ID configurado. Podés quitarlo si querés.";
      btn.hidden = true; document.getElementById("removeBiometricBtn").hidden = false;
    } catch (err) {
      hint.textContent = err.name === "NotAllowedError" ? "Cancelado. Intentá de nuevo." : "Error: " + err.message;
    } finally { btn.disabled = false; btn.style.opacity = ""; }
  });

  document.getElementById("removeBiometricBtn").addEventListener("click", () => {
    if (!confirm("¿Quitar Face ID?")) return;
    removePasskey(currentUser);
    document.getElementById("biometricHint").textContent = "Configurá Face ID para no ingresar tu contraseña cada día.";
    document.getElementById("setupBiometricBtn").hidden = false;
    document.getElementById("removeBiometricBtn").hidden = true;
  });

  // Logout
  document.getElementById("logoutBtn").addEventListener("click", () => {
    if (!confirm(`¿Cerrar sesión de ${currentUser}?`)) return;
    clearSession(); location.reload();
  });

  // ── Loans ──────────────────────────────────────────────────

  // Loans overview banner → scroll to section
  document.getElementById("loansOverview").addEventListener("click", () => {
    document.getElementById("loansPanel").scrollIntoView({ behavior: "smooth" });
  });

  // Toggle new loan form
  document.getElementById("addLoanToggle").addEventListener("click", () => {
    const form = document.getElementById("newLoanForm");
    form.hidden = !form.hidden;
    if (!form.hidden) {
      document.getElementById("loanDate").value = todayIso();
      document.getElementById("loanAmount").focus();
    }
  });

  // Save new loan
  document.getElementById("saveLoanBtn").addEventListener("click", () => {
    const amount = Number(document.getElementById("loanAmount").value);
    const person = document.getElementById("loanPerson").value.trim();
    const note   = document.getElementById("loanNote").value.trim();
    const date   = document.getElementById("loanDate").value;
    if (!amount || amount <= 0 || !person) return;

    loans.push({ id: crypto.randomUUID(), person, amount, date, note, createdAt: Date.now(), repayments: [], settled: false });
    persist(KEY.loans, loans);

    document.getElementById("loanAmount").value = "";
    document.getElementById("loanPerson").value = "";
    document.getElementById("loanNote").value   = "";
    document.getElementById("newLoanForm").hidden = true;
    renderLoans();
  });
}

// ════════════════════════════════════════════════════════════
// LOGIN SCREEN UI
// ════════════════════════════════════════════════════════════

function showBiometricMode(username) {
  document.getElementById("passwordMode").hidden   = true;
  document.getElementById("biometricMode").hidden  = false;
  document.getElementById("bioInitial").textContent = username.charAt(0).toUpperCase();
  document.getElementById("bioName").textContent    = username;
  document.getElementById("biometricError").hidden  = true;
}

function showPasswordMode() {
  document.getElementById("biometricMode").hidden = true;
  document.getElementById("passwordMode").hidden  = false;
}

document.getElementById("loginForm").addEventListener("submit", e => {
  e.preventDefault();
  const user = document.getElementById("loginUser").value.trim();
  const pass = document.getElementById("loginPass").value;
  if (!tryLogin(user, pass)) { document.getElementById("loginError").hidden = false; return; }
  saveSession(user); startApp(user);
});

document.getElementById("biometricBtn").addEventListener("click", async () => {
  const btn     = document.getElementById("biometricBtn");
  const errEl   = document.getElementById("biometricError");
  const lastUser = getLastUser();
  if (!lastUser) { showPasswordMode(); return; }
  btn.disabled = true; btn.style.opacity = ".6"; errEl.hidden = true;
  try {
    await verifyPasskey(lastUser);
    saveSession(lastUser); startApp(lastUser);
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = err.name === "NotAllowedError" ? "Cancelado. Intentá de nuevo." : "No se pudo verificar. Usá tu contraseña.";
  } finally { btn.disabled = false; btn.style.opacity = ""; }
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

document.getElementById("showRegisterBtn").addEventListener("click", () => {
  document.getElementById("loginPanel").hidden    = true;
  document.getElementById("registerPanel").hidden = false;
});

document.getElementById("backToLoginBtn").addEventListener("click", () => {
  document.getElementById("registerPanel").hidden = true;
  document.getElementById("loginPanel").hidden    = false;
});

document.getElementById("registerForm").addEventListener("submit", e => {
  e.preventDefault();
  const user  = document.getElementById("regUser").value.trim();
  const pass  = document.getElementById("regPass").value;
  const pass2 = document.getElementById("regPass2").value;
  const errEl = document.getElementById("registerError");
  if (!user || user.length < 2) { errEl.textContent = "Mínimo 2 caracteres."; errEl.hidden = false; return; }
  if (pass.length < 4) { errEl.textContent = "Contraseña mínimo 4 caracteres."; errEl.hidden = false; return; }
  if (pass !== pass2)  { errEl.textContent = "Las contraseñas no coinciden.";   errEl.hidden = false; return; }
  const err = createAccount(user, pass);
  if (err) { errEl.textContent = err; errEl.hidden = false; return; }
  saveSession(user); startApp(user);
});

// ════════════════════════════════════════════════════════════
// ENTRY POINT
// ════════════════════════════════════════════════════════════

// Pre-create your two accounts (only runs if they don't exist yet)
(function seedAccounts() {
  const users = loadUsers();
  if (!users["taisiña"])  createAccount("Taisiña",  "Taisonlybirdies1");
  if (!users["ikersiño"]) createAccount("Ikersiño", "8790");
})();

// Start: valid same-day session → go straight to app
const activeSession = getSession();
if (activeSession) {
  startApp(activeSession);
} else {
  const lastUser = getLastUser();
  if (lastUser && hasPasskey(lastUser)) {
    showBiometricMode(lastUser);
  } else {
    if (lastUser) document.getElementById("loginUser").value = lastUser;
    showPasswordMode();
  }
}
