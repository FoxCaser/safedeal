const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const state = {
  currentReviewArchive: null,
  currentEvidence: null,
  currentReport: null,
  currentInput: "",
  currentShare: null,
  type: "seller",
  screenshotFile: null,
  screenshotOcrText: ""
};

const titles = {
  home: "Перевіряй. Аналізуй. Уникай шахраїв.",
  reports: "База скарг",
  history: "Історія перевірок",
  profile: "Профіль",
};

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getClientId() {
  const key = "safedeal_client_id_v1";
  let id = localStorage.getItem(key) || "";
  if (!/^[a-zA-Z0-9_-]{12,80}$/.test(id)) {
    const random = globalThis.crypto?.randomUUID
      ? globalThis.crypto.randomUUID().replaceAll("-", "")
      : `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
    id = `sd_${random}`.slice(0, 70);
    localStorage.setItem(key, id);
  }
  return id;
}

async function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("x-client-id", getClientId());
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  return fetch(url, { ...options, headers, credentials: "same-origin" });
}

function showPage(id) {
  $$(".page").forEach((p) => p.classList.toggle("active", p.id === id));
  $$('[data-page]').forEach((b) => b.classList.toggle("active", b.dataset.page === id));
  $("#pageTitle").textContent = titles[id] || titles.home;
  window.scrollTo({ top: 0, behavior: "smooth" });

  if (id === "reports") loadReports().catch(console.error);
  if (id === "history") loadHistory().catch(console.error);
  if (id === "profile") loadProfile().catch(console.error);
}

function updateCheckHint() {
  const hint = $("#checkHint");
  const input = $("#checkInput");
  if (!hint || !input) return;
  const hints = {
    seller: "Встав дані продавця, оголошення, реквізити контакту або текст переписки.",
    job: "Встав текст вакансії, умови роботи, @username або посилання роботодавця.",
    link: "Встав повне http:// або https:// посилання.",
    contact: "Встав @username, t.me/username або приватне t.me/+... запрошення. SafeDeal перевірить публічне прев’ю та базу скарг.",
    phone: "Встав номер телефону. SafeDeal нормалізує його та перевірить точні збіги у модерованій базі скарг.",
    text: "Встав підозрілий текст або завантаж скріншот — OCR розпізнає українську та англійську.",
    facebook: "Встав посилання на Facebook-профіль, сторінку, групу або публікацію.",
    instagram: "Встав @username або повне посилання Instagram.",
    whatsapp: "Встав номер телефону або офіційне wa.me / WhatsApp-посилання.",
    viber: "Встав номер телефону або офіційне Viber-посилання.",
    olx: "Встав посилання на OLX-оголошення / продавця або дані продавця."
  };
  const placeholders = {
    seller: "Встав дані продавця або переписку...",
    job: "Встав текст вакансії або контакт роботодавця...",
    link: "https://example.com/...",
    contact: "@username або https://t.me/username",
    phone: "+380 67 123 45 67",
    text: "Встав текст повідомлення або завантаж скрін...",
    facebook: "https://facebook.com/...",
    instagram: "@username або https://instagram.com/username",
    whatsapp: "+380... або https://wa.me/...",
    viber: "+380... або Viber-посилання",
    olx: "https://www.olx.ua/d/uk/obyavlenie/..."
  };
  hint.textContent = hints[state.type] || hints.seller;
  input.placeholder = placeholders[state.type] || placeholders.seller;
}

function selectType(type) {
  state.type = type;
  $$(".check-tab").forEach((b) => b.classList.toggle("active", b.dataset.type === type));
  updateCheckHint();
  showPage("home");
  setTimeout(() => $("#quickCheck").scrollIntoView({ behavior: "smooth", block: "start" }), 50);
}

$$('[data-page]').forEach((btn) => btn.addEventListener("click", () => showPage(btn.dataset.page)));
$$('[data-check]').forEach((btn) => btn.addEventListener("click", () => selectType(btn.dataset.check)));
$$(".check-tab").forEach((btn) => btn.addEventListener("click", () => selectType(btn.dataset.type)));
updateCheckHint();

const focusCheck = document.querySelector("[data-focus-check]");
if (focusCheck) {
  focusCheck.addEventListener("click", () => {
    showPage("home");
    setTimeout(() => $("#quickCheck").scrollIntoView({ behavior: "smooth" }), 50);
  });
}

function setScoreVisual(score, level) {
  const ring = $("#scoreRing");
  const color =
    level === "very-high" ? "#ff5d67" :
    level === "high" ? "#ff7a59" :
    level === "medium" ? "#ffbf4d" :
    "#37d98f";

  ring.style.background = `conic-gradient(${color} 0 ${score}%, #17263a ${score}% 100%)`;
  $("#scoreLabel").style.color = color;
}

function getLocalHistory() {
  try {
    const raw = localStorage.getItem("safedeal_history_v1");
    const items = raw ? JSON.parse(raw) : [];
    return Array.isArray(items) ? items : [];
  } catch {
    return [];
  }
}

function saveLocalHistory(report, input) {
  const items = getLocalHistory();
  items.unshift({
    id: report.id,
    type: report.type,
    input: String(input).slice(0, 240),
    score: report.score,
    level: report.level,
    label: report.label,
    createdAt: new Date().toISOString()
  });
  localStorage.setItem("safedeal_history_v1", JSON.stringify(items.slice(0, 30)));
}

async function migrateLocalHistory() {
  if (localStorage.getItem("safedeal_history_cloud_migrated_v1") === "1") return;
  const items = getLocalHistory();
  if (!items.length) {
    localStorage.setItem("safedeal_history_cloud_migrated_v1", "1");
    return;
  }
  try {
    const res = await apiFetch("/api/history/import", {
      method: "POST",
      body: JSON.stringify({ items })
    });
    const data = await res.json();
    if (res.ok && data.ok) localStorage.setItem("safedeal_history_cloud_migrated_v1", "1");
  } catch {}
}

function renderHistoryItems(items, source = "cloud") {
  const wrap = $("#historyList");
  if (!wrap) return;

  if (!items.length) {
    wrap.innerHTML = `<div class="empty-state">Історія поки порожня. Виконай першу перевірку.</div>`;
    return;
  }

  wrap.innerHTML = items.map((item) => {
    const createdAt = item.created_at || item.createdAt;
    const input = item.input_preview || item.input || "";
    const date = new Date(createdAt);
    const shownDate = Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("uk-UA");
    return `
      <article class="history-item">
        <div class="history-main">
          <span class="history-type">${escapeHtml(typeLabel(item.type))}</span>
          <h4>${escapeHtml(input)}</h4>
          <small>${escapeHtml(shownDate)}${source === "cloud" ? " · PostgreSQL" : " · цей пристрій"}</small>
          <button class="history-recheck" data-recheck="${escapeHtml(input)}" data-recheck-type="${escapeHtml(item.type || "seller")}">Перевірити знову</button>
        </div>
        <div class="history-score">${Number(item.score) || 0}<span>/100</span></div>
      </article>
    `;
  }).join("");
}

async function loadHistory() {
  const wrap = $("#historyList");
  const sync = $("#historySyncStatus");
  if (wrap) wrap.innerHTML = `<div class="empty-state">Завантажуємо історію…</div>`;
  if (sync) sync.textContent = "Синхронізація з базою…";

  await migrateLocalHistory();
  try {
    const res = await apiFetch("/api/history", { cache: "no-store" });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "history_failed");
    renderHistoryItems(data.items || [], "cloud");
    if (sync) sync.textContent = data.syncedAcrossDevices
      ? "Історія синхронізується через акаунт між пристроями ✅"
      : "Історія зберігається в PostgreSQL для цього браузера.";
  } catch (e) {
    renderHistoryItems(getLocalHistory(), "local");
    if (sync) sync.textContent = "База тимчасово недоступна — показано локальну історію цього пристрою.";
  }
}

const clearHistory = $("#clearHistory");
if (clearHistory) {
  clearHistory.addEventListener("click", async () => {
    if (!confirm("Очистити історію перевірок цього профілю?")) return;
    clearHistory.disabled = true;
    try {
      await apiFetch("/api/history", { method: "DELETE" });
      localStorage.removeItem("safedeal_history_v1");
      localStorage.setItem("safedeal_history_cloud_migrated_v1", "1");
      await loadHistory();
      loadProfile().catch(()=>{});
    } finally {
      clearHistory.disabled = false;
    }
  });
}

const historyList = $("#historyList");
if (historyList) {
  historyList.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-recheck]");
    if (!btn) return;
    const input = btn.dataset.recheck || "";
    const type = btn.dataset.recheckType || "seller";
    state.type = type;
    $("#checkInput").value = input;
    $$(".check-tab").forEach((b) => b.classList.toggle("active", b.dataset.type === type));
    showPage("home");
    setTimeout(() => $("#runCheck").click(), 100);
  });
}

function renderAccount(account = {}) {
  const loggedIn = Boolean(account.authenticated);
  const guestBox = $("#authGuestBox");
  const userBox = $("#authUserBox");
  if (guestBox) guestBox.classList.toggle("hidden", loggedIn);
  if (userBox) userBox.classList.toggle("hidden", !loggedIn);
  if ($("#accountEmail")) $("#accountEmail").textContent = loggedIn ? (account.email || "") : "";
  if ($("#accountBadge")) $("#accountBadge").textContent = loggedIn ? "Синхронізація активна" : "Гостьовий профіль";
  if ($("#activeSessions")) $("#activeSessions").textContent = loggedIn ? String(Number(account.activeSessions) || 1) : "0";
  const copy = $("#profileCopy");
  if (copy) copy.textContent = loggedIn
    ? "Ти увійшов у SafeDeal. Історія перевірок і скарги синхронізуються між пристроями через PostgreSQL."
    : "Зараз це профіль цього браузера. Створи акаунт або увійди через email, щоб синхронізувати історію між телефоном і комп’ютером.";
}

function authErrorText(code) {
  const map = {
    invalid_email: "Введи правильну email-адресу.",
    weak_password: "Новий пароль: мінімум 10 символів, хоча б одна літера та одна цифра.",
    weak_new_password: "Новий пароль: мінімум 10 символів, хоча б одна літера та одна цифра.",
    email_exists: "Акаунт з таким email уже існує. Натисни «Увійти».",
    invalid_credentials: "Неправильний email або пароль.",
    login_temporarily_locked: "Забагато неправильних паролів. Вхід тимчасово заблоковано приблизно на 15 хвилин.",
    current_password_required: "Введи поточний пароль.",
    current_password_invalid: "Поточний пароль неправильний.",
    password_unchanged: "Новий пароль має відрізнятися від поточного.",
    auth_required: "Спочатку увійди в акаунт.",
    rate_limited: "Забагато спроб. Спробуй трохи пізніше.",
    database_unavailable: "База даних тимчасово недоступна."
  };
  return map[code] || "Не вдалося виконати дію. Спробуй ще раз.";
}

async function loadProfile() {
  const status = $("#profileStatus");
  if (status) status.textContent = "Завантажуємо профіль…";
  try {
    const res = await apiFetch("/api/profile", { cache: "no-store" });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "profile_failed");
    const p = data.profile || {};
    renderAccount(data.account || {});
    if ($("#profileNickname")) $("#profileNickname").value = p.nickname || "Гість";
    if ($("#profileChecks")) $("#profileChecks").textContent = Number(p.check_count) || 0;
    if ($("#profileReports")) $("#profileReports").textContent = Number(p.report_count) || 0;
    if ($("#profilePending")) $("#profilePending").textContent = Number(p.pending_count) || 0;
    if ($("#profileApproved")) $("#profileApproved").textContent = Number(p.approved_count) || 0;
    if ($("#profileSince")) {
      const d = new Date(p.created_at);
      $("#profileSince").textContent = Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString("uk-UA");
    }
    if (status) status.textContent = data.account?.authenticated
      ? "Акаунт активний. Дані синхронізуються між пристроями ✅"
      : "Гостьовий профіль активний. Дані поки прив’язані до цього браузера.";
  } catch (e) {
    if (status) status.textContent = "Не вдалося завантажити профіль з бази.";
  }
}

async function runAuth(mode) {
  const email = $("#authEmail")?.value.trim() || "";
  const password = $("#authPassword")?.value || "";
  const authStatus = $("#authStatus");
  const loginBtn = $("#authLogin");
  const registerBtn = $("#authRegister");
  if (!email || !password) {
    if (authStatus) authStatus.textContent = "Введи email і пароль.";
    return;
  }
  if (loginBtn) loginBtn.disabled = true;
  if (registerBtn) registerBtn.disabled = true;
  if (authStatus) authStatus.textContent = mode === "register" ? "Створюємо акаунт…" : "Входимо…";
  try {
    const nickname = $("#profileNickname")?.value.trim() || "Гість";
    const res = await apiFetch(`/api/auth/${mode}`, {
      method: "POST",
      body: JSON.stringify({ email, password, nickname })
    });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "auth_failed");
    if ($("#authPassword")) $("#authPassword").value = "";
    if (authStatus) authStatus.textContent = mode === "register" ? "Акаунт створено ✅" : "Вхід успішний ✅";
    await loadProfile();
    loadHistory().catch(()=>{});
  } catch (error) {
    if (authStatus) authStatus.textContent = authErrorText(error.message);
  } finally {
    if (loginBtn) loginBtn.disabled = false;
    if (registerBtn) registerBtn.disabled = false;
  }
}

$("#authLogin")?.addEventListener("click", () => runAuth("login"));
$("#authRegister")?.addEventListener("click", () => runAuth("register"));
$("#authPassword")?.addEventListener("keydown", (e) => { if (e.key === "Enter") runAuth("login"); });
$("#authLogout")?.addEventListener("click", async () => {
  const btn = $("#authLogout");
  if (btn) btn.disabled = true;
  try {
    await apiFetch("/api/auth/logout", { method: "POST" });
    if ($("#authStatus")) $("#authStatus").textContent = "Ви вийшли з акаунта.";
    await loadProfile();
    loadHistory().catch(()=>{});
  } finally {
    if (btn) btn.disabled = false;
  }
});


const changePasswordBtn = $("#changePassword");
if (changePasswordBtn) {
  changePasswordBtn.addEventListener("click", async () => {
    const currentPassword = $("#currentPassword")?.value || "";
    const newPassword = $("#newPassword")?.value || "";
    const confirmPassword = $("#confirmNewPassword")?.value || "";
    const status = $("#securityStatus");
    if (!currentPassword || !newPassword || !confirmPassword) {
      if (status) status.textContent = "Заповни всі три поля пароля.";
      return;
    }
    if (newPassword !== confirmPassword) {
      if (status) status.textContent = "Нові паролі не збігаються.";
      return;
    }
    changePasswordBtn.disabled = true;
    if (status) status.textContent = "Змінюємо пароль…";
    try {
      const res = await apiFetch("/api/auth/change-password", {
        method: "POST",
        body: JSON.stringify({ currentPassword, newPassword })
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "password_change_failed");
      $("#currentPassword").value = "";
      $("#newPassword").value = "";
      $("#confirmNewPassword").value = "";
      if (status) status.textContent = "Пароль змінено ✅ Інші активні сесії завершено.";
      await loadProfile();
    } catch (error) {
      if (status) status.textContent = authErrorText(error.message);
    } finally {
      changePasswordBtn.disabled = false;
    }
  });
}

$("#authLogoutAll")?.addEventListener("click", async () => {
  if (!confirm("Вийти з SafeDeal на всіх пристроях, включно з цим?")) return;
  const btn = $("#authLogoutAll");
  const status = $("#securityStatus");
  btn.disabled = true;
  if (status) status.textContent = "Завершуємо всі сесії…";
  try {
    const res = await apiFetch("/api/auth/logout-all", { method: "POST" });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "logout_all_failed");
    if (status) status.textContent = `З усіх пристроїв виконано вихід ✅ Завершено сесій: ${Number(data.sessionsRevoked) || 0}.`;
    await loadProfile();
    loadHistory().catch(()=>{});
  } catch (error) {
    if (status) status.textContent = authErrorText(error.message);
  } finally {
    btn.disabled = false;
  }
});

$("#forgotPassword")?.addEventListener("click", async () => {
  const email = $("#authEmail")?.value.trim() || "";
  const status = $("#authStatus");
  if (!email) {
    if (status) status.textContent = "Спочатку введи email акаунта.";
    return;
  }
  const btn = $("#forgotPassword");
  btn.disabled = true;
  if (status) status.textContent = "Створюємо запит на відновлення…";
  try {
    const res = await apiFetch("/api/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email })
    });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "reset_request_failed");
    if (status) status.textContent = data.emailDeliveryConfigured
      ? "Якщо акаунт існує, лист для відновлення надіслано."
      : "Запит підготовлено ✅ Надсилання листа активуємо після підключення поштового сервісу.";
  } catch (error) {
    if (status) status.textContent = authErrorText(error.message);
  } finally {
    btn.disabled = false;
  }
});

const saveProfileBtn = $("#saveProfile");
if (saveProfileBtn) {
  saveProfileBtn.addEventListener("click", async () => {
    const nickname = $("#profileNickname").value.trim();
    const status = $("#profileStatus");
    if (nickname.length < 2) {
      status.textContent = "Ім’я має містити щонайменше 2 символи.";
      return;
    }
    saveProfileBtn.disabled = true;
    status.textContent = "Зберігаємо…";
    try {
      const res = await apiFetch("/api/profile", {
        method: "PATCH",
        body: JSON.stringify({ nickname })
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "profile_update_failed");
      status.textContent = "Ім’я збережено ✅";
    } catch {
      status.textContent = "Не вдалося зберегти ім’я.";
    } finally {
      saveProfileBtn.disabled = false;
    }
  });
}

let ocrLoaderPromise = null;
async function ensureOcrEngine() {
  if (globalThis.Tesseract?.recognize) return true;
  if (ocrLoaderPromise) return ocrLoaderPromise;
  const sources = [
    "https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js",
    "https://unpkg.com/tesseract.js@5.1.1/dist/tesseract.min.js"
  ];
  ocrLoaderPromise = (async () => {
    for (const src of sources) {
      try {
        await new Promise((resolve, reject) => {
          const script = document.createElement("script");
          script.src = src;
          script.async = true;
          script.onload = resolve;
          script.onerror = reject;
          document.head.appendChild(script);
        });
        if (globalThis.Tesseract?.recognize) return true;
      } catch {}
    }
    return false;
  })();
  return ocrLoaderPromise;
}

async function recognizeScreenshot(file) {
  const status = $("#ocrStatus");
  if (!file) return "";
  if (!(await ensureOcrEngine())) throw new Error("ocr_engine_unavailable");
  if (!String(file.type || "").startsWith("image/")) throw new Error("ocr_not_image");
  if (file.size > 8 * 1024 * 1024) throw new Error("ocr_file_too_large");

  if (status) {
    status.classList.remove("hidden", "error", "success");
    status.textContent = "OCR: готуємо розпізнавання…";
  }

  const result = await globalThis.Tesseract.recognize(file, "ukr+eng", {
    logger: (message) => {
      if (!status) return;
      if (message.status === "recognizing text") {
        const pct = Math.max(0, Math.min(100, Math.round((Number(message.progress) || 0) * 100)));
        status.textContent = `OCR: розпізнаємо текст — ${pct}%`;
      } else if (message.status) {
        status.textContent = `OCR: ${String(message.status).replaceAll("_", " ")}…`;
      }
    }
  });

  const text = String(result?.data?.text || "").replace(/\n{3,}/g, "\n\n").trim();
  if (status) {
    status.classList.add(text ? "success" : "error");
    status.textContent = text
      ? `OCR готовий ✅ Розпізнано ${text.length} символів. Перевір текст нижче — його можна відредагувати.`
      : "OCR не знайшов читабельного тексту. Спробуй чіткіший скрін.";
  }
  return text;
}

$("#runCheck").addEventListener("click", async () => {
  let input = $("#checkInput").value.trim();
  const file = state.screenshotFile || $("#screenshotInput")?.files?.[0] || null;
  let historyPreview = input;

  const button = $("#runCheck");
  button.disabled = true;

  try {
    if (file) {
      button.textContent = "Розпізнаємо скрін...";
      const ocrText = state.screenshotOcrText || await recognizeScreenshot(file);
      if (ocrText) {
        state.screenshotOcrText = ocrText;
        if (!input) input = ocrText;
        else if (!input.includes(ocrText)) input = `${input}\n\n${ocrText}`;
        input = input.slice(0, 12000);
        $("#checkInput").value = input;
        historyPreview = `Скріншот OCR: ${String(file.name || "зображення").slice(0, 120)}`;
      }
    }

    if (!input) {
      $("#checkInput").focus();
      throw new Error(file ? "ocr_no_text" : "input_required");
    }

    button.textContent = "Перевіряємо...";
    const res = await apiFetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: state.type, input, historyPreview })
    });

    const data = await res.json();
    if (!data.ok) throw new Error(data.error || "check_failed");

    const r = data.report;
    state.currentReport = r; state.currentInput = input; state.currentShare = null;
    $("#reportId").textContent = r.id; $("#scoreValue").textContent = r.score; $("#scoreLabel").textContent = r.label;
    $("#riskHeadline").textContent = r.label; $("#riskScoreSecondary").textContent = `${r.score}/100`;
    $("#schemeLabel").textContent = r.scamScheme?.label || "Схему не визначено";
    $("#schemeConfidence").textContent = r.scamScheme?.confidence ? `Надійність сигналу: ${r.scamScheme.confidence}` : "";
    state.currentEvidence = r.evidence || { items: [] }; $("#evidenceCount").textContent = `${Number(r.evidence?.total || 0)} сигналів`;
    const changeBox=$("#changeBox");
    if(r.changesSinceLastCheck?.changed){$("#changeList").innerHTML=r.changesSinceLastCheck.items.map(x=>`<div>• ${escapeHtml(x)}</div>`).join("");changeBox.classList.remove("hidden");}
    else if(r.changesSinceLastCheck?.firstCheck){$("#changeList").innerHTML=`<div>Це перший збережений знімок цього об’єкта в SafeDeal.</div>`;changeBox.classList.remove("hidden");}
    else changeBox.classList.add("hidden");
    const relatedBox=$("#relatedBox");
    if(r.relatedObjects?.length){$("#relatedList").innerHTML=r.relatedObjects.slice(0,6).map(x=>`<div class="related-item"><b>${escapeHtml(x.type)}</b><span>${escapeHtml(x.targetKey)}</span><small>${escapeHtml(x.note)}</small></div>`).join("");relatedBox.classList.remove("hidden");}else relatedBox.classList.add("hidden");
    $("#watchBtn").textContent=r.isWatched?"✓ SafeDeal Watch активний":"👁 Стежити";

    const verdict = r.verdict || {};
    const verdictBox = $("#verdictBox");
    const verdictKind = verdict.kind || (r.level === "low" ? "ok" : "warning");
    verdictBox.className = `verdict-box ${verdictKind}`;
    $("#verdictIcon").textContent =
      verdictKind === "danger" ? "!" :
      verdictKind === "warning" ? "!" :
      verdictKind === "limited" ? "?" : "✓";
    $("#verdictTitle").textContent = verdict.title || r.label;
    $("#verdictText").textContent = verdict.text || "";
    $("#verdictEvidence").textContent = verdict.evidence || "";

    const plainSummaryBox = $("#plainSummaryBox");
    const plainSummaryText = $("#plainSummaryText");
    if (r.plainSummary) {
      plainSummaryText.textContent = r.plainSummary;
      plainSummaryBox.classList.remove("hidden");
    } else {
      plainSummaryText.textContent = "";
      plainSummaryBox.classList.add("hidden");
    }

    state.currentReviewArchive = r.reviewArchive || null;
    const reviewArchiveBtn = $("#reviewArchiveBtn");
    const reviewArchiveCount = $("#reviewArchiveCount");
    if (r.reviewArchive?.available) {
      reviewArchiveCount.textContent = `${Number(r.reviewArchive.confirmedCount) || 0} підтверджених`;
      reviewArchiveBtn.classList.remove("hidden");
    } else {
      reviewArchiveBtn.classList.add("hidden");
    }

    const reasonIsOnlyNoSignal = r.reasons.length === 1 &&
      /не знайдено явних типових сигналів/i.test(r.reasons[0]);
    $("#reasonList").innerHTML = r.reasons.map((x) =>
      `<div class="reason ${reasonIsOnlyNoSignal ? "reason-ok" : ""}">${reasonIsOnlyNoSignal ? "✓" : "!"} <span>${escapeHtml(x)}</span></div>`
    ).join("");
    $("#actionList").innerHTML = r.actions.map((x) => `<div class="action">✓ <span>${escapeHtml(x)}</span></div>`).join("");
    $("#disclaimer").textContent = r.disclaimer;
    setScoreVisual(r.score, r.level);

    const techBox = $("#technicalBox");
    const techGrid = $("#technicalGrid");
    const factsList = $("#factsList");

    const t = r.technical;
    if (t) {
      const ageText = Number.isFinite(t.domainAgeDays) ? `${t.domainAgeDays} дн.` : "Не підтверджено";
      const webRiskText =
        t.webRiskConfigured === false
          ? "Не підключено"
          : t.webRiskMatches > 0
            ? `Є збіг (${t.webRiskMatches})`
            : t.webRiskOk
              ? "Відомих збігів немає"
              : "Тимчасово недоступно";

      const phishTankText =
        t.phishTankOk
          ? (t.phishTankInDatabase && t.phishTankVerified && t.phishTankValid
              ? "Підтверджений фішинг"
              : t.phishTankInDatabase
                ? "Є запис у базі"
                : "Збігів немає")
          : t.phishTankRateLimited
            ? "Ліміт запитів"
            : "Тимчасово недоступно";

      const phishDestroyText =
        t.phishDestroyOk
          ? (t.phishDestroyThreat
              ? `Загроза: ${t.phishDestroySeverity || "risk"} (${t.phishDestroyRiskScore || 0}/100)`
              : "Збігів немає")
          : "Тимчасово недоступно";

      const urlHausText =
        t.urlHausConfigured === false
          ? "Не підключено"
          : t.urlHausAuthError
            ? "Помилка Auth-Key"
            : !t.urlHausOk
              ? "Тимчасово недоступно"
              : t.urlHausMatch
                ? (t.urlHausUrlStatus === "online" ? "Відомий malware URL (активний)" : "Відомий malware URL")
                : t.urlHausHostMatch
                  ? `На хості є malware URL (${t.urlHausHostUrlCount || 1})`
                  : "Збігів немає";

      const threatFoxText =
        t.threatFoxConfigured === false
          ? "Не підключено"
          : t.threatFoxAuthError
            ? "Помилка Auth-Key"
            : !t.threatFoxOk
              ? "Тимчасово недоступно"
              : t.threatFoxMatch
                ? [
                    t.threatFoxMatchType === "url" ? "IOC для URL" : "IOC для домену",
                    t.threatFoxMalware ? `— ${t.threatFoxMalware}` : "",
                    Number.isFinite(t.threatFoxConfidence) ? `(${t.threatFoxConfidence}%)` : ""
                  ].filter(Boolean).join(" ")
                : "Збігів немає";

      const spoofText =
        t.brandImpersonation
          ? `Схоже на ${t.brandTarget || "відомий бренд"}`
          : t.mixedScript
            ? "Змішані алфавіти"
            : t.punycode
              ? "Punycode"
              : "Ознак підміни немає";

      const structureFlags = [];
      if (t.bidiOrInvisible) structureFlags.push("невидимі/bidi символи");
      if (t.encodedAuthority) structureFlags.push("кодована адреса");
      if (t.nonStandardPort) structureFlags.push("нестандартний порт");
      if (t.longHostname) structureFlags.push("дуже довгий домен");
      else if (t.longUrl) structureFlags.push("дуже довгий URL");
      const structureText = structureFlags.length ? structureFlags.join(", ") : "Без явних трюків";

      const dnsText =
        t.dnsOk === false
          ? "Домен не знайдено через DNS"
          : Array.isArray(t.dns) && t.dns.length
            ? `${t.dns.length} адрес(и)`
            : "DNS-відповідь порожня";

      const scanUnavailableText =
        t.dnsOk === false
          ? "Неможливо перевірити — домен не відповідає через DNS"
          : t.pageScanError === "private_address"
            ? "Неможливо перевірити — приватна адреса"
            : "Неможливо перевірити — сайт не відповів";

      const sslText =
        t.finalProtocol !== "https"
          ? "Немає HTTPS"
          : !t.pageScanOk
            ? scanUnavailableText
            : t.tlsPresent === false
              ? "HTTPS є, але сертифікат не вдалося прочитати"
              : t.tlsAuthorized
                ? (t.tlsValidTo ? `Дійсний до ${new Date(t.tlsValidTo).toLocaleDateString("uk-UA")}` : "Дійсний")
                : "Проблема сертифіката";

      const redirectText =
        t.pageScanOk
          ? (t.redirectCount > 0 ? `${t.redirectCount} → ${t.finalHostname || "—"}` : "Немає")
          : scanUnavailableText;

      const forms = [];
      if (t.loginForm) forms.push("вхід");
      if (t.paymentForm) forms.push("оплата");
      if (t.otpField) forms.push("OTP");
      const formsText = t.pageScanOk
        ? (forms.length ? forms.join(", ") : "Чутливих форм не знайдено")
        : scanUnavailableText;

      const contentBrandText = !t.pageScanOk
        ? scanUnavailableText
        : t.pageBrandMismatch
          ? `Заявляє ${t.pageBrandTarget || "відомий бренд"} — домен інший`
          : t.pageBrandDetected && t.pageBrandOfficialDomain
            ? `${t.pageBrandTarget || "Бренд"} — офіційний домен`
            : "Явної підміни бренду не знайдено";

      const httpStatusText = t.pageScanOk && t.pageStatus
        ? String(t.pageStatus)
        : scanUnavailableText;

      techGrid.innerHTML = `
        <div class="tech-item"><span>🌐 Домен</span><b>${escapeHtml(t.hostname || "—")}</b></div>
        <div class="tech-item"><span>🔒 Протокол</span><b>${escapeHtml(String(t.protocol || "—").toUpperCase())}</b></div>
        <div class="tech-item"><span>🪞 Підміна домену</span><b>${escapeHtml(spoofText)}</b></div>
        <div class="tech-item"><span>🧬 Структура URL</span><b>${escapeHtml(structureText)}</b></div>
        <div class="tech-item"><span>📅 Вік домену</span><b>${escapeHtml(ageText)}</b></div>
        <div class="tech-item"><span>🛰 DNS</span><b>${escapeHtml(dnsText)}</b></div>
        <div class="tech-item"><span>🛡 Google Web Risk</span><b>${escapeHtml(webRiskText)}</b></div>
        <div class="tech-item"><span>🎣 PhishTank</span><b>${escapeHtml(phishTankText)}</b></div>
        <div class="tech-item"><span>🧨 PhishDestroy</span><b>${escapeHtml(phishDestroyText)}</b></div>
        <div class="tech-item"><span>🦠 URLhaus</span><b>${escapeHtml(urlHausText)}</b></div>
        <div class="tech-item"><span>🕷️ ThreatFox</span><b>${escapeHtml(threatFoxText)}</b></div>
        <div class="tech-item"><span>🔐 SSL/TLS</span><b>${escapeHtml(sslText)}</b></div>
        <div class="tech-item"><span>↪️ Редиректи</span><b>${escapeHtml(redirectText)}</b></div>
        <div class="tech-item"><span>🧾 Форми</span><b>${escapeHtml(formsText)}</b></div>
        <div class="tech-item"><span>🏷️ Бренд на сторінці</span><b>${escapeHtml(contentBrandText)}</b></div>
        <div class="tech-item"><span>📡 HTTP-статус</span><b>${escapeHtml(httpStatusText)}</b></div>
      `;

      factsList.innerHTML = (r.facts || [])
        .map((x) => `<div class="fact">✓ <span>${escapeHtml(x)}</span></div>`)
        .join("");

      techBox.classList.remove("hidden");
    } else {
      techGrid.innerHTML = "";
      factsList.innerHTML = (r.facts || [])
        .map((x) => `<div class="fact">✓ <span>${escapeHtml(x)}</span></div>`)
        .join("");
      techBox.classList.toggle("hidden", !(r.facts || []).length);
    }

    if (r.telegram) {
      const tg = r.telegram;
      const kindMap = {
        invite: "Приватне запрошення",
        bot: "Бот",
        channel: "Публічний канал",
        group: "Публічна група",
        account_or_channel: "Акаунт / канал"
      };
      const previewText = tg.kind === "invite"
        ? "Обмежене — приватне запрошення"
        : tg.publicPreviewOk
          ? "Публічне прев’ю доступне"
          : "Публічне прев’ю не підтверджено";
      const postsText = tg.kind === "invite"
        ? "Недоступні для приватного запрошення"
        : tg.publicPostsOk
          ? `Проаналізовано ${tg.recentPostsCount || 0}`
          : "Не вдалося прочитати";
      const titleText = tg.title ? String(tg.title).slice(0, 120) : "—";
      techGrid.insertAdjacentHTML("afterbegin", `
        <div class="tech-item telegram-tech"><span>✈ Telegram</span><b>${escapeHtml(tg.target || "—")}</b></div>
        <div class="tech-item telegram-tech"><span>👤 Тип</span><b>${escapeHtml(kindMap[tg.kind] || "Акаунт / канал")}</b></div>
        <div class="tech-item telegram-tech"><span>📰 Публічні пости</span><b>${escapeHtml(postsText)}</b></div>
        <div class="tech-item telegram-tech"><span>👁 Публічне прев’ю</span><b>${escapeHtml(previewText)}</b></div>
        <div class="tech-item telegram-tech"><span>🏷 Назва</span><b>${escapeHtml(titleText)}</b></div>
      `);
      techBox.classList.remove("hidden");
    }

    if (r.platform) {
      const p = r.platform;
      techGrid.insertAdjacentHTML("afterbegin", `
        <div class="tech-item platform-tech"><span>🌐 Платформа</span><b>${escapeHtml(p.label || p.type || "—")}</b></div>
        <div class="tech-item platform-tech"><span>🎯 Ціль</span><b>${escapeHtml(p.normalized || "—")}</b></div>
        <div class="tech-item platform-tech"><span>🔎 Режим</span><b>${p.limited ? "Часткова публічна перевірка" : "Публічна перевірка"}</b></div>
      `);
      techBox.classList.remove("hidden");
    }

    saveLocalHistory(r, historyPreview || input);

    const card = $("#resultCard");
    card.classList.remove("hidden");
    card.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    console.error(e);
    const status = $("#ocrStatus");
    const messages = {
      ocr_engine_unavailable: "OCR-модуль не завантажився. Онови сторінку та спробуй ще раз.",
      ocr_not_image: "Вибраний файл не є зображенням.",
      ocr_file_too_large: "Скрін завеликий. Максимум 8 МБ.",
      ocr_no_text: "На скріні не вдалося розпізнати текст.",
      input_required: "Встав текст або завантаж скріншот."
    };
    const message = messages[e.message] || "Не вдалося виконати перевірку.";
    if (status && String(e.message).startsWith("ocr_")) {
      status.classList.remove("hidden", "success");
      status.classList.add("error");
      status.textContent = message;
    } else {
      alert(message);
    }
  } finally {
    button.disabled = false;
    button.textContent = "⌕ Перевірити";
  }
});

async function loadAlerts() {
  const res = await fetch("/api/community-alerts");
  const data = await res.json();

  const items = Array.isArray(data.items) ? data.items : [];
  if (!items.length) {
    $("#alertsGrid").innerHTML = `<div class="empty-state">Поки немає опублікованих попереджень.</div>`;
    return;
  }
  $("#alertsGrid").innerHTML = items.map((item) => `
    <article class="alert-card">
      <div class="alert-head">
        <span class="risk-badge ${escapeHtml(item.level)}">${escapeHtml(item.label)}</span>
        <small>${escapeHtml(item.updatedAt)}</small>
      </div>
      <h4>${escapeHtml(item.target)}</h4>
      <p>${escapeHtml(item.reasons?.[0] || "Є сигнали ризику")}</p>
      <div class="alert-score">${Number(item.score) || 0}/100</div>
    </article>
  `).join("");
}

function typeLabel(type) {
  return ({
    seller: "Продавець",
    job: "Вакансія",
    link: "Посилання",
    contact: "Telegram",
    phone: "Номер телефону",
    text: "Текст",
    facebook: "Facebook",
    instagram: "Instagram",
    whatsapp: "WhatsApp",
    viber: "Viber",
    olx: "OLX"
  })[type] || type;
}

async function loadReports() {
  const search = $("#reportSearch");
  const type = $("#reportTypeFilter");
  const results = $("#reportResults");
  const meta = $("#reportSearchMeta");
  if (!results || !meta) return;

  const q = search?.value.trim() || "";
  const selectedType = type?.value || "all";
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (selectedType !== "all") params.set("type", selectedType);

  meta.textContent = "Шукаємо...";

  const res = await fetch(`/api/reports?${params.toString()}`);
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || "reports_failed");

  meta.textContent = `Знайдено: ${data.items.length}. ${data.demo ? "Частина записів зараз демонстраційна." : ""}`;

  if (!data.items.length) {
    results.innerHTML = `<div class="empty-state">Збігів не знайдено.</div>`;
    return;
  }

  state.reportSearchItems = data.items;
  results.innerHTML = data.items.map((item, index) => `
    <article class="report-row report-row-clickable" data-report-index="${index}" tabindex="0" role="button" aria-label="Відкрити деталі скарги">
      <div class="report-row-top">
        <span class="report-type">${escapeHtml(typeLabel(item.type))}</span>
        <span class="report-status">${escapeHtml(item.statusLabel || "Перевірено")}</span>
      </div>
      <h4>${escapeHtml(item.target)}</h4>
      <p>${escapeHtml(item.reason || item.reasons?.[0] || "Є підтверджені сигнали ризику")}</p>
      <div class="report-row-foot"><small>${escapeHtml(item.updatedAt || "")}</small><span>Відкрити ›</span></div>
    </article>
  `).join("");
}


function openReviewArchiveModal() {
  const modal = $("#reviewArchiveModal");
  const archive = state.currentReviewArchive;
  if (!modal || !archive) return;
  $("#reviewArchiveConfirmed").textContent = Number(archive.confirmedCount) || 0;
  $("#reviewArchiveNote").textContent = archive.note || "SafeDeal показує тільки записи з доказами.";
  const items = Array.isArray(archive.items) ? archive.items : [];
  $("#reviewArchiveItems").innerHTML = items.length
    ? items.map((item) => `
      <article class="review-archive-item">
        <div><b>${escapeHtml(item.platform || "Джерело")}</b><span>Підтверджений архівний запис</span></div>
        <p>${escapeHtml(item.summary || item.archivedText || "Збережений текст відгуку")}</p>
        ${item.archivedText && item.archivedText !== item.summary ? `<blockquote>${escapeHtml(item.archivedText)}</blockquote>` : ""}
        <small>${item.firstSeenAt ? `Було видно: ${escapeHtml(new Date(item.firstSeenAt).toLocaleDateString("uk-UA"))}` : ""}${item.missingAt ? ` · Зникло/змінилося: ${escapeHtml(new Date(item.missingAt).toLocaleDateString("uk-UA"))}` : ""}</small>
      </article>`).join("")
    : `<div class="empty-state compact">Підтверджених видалених або прихованих відгуків не знайдено.</div>`;
  modal.classList.remove("hidden");
  document.body.classList.add("modal-open");
}

function closeModal(id) {
  const modal = $(id);
  if (modal) modal.classList.add("hidden");
  document.body.classList.remove("modal-open");
}

function openReportDetail(item) {
  if (!item) return;
  const modal = $("#reportDetailModal");
  const body = $("#reportDetailBody");
  if (!modal || !body) return;
  body.innerHTML = `
    <div class="report-detail-meta"><span>${escapeHtml(typeLabel(item.type))}</span><b>${escapeHtml(item.statusLabel || "Перевірено модерацією")}</b></div>
    <h4>${escapeHtml(item.target || "—")}</h4>
    <div class="report-detail-section"><small>Причина</small><p>${escapeHtml(item.reason || "Не вказано")}</p></div>
    <div class="report-detail-section"><small>Опис</small><p>${escapeHtml(item.details || "Додаткових деталей немає.")}</p></div>
    <div class="report-detail-bottom"><span>Код: ${escapeHtml(item.code || "—")}</span><span>${escapeHtml(item.updatedAt || "")}</span></div>
    <p class="sd-modal-note">Це модерована скарга користувача SafeDeal, а не автоматичне твердження про шахрайство.</p>`;
  modal.classList.remove("hidden");
  document.body.classList.add("modal-open");
}

$("#reviewArchiveBtn")?.addEventListener("click", openReviewArchiveModal);
$("#closeReviewArchive")?.addEventListener("click", () => closeModal("#reviewArchiveModal"));
$("#closeReportDetail")?.addEventListener("click", () => closeModal("#reportDetailModal"));

$("#reviewArchiveModal")?.addEventListener("click", (e) => {
  if (e.target.id === "reviewArchiveModal") closeModal("#reviewArchiveModal");
});
$("#reportDetailModal")?.addEventListener("click", (e) => {
  if (e.target.id === "reportDetailModal") closeModal("#reportDetailModal");
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeModal("#reviewArchiveModal");
    closeModal("#reportDetailModal");
  }
});

const reportResults = $("#reportResults");
if (reportResults) {
  const openFromEvent = (e) => {
    const row = e.target.closest?.("[data-report-index]");
    if (!row) return;
    const index = Number(row.dataset.reportIndex);
    openReportDetail(state.reportSearchItems?.[index]);
  };
  reportResults.addEventListener("click", openFromEvent);
  reportResults.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openFromEvent(e);
    }
  });
}

const searchReports = $("#searchReports");
if (searchReports) searchReports.addEventListener("click", () => loadReports().catch(console.error));

const reportSearch = $("#reportSearch");
if (reportSearch) {
  reportSearch.addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadReports().catch(console.error);
  });
}

const submitReport = $("#submitReport");
if (submitReport) {
  submitReport.addEventListener("click", async () => {
    const target = $("#reportTarget").value.trim();
    const type = $("#reportSubmitType").value;
    const reason = $("#reportReason").value.trim();
    const details = $("#reportDetails").value.trim();
    const status = $("#reportSubmitStatus");

    if (!target || !reason) {
      status.textContent = "Заповни об’єкт скарги та коротку причину.";
      status.className = "report-submit-status error";
      return;
    }

    submitReport.disabled = true;
    submitReport.textContent = "Надсилаємо...";
    status.textContent = "";

    try {
      const res = await apiFetch("/api/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, type, reason, details })
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "submit_failed");

      status.textContent = data.duplicate
        ? `Схожа скарга вже була надіслана нещодавно. Код: ${data.report.code}.`
        : data.persistent
          ? `Скаргу прийнято. Код: ${data.report.code}. Статус: на модерації.`
          : `Скаргу прийнято тимчасово. Код: ${data.report.code}. Постійне збереження запрацює після підключення бази даних.`;
      status.className = "report-submit-status success";
      $("#reportReason").value = "";
      $("#reportDetails").value = "";
    } catch (e) {
      console.error(e);
      status.textContent = "Не вдалося надіслати скаргу.";
      status.className = "report-submit-status error";
    } finally {
      submitReport.disabled = false;
      submitReport.textContent = "Надіслати на модерацію";
    }
  });
}

const submitAppeal = $("#submitAppeal");
if (submitAppeal) {
  submitAppeal.addEventListener("click", async () => {
    const reportCode = $("#appealCode").value.trim();
    const message = $("#appealMessage").value.trim();
    const contact = $("#appealContact").value.trim();
    const status = $("#appealStatus");
    if (!reportCode || message.length < 20) {
      status.textContent = "Вкажи код скарги та пояснення щонайменше 20 символів.";
      status.className = "report-submit-status error";
      return;
    }
    submitAppeal.disabled = true;
    status.textContent = "Надсилаємо…";
    status.className = "report-submit-status";
    try {
      const res = await apiFetch("/api/appeals", {
        method: "POST",
        body: JSON.stringify({ reportCode, message, contact })
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "appeal_failed");
      status.textContent = data.duplicate
        ? "Оскарження на цей запис уже очікує модерації."
        : "Оскарження прийнято на ручну перевірку ✅";
      status.className = "report-submit-status success";
      if (!data.duplicate) {
        $("#appealMessage").value = "";
        $("#appealContact").value = "";
      }
    } catch (e) {
      const messages = {
        report_not_found: "Схвалену скаргу з таким кодом не знайдено.",
        invalid_appeal: "Перевір код скарги та пояснення.",
        rate_limited: "Забагато спроб. Спробуй пізніше."
      };
      status.textContent = messages[e.message] || "Не вдалося надіслати оскарження.";
      status.className = "report-submit-status error";
    } finally {
      submitAppeal.disabled = false;
    }
  });
}

loadAlerts().catch(console.error);

const screenshotInput = document.querySelector("#screenshotInput");
const screenshotName = document.querySelector("#screenshotName");
const screenshotPreview = document.querySelector("#screenshotPreview");
const screenshotPreviewWrap = document.querySelector("#screenshotPreviewWrap");
const removeScreenshot = document.querySelector("#removeScreenshot");
const ocrStatus = document.querySelector("#ocrStatus");
let screenshotObjectUrl = "";

if (screenshotInput) {
  screenshotInput.addEventListener("change", () => {
    const file = screenshotInput.files?.[0];
    if (!file) return;

    if (!String(file.type || "").startsWith("image/")) {
      screenshotInput.value = "";
      if (ocrStatus) {
        ocrStatus.classList.remove("hidden", "success");
        ocrStatus.classList.add("error");
        ocrStatus.textContent = "Потрібно вибрати зображення.";
      }
      return;
    }

    state.screenshotFile = file;
    state.screenshotOcrText = "";
    state.type = "text";
    $$(".check-tab").forEach((b) => b.classList.toggle("active", b.dataset.type === "text"));
    updateCheckHint();

    screenshotName.textContent = file.name;
    if (screenshotObjectUrl) URL.revokeObjectURL(screenshotObjectUrl);
    screenshotObjectUrl = URL.createObjectURL(file);
    screenshotPreview.src = screenshotObjectUrl;
    screenshotPreviewWrap.classList.remove("hidden");
    if (ocrStatus) {
      ocrStatus.classList.remove("hidden", "error", "success");
      ocrStatus.textContent = "Скрін готовий. Натисни «Перевірити» — OCR запуститься локально у браузері.";
    }
  });
}

if (removeScreenshot) {
  removeScreenshot.addEventListener("click", () => {
    if (screenshotObjectUrl) URL.revokeObjectURL(screenshotObjectUrl);
    screenshotObjectUrl = "";
    state.screenshotFile = null;
    state.screenshotOcrText = "";
    screenshotInput.value = "";
    screenshotPreview.removeAttribute("src");
    screenshotPreviewWrap.classList.add("hidden");
    screenshotName.textContent = "Скрін не вибрано";
    if (ocrStatus) {
      ocrStatus.classList.add("hidden");
      ocrStatus.textContent = "";
      ocrStatus.classList.remove("error", "success");
    }
  });
}

function openEvidenceModal(){const modal=$("#evidenceModal"),list=$("#evidenceItems"),note=$("#evidenceNote"),ev=state.currentEvidence||{items:[]},labels={high:"Висока",medium:"Середня",low:"Низька"};list.innerHTML=(ev.items||[]).length?ev.items.map(x=>`<article class="evidence-item evidence-${escapeHtml(x.kind||"context")}"><div class="evidence-item-head"><b>${escapeHtml(x.title||"Сигнал")}</b><span>${escapeHtml(labels[x.confidence]||x.confidence||"—")} надійність</span></div><p>${escapeHtml(x.detail||"")}</p><small>Джерело: ${escapeHtml(x.source||"SafeDeal")}</small></article>`).join(""):`<div class="empty-state">Окремих доказів у цьому результаті немає.</div>`;note.textContent=ev.note||"";modal.classList.remove("hidden");}
async function ensureSharedCheck(){if(state.currentShare?.url)return state.currentShare;if(!state.currentReport)throw new Error("Спочатку виконай перевірку");const res=await apiFetch("/api/share-check",{method:"POST",body:JSON.stringify({report:state.currentReport,inputPreview:state.currentInput})});const data=await res.json();if(!data.ok)throw new Error(data.error||"share_failed");state.currentShare=data;return data;}
$("#evidenceBtn")?.addEventListener("click",openEvidenceModal);$("#closeEvidence")?.addEventListener("click",()=>closeModal("#evidenceModal"));$("#evidenceModal")?.addEventListener("click",e=>{if(e.target.id==="evidenceModal")closeModal("#evidenceModal");});
$("#shareCheckBtn")?.addEventListener("click",async()=>{try{const sh=await ensureSharedCheck();if(navigator.share)await navigator.share({title:"SafeDeal — результат перевірки",text:`${state.currentReport?.label||"Результат"} · ${state.currentReport?.score||0}/100`,url:sh.url});else{await navigator.clipboard.writeText(sh.url);alert("Посилання скопійовано.");}}catch(e){alert(`Не вдалося поділитися: ${e.message}`);}});
$("#reportBtn")?.addEventListener("click",async()=>{try{const sh=await ensureSharedCheck();window.open(sh.reportUrl,"_blank","noopener");}catch(e){alert(`Не вдалося створити звіт: ${e.message}`);}});
$("#watchBtn")?.addEventListener("click",async()=>{if(!state.currentReport||!state.currentInput)return;try{const active=$("#watchBtn").textContent.includes("активний");const res=await apiFetch("/api/watch",{method:active?"DELETE":"POST",body:JSON.stringify({type:state.currentReport.type,input:state.currentInput})});const data=await res.json();if(!data.ok)throw new Error(data.error||"watch_failed");$("#watchBtn").textContent=data.watching?"✓ SafeDeal Watch активний":"👁 Стежити";}catch(e){alert(`SafeDeal Watch: ${e.message}`);}});
$("#passportBtn")?.addEventListener("click",async()=>{if(!state.currentReport||!state.currentInput)return;const modal=$("#passportModal"),body=$("#passportBody");body.innerHTML=`<div class="empty-state">Завантажуємо...</div>`;modal.classList.remove("hidden");try{const res=await apiFetch(`/api/passport?type=${encodeURIComponent(state.currentReport.type)}&input=${encodeURIComponent(state.currentInput)}`);const data=await res.json();if(!data.ok)throw new Error(data.error||"passport_failed");const p=data.passport;body.innerHTML=`<div class="passport-grid"><div><strong>${Number(p.latest?.score||0)}/100</strong><span>Останній ризик</span></div><div><strong>${Number(p.checks||0)}</strong><span>Збережених перевірок</span></div><div><strong>${Number(p.approvedComplaints||0)}</strong><span>Схвалених скарг</span></div><div><strong>${Number(p.archivedReviews||0)}</strong><span>Архівних доказів</span></div></div><h4>Історія</h4><div class="passport-history">${(p.history||[]).slice(0,12).map(x=>`<div><b>${escapeHtml(x.label||"")}</b><span>${Number(x.score||0)}/100</span><small>${new Date(x.createdAt).toLocaleString("uk-UA")}</small></div>`).join("")||"Поки немає історії."}</div><h4>Пов’язані об’єкти</h4><div>${(p.related||[]).map(x=>`<div class="related-item"><b>${escapeHtml(x.type)}</b><span>${escapeHtml(x.targetKey)}</span><small>${escapeHtml(x.note)}</small></div>`).join("")||"Підтверджених зв’язків не знайдено."}</div>`;}catch(e){body.innerHTML=`<div class="empty-state">Не вдалося завантажити Passport: ${escapeHtml(e.message)}</div>`;}});
$("#closePassport")?.addEventListener("click",()=>closeModal("#passportModal"));$("#passportModal")?.addEventListener("click",e=>{if(e.target.id==="passportModal")closeModal("#passportModal");});
$("#prepayOpen")?.addEventListener("click",()=>$("#prepayPanel")?.classList.toggle("hidden"));$("#prepayEvaluate")?.addEventListener("click",()=>{const boxes=$$("#prepayPanel input[type=checkbox]"),dangerous=boxes.filter(x=>x.checked&&x.dataset.risk==="1").length,protective=boxes.filter(x=>x.checked&&x.dataset.safe==="1").length,out=$("#prepayResult");if(dangerous>=3)out.innerHTML=`<b>Краще не оплачувати зараз.</b><span>Є кілька сильних ознак ризику.</span>`;else if(dangerous>=1)out.innerHTML=`<b>Продовжуй лише з обережністю.</b><span>Не переказуй гроші, доки ризикові пункти не перевірені.</span>`;else if(protective>=2)out.innerHTML=`<b>Сильних тривожних пунктів у чеклісті немає.</b><span>Це не гарантія безпеки — виконай основну перевірку.</span>`;else out.innerHTML=`<b>Заповни чекліст.</b><span>Познач те, що відповідає ситуації.</span>`;});
async function computeAHash(file){const bitmap=await createImageBitmap(file),canvas=document.createElement("canvas");canvas.width=8;canvas.height=8;const ctx=canvas.getContext("2d",{willReadFrequently:true});ctx.drawImage(bitmap,0,0,8,8);const data=ctx.getImageData(0,0,8,8).data,vals=[];for(let i=0;i<data.length;i+=4)vals.push(data[i]*.299+data[i+1]*.587+data[i+2]*.114);const avg=vals.reduce((x,y)=>x+y,0)/vals.length;let bits="";vals.forEach(v=>bits+=v>=avg?"1":"0");let hex="";for(let i=0;i<64;i+=4)hex+=parseInt(bits.slice(i,i+4),2).toString(16);return hex;}

function blobToBase64(blob){return new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(String(r.result||"").split(",")[1]||"");r.onerror=()=>reject(r.error||new Error("file_read_failed"));r.readAsDataURL(blob);});}
async function prepareImageForInternet(file){
  const bitmap=await createImageBitmap(file);
  const maxSide=1200,scale=Math.min(1,maxSide/Math.max(bitmap.width,bitmap.height));
  let width=Math.max(1,Math.round(bitmap.width*scale)),height=Math.max(1,Math.round(bitmap.height*scale));
  const canvas=document.createElement("canvas"),ctx=canvas.getContext("2d");
  let blob=null;
  for(const quality of [.84,.72,.6,.5]){
    canvas.width=width;canvas.height=height;ctx.clearRect(0,0,width,height);ctx.drawImage(bitmap,0,0,width,height);
    blob=await new Promise(r=>canvas.toBlob(r,"image/jpeg",quality));
    if(blob&&blob.size<=430*1024)break;
    width=Math.max(320,Math.round(width*.86));height=Math.max(320,Math.round(height*.86));
  }
  if(!blob)throw new Error("image_prepare_failed");
  if(blob.size>500*1024)throw new Error("image_too_large");
  return {imageBase64:await blobToBase64(blob),mimeType:"image/jpeg",bytes:blob.size};
}
function safeHref(value=""){try{const u=new URL(String(value));return ["http:","https:"].includes(u.protocol)?u.href:"";}catch{return "";}}
function renderInternetImageMatch(item,label){
  const href=safeHref(item.link||"");
  return `<div class="internet-image-match"><div><b>${escapeHtml(label)}</b><span>${escapeHtml(item.title||item.source||"Збіг")}</span>${item.source?`<small>${escapeHtml(item.source)}</small>`:""}</div>${href?`<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">Відкрити джерело ↗</a>`:""}</div>`;
}
$("#antiFakeRun")?.addEventListener("click",async()=>{
  const file=$("#antiFakeFile")?.files?.[0],out=$("#antiFakeResult"),btn=$("#antiFakeRun");
  if(!file){out.textContent="Вибери фото товару або оголошення.";return;}
  if(file.size>12*1024*1024){out.textContent="Фото завелике. Вибери файл до 12 МБ.";return;}
  btn.disabled=true;
  out.innerHTML=`<b>Перевіряємо фото…</b><small>SafeDeal порівнює власну історію та шукає збіги у відкритих джерелах.</small>`;
  try{
    const [ahash,prepared]=await Promise.all([computeAHash(file),prepareImageForInternet(file)]);
    const target=$("#antiFakeTarget")?.value||state.currentInput||"";
    const res=await apiFetch("/api/image-fingerprint",{method:"POST",body:JSON.stringify({ahash,target,imageBase64:prepared.imageBase64,mimeType:prepared.mimeType})});
    const data=await res.json();
    if(!data.ok)throw new Error(data.error||"image_check_failed");

    const local=data.local||{matches:[],exactOrSimilarCount:0};
    const internet=data.internet||{configured:false,ok:false,exactMatches:[],visualMatches:[]};
    const exact=internet.exactMatches||[],visual=internet.visualMatches||[];
    const internetCount=exact.length+visual.length;

    let html=`<div class="anti-fake-summary"><b>Результат перевірки фото</b><span>SafeDeal: ${Number(local.exactOrSimilarCount||0)} · Інтернет: ${internetCount}</span></div>`;
    html+=local.exactOrSimilarCount
      ? `<div class="anti-fake-section"><strong>Власна історія SafeDeal</strong>${local.matches.map(x=>`<div class="local-image-match">• ${Number(x.similarity||0)}% схожості — ${escapeHtml(x.target||"інший об’єкт")}</div>`).join("")}</div>`
      : `<div class="anti-fake-section"><strong>Власна історія SafeDeal</strong><small>Збігів не знайдено.</small></div>`;

    if(!internet.configured){
      html+=`<div class="anti-fake-section warning"><strong>Пошук по інтернету ще не підключений</strong><small>${escapeHtml(internet.note||"Потрібен ключ провайдера.")}</small></div>`;
    }else if(!internet.ok){
      html+=`<div class="anti-fake-section warning"><strong>Інтернет-пошук тимчасово недоступний</strong><small>${escapeHtml(internet.note||"Спробуй ще раз пізніше.")}</small></div>`;
    }else if(!internetCount){
      html+=`<div class="anti-fake-section"><strong>Відкриті джерела</strong><small>Точних або візуально схожих збігів не знайдено. Це не гарантує, що фото оригінальне.</small></div>`;
    }else{
      html+=`<div class="anti-fake-section"><strong>Збіги у відкритих джерелах</strong>${exact.map(x=>renderInternetImageMatch(x,"Точний збіг")).join("")}${visual.map(x=>renderInternetImageMatch(x,"Схоже фото")).join("")}</div>`;
    }
    html+=`<small>${escapeHtml(internet.note||data.note||"")}</small>`;
    out.innerHTML=html;
  }catch(e){
    const map={image_too_large:"Не вдалося стиснути фото до дозволеного розміру.",unsupported_image_type:"Непідтримуваний формат фото.",invalid_image_data:"Помилка підготовки фото."};
    out.textContent=`Не вдалося перевірити фото: ${map[e.message]||e.message}`;
  }finally{btn.disabled=false;}
});
const recheck=new URLSearchParams(location.search).get("recheck");if(recheck){$("#checkInput").value=recheck;setTimeout(()=>$("#quickCheck")?.scrollIntoView({behavior:"smooth"}),250);}
