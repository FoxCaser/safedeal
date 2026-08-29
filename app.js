const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const state = {
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
    $("#reportId").textContent = r.id;
    $("#scoreValue").textContent = r.score;
    $("#scoreLabel").textContent = r.label;

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

  results.innerHTML = data.items.map((item) => `
    <article class="report-row">
      <div class="report-row-top">
        <span class="report-type">${escapeHtml(typeLabel(item.type))}</span>
        <span class="report-status">${escapeHtml(item.statusLabel || "Перевірено")}</span>
      </div>
      <h4>${escapeHtml(item.target)}</h4>
      <p>${escapeHtml(item.reason || item.reasons?.[0] || "Є підтверджені сигнали ризику")}</p>
      <small>${escapeHtml(item.updatedAt || "")}</small>
    </article>
  `).join("");
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
