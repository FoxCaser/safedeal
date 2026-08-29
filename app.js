const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const state = {
  type: "seller"
};

const titles = {
  home: "Перевіряй. Аналізуй. Уникай шахраїв.",
  reports: "База скарг",
  history: "Історія перевірок",
  profile: "Профіль",
  reputation: "Історія репутації"
};

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function showPage(id) {
  $$(".page").forEach((p) => p.classList.toggle("active", p.id === id));
  $$('[data-page]').forEach((b) => b.classList.toggle("active", b.dataset.page === id));
  $("#pageTitle").textContent = titles[id] || titles.home;
  window.scrollTo({ top: 0, behavior: "smooth" });

  if (id === "reports") loadReports().catch(console.error);
  if (id === "history") renderHistory();
}

function selectType(type) {
  state.type = type;
  $$(".check-tab").forEach((b) => b.classList.toggle("active", b.dataset.type === type));
  showPage("home");
  setTimeout(() => $("#quickCheck").scrollIntoView({ behavior: "smooth", block: "start" }), 50);
}

$$('[data-page]').forEach((btn) => btn.addEventListener("click", () => showPage(btn.dataset.page)));
$$('[data-check]').forEach((btn) => btn.addEventListener("click", () => selectType(btn.dataset.check)));
$$(".check-tab").forEach((btn) => btn.addEventListener("click", () => selectType(btn.dataset.type)));

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

function getHistory() {
  try {
    const raw = localStorage.getItem("safedeal_history_v1");
    const items = raw ? JSON.parse(raw) : [];
    return Array.isArray(items) ? items : [];
  } catch {
    return [];
  }
}

function saveHistory(report, input) {
  const items = getHistory();
  items.unshift({
    id: report.id,
    type: report.type,
    input: String(input).slice(0, 240),
    score: report.score,
    label: report.label,
    createdAt: new Date().toISOString()
  });

  localStorage.setItem("safedeal_history_v1", JSON.stringify(items.slice(0, 30)));
}

function renderHistory() {
  const wrap = $("#historyList");
  if (!wrap) return;

  const items = getHistory();
  if (!items.length) {
    wrap.innerHTML = `<div class="empty-state">Історія поки порожня. Виконай першу перевірку.</div>`;
    return;
  }

  wrap.innerHTML = items.map((item) => {
    const date = new Date(item.createdAt);
    const shownDate = Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("uk-UA");
    return `
      <article class="history-item">
        <div>
          <span class="history-type">${escapeHtml(item.type)}</span>
          <h4>${escapeHtml(item.input)}</h4>
          <small>${escapeHtml(shownDate)}</small>
        </div>
        <div class="history-score">${Number(item.score) || 0}<span>/100</span></div>
      </article>
    `;
  }).join("");
}

const clearHistory = $("#clearHistory");
if (clearHistory) {
  clearHistory.addEventListener("click", () => {
    localStorage.removeItem("safedeal_history_v1");
    renderHistory();
  });
}

$("#runCheck").addEventListener("click", async () => {
  const input = $("#checkInput").value.trim();
  if (!input) {
    $("#checkInput").focus();
    return;
  }

  const button = $("#runCheck");
  button.disabled = true;
  button.textContent = "Перевіряємо...";

  try {
    const res = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: state.type, input })
    });

    const data = await res.json();
    if (!data.ok) throw new Error(data.error || "check_failed");

    const r = data.report;
    $("#reportId").textContent = r.id;
    $("#scoreValue").textContent = r.score;
    $("#scoreLabel").textContent = r.label;
    $("#reasonList").innerHTML = r.reasons.map((x) => `<div class="reason">! <span>${escapeHtml(x)}</span></div>`).join("");
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

      techGrid.innerHTML = `
        <div class="tech-item"><span>🌐 Домен</span><b>${escapeHtml(t.hostname || "—")}</b></div>
        <div class="tech-item"><span>🔒 Протокол</span><b>${escapeHtml(String(t.protocol || "—").toUpperCase())}</b></div>
        <div class="tech-item"><span>📅 Вік домену</span><b>${escapeHtml(ageText)}</b></div>
        <div class="tech-item"><span>🛰 DNS</span><b>${Array.isArray(t.dns) && t.dns.length ? `${t.dns.length} адрес(и)` : "Не знайдено"}</b></div>
        <div class="tech-item"><span>🛡 Google Web Risk</span><b>${escapeHtml(webRiskText)}</b></div>
        <div class="tech-item"><span>🎣 PhishTank</span><b>${escapeHtml(phishTankText)}</b></div>
        <div class="tech-item"><span>🧨 PhishDestroy</span><b>${escapeHtml(phishDestroyText)}</b></div>
        <div class="tech-item"><span>🦠 URLhaus</span><b>${escapeHtml(urlHausText)}</b></div>
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

    saveHistory(r, input);

    const card = $("#resultCard");
    card.classList.remove("hidden");
    card.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    console.error(e);
    alert("Не вдалося виконати перевірку.");
  } finally {
    button.disabled = false;
    button.textContent = "⌕ Перевірити";
  }
});

async function loadAlerts() {
  const res = await fetch("/api/community-alerts");
  const data = await res.json();

  $("#alertsGrid").innerHTML = data.items.map((item) => `
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
    contact: "Контакт",
    text: "Текст"
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
      const res = await fetch("/api/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, type, reason, details })
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "submit_failed");

      status.textContent = data.persistent
        ? `Скаргу прийнято. Код: ${data.report.code}. Статус: на модерації.`
        : `Тестову скаргу прийнято. Код: ${data.report.code}. Постійне збереження запрацює після підключення бази даних.`;
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

loadAlerts().catch(console.error);

const screenshotInput = document.querySelector("#screenshotInput");
const screenshotName = document.querySelector("#screenshotName");
const screenshotPreview = document.querySelector("#screenshotPreview");
const screenshotPreviewWrap = document.querySelector("#screenshotPreviewWrap");
const removeScreenshot = document.querySelector("#removeScreenshot");

if (screenshotInput) {
  screenshotInput.addEventListener("change", () => {
    const file = screenshotInput.files?.[0];
    if (!file) return;

    screenshotName.textContent = file.name;
    const url = URL.createObjectURL(file);
    screenshotPreview.src = url;
    screenshotPreviewWrap.classList.remove("hidden");
  });
}

if (removeScreenshot) {
  removeScreenshot.addEventListener("click", () => {
    if (screenshotPreview.src) URL.revokeObjectURL(screenshotPreview.src);
    screenshotInput.value = "";
    screenshotPreview.removeAttribute("src");
    screenshotPreviewWrap.classList.add("hidden");
    screenshotName.textContent = "Скрін не вибрано";
  });
}
