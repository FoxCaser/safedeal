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

function showPage(id) {
  $$(".page").forEach((p) => p.classList.toggle("active", p.id === id));
  $$("[data-page]").forEach((b) => b.classList.toggle("active", b.dataset.page === id));
  $("#pageTitle").textContent = titles[id] || titles.home;
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function selectType(type) {
  state.type = type;
  $$(".check-tab").forEach((b) => b.classList.toggle("active", b.dataset.type === type));
  showPage("home");
  setTimeout(() => $("#quickCheck").scrollIntoView({ behavior: "smooth", block: "start" }), 50);
}

$$("[data-page]").forEach((btn) => btn.addEventListener("click", () => showPage(btn.dataset.page)));
$$("[data-check]").forEach((btn) => btn.addEventListener("click", () => selectType(btn.dataset.check)));
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
    $("#reasonList").innerHTML = r.reasons.map((x) => `<div class="reason">! <span>${x}</span></div>`).join("");
    $("#actionList").innerHTML = r.actions.map((x) => `<div class="action">✓ <span>${x}</span></div>`).join("");
    $("#disclaimer").textContent = r.disclaimer;
    setScoreVisual(r.score, r.level);

    const techBox = $("#technicalBox");
    const techGrid = $("#technicalGrid");
    const factsList = $("#factsList");

    const t = r.technical;
    if (t) {
      const ageText =
        Number.isFinite(t.domainAgeDays) ? `${t.domainAgeDays} дн.` : "Не підтверджено";

      const webRiskText =
        t.webRiskConfigured === false
          ? "Не підключено"
          : t.webRiskMatches > 0
            ? `Є збіг (${t.webRiskMatches})`
            : "Відомих збігів немає";

      techGrid.innerHTML = `
        <div class="tech-item">
          <span>🌐 Домен</span>
          <b>${t.hostname || "—"}</b>
        </div>
        <div class="tech-item">
          <span>🔒 Протокол</span>
          <b>${String(t.protocol || "—").toUpperCase()}</b>
        </div>
        <div class="tech-item">
          <span>📅 Вік домену</span>
          <b>${ageText}</b>
        </div>
        <div class="tech-item">
          <span>🛰 DNS</span>
          <b>${Array.isArray(t.dns) && t.dns.length ? `${t.dns.length} адрес(и)` : "Не знайдено"}</b>
        </div>
        <div class="tech-item">
          <span>🛡 Google Web Risk</span>
          <b>${webRiskText}</b>
        </div>
      `;

      factsList.innerHTML = (r.facts || [])
        .map((x) => `<div class="fact">✓ <span>${x}</span></div>`)
        .join("");

      techBox.classList.remove("hidden");
    } else {
      techGrid.innerHTML = "";
      factsList.innerHTML = "";
      techBox.classList.add("hidden");
    }

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
        <span class="risk-badge ${item.level}">${item.label}</span>
        <small>${item.updatedAt}</small>
      </div>
      <h4>${item.target}</h4>
      <p>${item.reasons[0]}</p>
      <div class="alert-score">${item.score}/100</div>
    </article>
  `).join("");
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
