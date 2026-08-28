const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const state = {
  type: "seller"
};

const titles = {
  home: "Перевіряй. Аналізуй. Уникай шахраїв.",
  reports: "База скарг",
  history: "Історія перевірок",
  profile: "Профіль"
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
