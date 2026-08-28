require("dotenv").config();

const express = require("express");
const path = require("path");
const helmet = require("helmet");
const compression = require("compression");
const cors = require("cors");
const morgan = require("morgan");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("tiny"));

const sampleReports = [
  {
    id: "R-78425",
    target: "t.me/fast_money_ua",
    type: "job",
    score: 92,
    level: "very-high",
    label: "Дуже високий ризик",
    reasons: [
      "Обіцяють нереалістичний дохід без досвіду",
      "Просять депозит / передоплату для активації",
      "Є підозріле зовнішнє посилання",
      "Запитують персональні або фінансові дані",
      "Схема схожа на task scam / fake job"
    ],
    updatedAt: "сьогодні"
  },
  {
    id: "R-78412",
    target: "shop-iphone-sale.com",
    type: "seller",
    score: 76,
    level: "high",
    label: "Високий ризик",
    reasons: [
      "Новий домен",
      "Ціна суттєво нижча за типову",
      "Є скарги користувачів",
      "Продавець наполягає на повній передоплаті"
    ],
    updatedAt: "15 хв тому"
  },
  {
    id: "R-78390",
    target: "+380 63 123 45 67",
    type: "contact",
    score: 69,
    level: "high",
    label: "Високий ризик",
    reasons: [
      "Контакт згадується в кількох скаргах",
      "Є повторювані повідомлення з однаковим сценарієм"
    ],
    updatedAt: "1 год тому"
  }
];

function normalizeText(value = "") {
  return String(value).trim().toLowerCase();
}

function analyzeInput(type, input) {
  const text = normalizeText(input);
  let score = 12;
  const reasons = [];
  const actions = new Set([
    "Не надсилайте паролі, PIN, CVV або коди з SMS.",
    "Не встановлюйте APK/EXE-файли з невідомих джерел."
  ]);

  const add = (points, reason) => {
    score += points;
    reasons.push(reason);
  };

  const moneyPromises = /\b(500|1000|2000)\s*(\$|usd|дол)|\bза\s*день\b|легк(і|ий)\s*гроші|без\s*досвіду/i;
  const deposit = /депозит|передоплат|активац|страхов(ий|ка)\s*внесок|внести\s*кошти/i;
  const cardData = /cvv|cvc|номер\s*карт|термін\s*дії|код\s*(з|із)\s*sms|pin|парол/i;
  const urgency = /терміново|прямо\s*зараз|10\s*хвилин|обмежен(а|ий)\s*час/i;
  const suspiciousFile = /\.apk\b|\.exe\b|\.scr\b|\.msi\b|\.zip\b/i;
  const shortener = /bit\.ly|tinyurl|t\.co|cutt\.ly|goo\.gl/i;
  const telegram = /t\.me\/|telegram|@\w{4,}/i;

  if (moneyPromises.test(text)) add(24, "Нереалістична або агресивна обіцянка заробітку");
  if (deposit.test(text)) {
    add(26, "Просять депозит / передоплату / платну активацію");
    actions.add("Не переказуйте гроші за «активацію роботи» або «страхування».");
  }
  if (cardData.test(text)) {
    add(28, "Є запит на чутливі банківські або авторизаційні дані");
    actions.add("Не вводьте повні реквізити картки, CVV, PIN або SMS-коди.");
  }
  if (urgency.test(text)) add(10, "Використовується тиск або штучна терміновість");
  if (suspiciousFile.test(text)) add(18, "Є згадка або посилання на потенційно небезпечне завантаження");
  if (shortener.test(text)) add(8, "Використовується скорочене посилання, яке приховує кінцеву адресу");
  if (telegram.test(text) && type === "job") add(6, "Вакансія веде в Telegram без достатньої інформації про роботодавця");

  if (type === "seller" && /передоплат|на\s*карт|скиньте\s*кошти/i.test(text)) {
    add(16, "Продавець наполягає на передоплаті або прямому переказі");
  }

  if (type === "link" && /^https?:\/\//.test(text)) {
    if (/login|secure|verify|payment|card|wallet|bonus|gift/i.test(text)) {
      add(12, "URL містить слова, типові для сторінок входу, оплати або верифікації");
    }
    // Реальна мережна перевірка навмисно не виконується в MVP.
    reasons.push("Глибока перевірка домену та редиректів буде підключена окремим безпечним модулем");
  }

  score = Math.max(0, Math.min(100, score));

  let level = "low";
  let label = "Низький ризик";
  if (score >= 76) {
    level = "very-high";
    label = "Дуже високий ризик";
  } else if (score >= 51) {
    level = "high";
    label = "Високий ризик";
  } else if (score >= 26) {
    level = "medium";
    label = "Середній ризик";
  }

  if (!reasons.length) {
    reasons.push("У введених даних не знайдено явних типових ознак шахрайства");
  }

  return {
    id: `R-${Date.now().toString().slice(-6)}`,
    type,
    score,
    level,
    label,
    reasons,
    actions: [...actions],
    disclaimer:
      "Це автоматична оцінка ризику, а не юридичний висновок і не гарантія безпеки."
  };
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "safedeal" });
});

app.get("/api/community-alerts", (req, res) => {
  res.json({ ok: true, items: sampleReports });
});

app.post("/api/check", (req, res) => {
  const { type = "seller", input = "" } = req.body || {};
  if (!String(input).trim()) {
    return res.status(400).json({ ok: false, error: "input_required" });
  }
  res.json({ ok: true, report: analyzeInput(type, input) });
});

app.use(express.static(__dirname));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`SafeDeal started on port ${PORT}`);
});
