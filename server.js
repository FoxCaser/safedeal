require("dotenv").config();

const express = require("express");
const path = require("path");
const dns = require("dns").promises;
const net = require("net");
const helmet = require("helmet");
const compression = require("compression");
const cors = require("cors");
const morgan = require("morgan");

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY || "";

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
  }
];

function normalizeText(value = "") {
  return String(value).trim().toLowerCase();
}

function extractFirstUrl(value = "") {
  const text = String(value).trim();

  const protocolMatch = text.match(/https?:\/\/[^\s<>"']+/i);
  if (protocolMatch) {
    return protocolMatch[0].replace(/[),.;!?]+$/, "");
  }

  // Дозволяємо також просто domain.tld/path
  const domainMatch = text.match(
    /(?:^|\s)((?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"']*)?)/i
  );

  if (domainMatch) {
    return `https://${domainMatch[1].replace(/[),.;!?]+$/, "")}`;
  }

  return null;
}

function isPrivateOrReservedIp(ip) {
  if (!net.isIP(ip)) return true;

  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    const [a, b] = p;

    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }

  const normalized = ip.toLowerCase();
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe8") ||
    normalized.startsWith("fe9") ||
    normalized.startsWith("fea") ||
    normalized.startsWith("feb")
  );
}

function scoreToLevel(score) {
  if (score >= 76) return { level: "very-high", label: "Дуже високий ризик" };
  if (score >= 51) return { level: "high", label: "Високий ризик" };
  if (score >= 26) return { level: "medium", label: "Середній ризик" };
  return { level: "low", label: "Низький ризик" };
}

function parseRdapRegistrationDate(rdap) {
  const events = Array.isArray(rdap?.events) ? rdap.events : [];
  const registration = events.find(
    (event) => String(event?.eventAction).toLowerCase() === "registration"
  );

  if (!registration?.eventDate) return null;

  const date = new Date(registration.eventDate);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

async function lookupDomain(hostname) {
  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    return {
      ok: true,
      addresses: records.map((r) => r.address),
      hasPrivateAddress: records.some((r) => isPrivateOrReservedIp(r.address))
    };
  } catch (error) {
    return {
      ok: false,
      addresses: [],
      hasPrivateAddress: false,
      error: error.code || "dns_lookup_failed"
    };
  }
}

async function lookupRdap(hostname) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);

  try {
    const response = await fetch(
      `https://rdap.org/domain/${encodeURIComponent(hostname)}`,
      {
        signal: controller.signal,
        redirect: "follow",
        headers: {
          Accept: "application/rdap+json, application/json"
        }
      }
    );

    if (!response.ok) {
      return { ok: false, status: response.status };
    }

    const data = await response.json();
    const registrationDate = parseRdapRegistrationDate(data);

    return {
      ok: true,
      registrationDate: registrationDate
        ? registrationDate.toISOString()
        : null,
      ageDays: registrationDate
        ? Math.max(
            0,
            Math.floor((Date.now() - registrationDate.getTime()) / 86400000)
          )
        : null,
      statuses: Array.isArray(data.status) ? data.status.slice(0, 10) : [],
      nameservers: Array.isArray(data.nameservers)
        ? data.nameservers
            .map((n) => n.ldhName || n.unicodeName)
            .filter(Boolean)
            .slice(0, 8)
        : []
    };
  } catch (error) {
    return { ok: false, error: error.name || "rdap_failed" };
  } finally {
    clearTimeout(timer);
  }
}

async function checkGoogleSafeBrowsing(url) {
  if (!GOOGLE_SAFE_BROWSING_API_KEY) {
    return { configured: false, matches: [] };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(
        GOOGLE_SAFE_BROWSING_API_KEY
      )}`,
      {
        method: "POST",
        signal: controller.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: {
            clientId: "safedeal",
            clientVersion: "0.2.0"
          },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      }
    );

    if (!response.ok) {
      return {
        configured: true,
        ok: false,
        status: response.status,
        matches: []
      };
    }

    const data = await response.json();
    return {
      configured: true,
      ok: true,
      matches: Array.isArray(data.matches) ? data.matches : []
    };
  } catch (error) {
    return {
      configured: true,
      ok: false,
      error: error.name || "safe_browsing_failed",
      matches: []
    };
  } finally {
    clearTimeout(timer);
  }
}

async function inspectUrl(rawUrl) {
  let parsed;

  try {
    parsed = new URL(rawUrl);
  } catch {
    return {
      ok: false,
      reasons: ["Не вдалося розпізнати адресу посилання"],
      technical: {}
    };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return {
      ok: false,
      reasons: ["Дозволені тільки HTTP/HTTPS-посилання"],
      technical: {}
    };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    net.isIP(hostname) && isPrivateOrReservedIp(hostname)
  ) {
    return {
      ok: false,
      reasons: ["Локальні та приватні адреси не перевіряються"],
      technical: { hostname }
    };
  }

  const dnsResult = await lookupDomain(hostname);

  if (dnsResult.hasPrivateAddress) {
    return {
      ok: false,
      reasons: ["Домен веде на приватну або зарезервовану IP-адресу"],
      technical: {
        hostname,
        dns: dnsResult.addresses
      }
    };
  }

  const [rdap, safeBrowsing] = await Promise.all([
    lookupRdap(hostname),
    checkGoogleSafeBrowsing(rawUrl)
  ]);

  const reasons = [];
  const facts = [];
  let points = 0;

  if (parsed.protocol !== "https:") {
    points += 12;
    reasons.push("Посилання використовує HTTP замість HTTPS");
  } else {
    facts.push("Посилання використовує HTTPS");
  }

  if (!dnsResult.ok) {
    points += 20;
    reasons.push("Домен не вдалося нормально знайти через DNS");
  } else {
    facts.push(`DNS знайдено: ${dnsResult.addresses.length} адрес(и)`);
  }

  if (rdap.ok && Number.isFinite(rdap.ageDays)) {
    if (rdap.ageDays <= 7) {
      points += 30;
      reasons.push(`Домен дуже новий: приблизно ${rdap.ageDays} дн.`);
    } else if (rdap.ageDays <= 30) {
      points += 22;
      reasons.push(`Домен зареєстрований нещодавно: приблизно ${rdap.ageDays} дн.`);
    } else if (rdap.ageDays <= 180) {
      points += 10;
      reasons.push(`Домен відносно новий: приблизно ${rdap.ageDays} дн.`);
    } else {
      facts.push(`Вік домену: приблизно ${rdap.ageDays} дн.`);
    }
  } else {
    facts.push("Дату реєстрації домену не вдалося підтвердити через RDAP");
  }

  if (safeBrowsing.configured) {
    if (safeBrowsing.matches.length > 0) {
      points += 65;
      reasons.push("Google Safe Browsing повернув збіг із базою небезпечних URL");
    } else if (safeBrowsing.ok) {
      facts.push("Google Safe Browsing не повернув відомих збігів для цього URL");
    }
  } else {
    facts.push("Google Safe Browsing ще не підключений до SafeDeal");
  }

  const suspiciousHostTokens = [
    "secure-login",
    "verify-account",
    "payment-confirm",
    "wallet-verify",
    "bonus-gift"
  ];

  if (suspiciousHostTokens.some((token) => hostname.includes(token))) {
    points += 12;
    reasons.push("У домені є слова, типові для фішингових сторінок");
  }

  if (hostname.split(".").length >= 5) {
    points += 6;
    reasons.push("Домен має незвично багато рівнів піддоменів");
  }

  return {
    ok: true,
    points,
    reasons,
    facts,
    technical: {
      hostname,
      protocol: parsed.protocol.replace(":", ""),
      dns: dnsResult.addresses,
      registrationDate: rdap.registrationDate || null,
      domainAgeDays: rdap.ageDays ?? null,
      safeBrowsingConfigured: safeBrowsing.configured,
      safeBrowsingMatches: safeBrowsing.matches.length
    }
  };
}

function analyzeTextSignals(type, input) {
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

  const moneyPromises =
    /\b(500|1000|2000)\s*(\$|usd|дол)|\bза\s*день\b|легк(і|ий)\s*гроші|без\s*досвіду/i;
  const deposit =
    /депозит|передоплат|активац|страхов(ий|ка)\s*внесок|внести\s*кошти/i;
  const cardData =
    /cvv|cvc|номер\s*карт|термін\s*дії|код\s*(з|із)\s*sms|pin|парол/i;
  const urgency =
    /терміново|прямо\s*зараз|10\s*хвилин|обмежен(а|ий)\s*час/i;
  const suspiciousFile = /\.apk\b|\.exe\b|\.scr\b|\.msi\b|\.zip\b/i;
  const shortener = /bit\.ly|tinyurl|t\.co|cutt\.ly|goo\.gl/i;
  const telegram = /t\.me\/|telegram|@\w{4,}/i;

  if (moneyPromises.test(text)) {
    add(24, "Нереалістична або агресивна обіцянка заробітку");
  }

  if (deposit.test(text)) {
    add(26, "Просять депозит / передоплату / платну активацію");
    actions.add("Не переказуйте гроші за «активацію роботи» або «страхування».");
  }

  if (cardData.test(text)) {
    add(28, "Є запит на чутливі банківські або авторизаційні дані");
    actions.add("Не вводьте повні реквізити картки, CVV, PIN або SMS-коди.");
  }

  if (urgency.test(text)) {
    add(10, "Використовується тиск або штучна терміновість");
  }

  if (suspiciousFile.test(text)) {
    add(18, "Є згадка або посилання на потенційно небезпечне завантаження");
  }

  if (shortener.test(text)) {
    add(8, "Використовується скорочене посилання, яке приховує кінцеву адресу");
  }

  if (telegram.test(text) && type === "job") {
    add(6, "Вакансія веде в Telegram без достатньої інформації про роботодавця");
  }

  if (
    type === "seller" &&
    /передоплат|на\s*карт|скиньте\s*кошти/i.test(text)
  ) {
    add(16, "Продавець наполягає на передоплаті або прямому переказі");
  }

  return {
    score,
    reasons,
    actions
  };
}

async function analyzeInput(type, input) {
  const textAnalysis = analyzeTextSignals(type, input);
  let score = textAnalysis.score;
  const reasons = [...textAnalysis.reasons];
  const facts = [];
  const actions = new Set(textAnalysis.actions);
  let technical = null;

  const detectedUrl = extractFirstUrl(input);

  if (detectedUrl) {
    const urlAnalysis = await inspectUrl(detectedUrl);

    if (urlAnalysis.ok) {
      score += urlAnalysis.points;
      reasons.push(...urlAnalysis.reasons);
      facts.push(...urlAnalysis.facts);
      technical = urlAnalysis.technical;
    } else {
      reasons.push(...urlAnalysis.reasons);
      technical = urlAnalysis.technical;
    }
  } else if (type === "link") {
    reasons.push("У введених даних не знайдено коректного URL");
    score += 8;
  }

  score = Math.max(0, Math.min(100, score));
  const { level, label } = scoreToLevel(score);

  if (!reasons.length) {
    reasons.push(
      "Не знайдено явних типових сигналів ризику, але це не гарантує безпечність"
    );
  }

  return {
    id: `R-${Date.now().toString().slice(-6)}`,
    type,
    score,
    level,
    label,
    reasons,
    facts,
    actions: [...actions],
    technical,
    disclaimer:
      "Це автоматична оцінка ризику, а не юридичний висновок і не гарантія безпеки."
  };
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "safedeal",
    safeBrowsingConfigured: Boolean(GOOGLE_SAFE_BROWSING_API_KEY)
  });
});

app.get("/api/community-alerts", (req, res) => {
  res.json({ ok: true, items: sampleReports });
});

app.post("/api/check", async (req, res) => {
  const { type = "seller", input = "" } = req.body || {};

  if (!String(input).trim()) {
    return res.status(400).json({ ok: false, error: "input_required" });
  }

  try {
    const report = await analyzeInput(type, input);
    res.json({ ok: true, report });
  } catch (error) {
    console.error("SafeDeal check error:", error);
    res.status(500).json({
      ok: false,
      error: "check_failed"
    });
  }
});

app.use(express.static(__dirname));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`SafeDeal started on port ${PORT}`);
  console.log(
    `Google Safe Browsing: ${
      GOOGLE_SAFE_BROWSING_API_KEY ? "configured" : "not configured"
    }`
  );
});
