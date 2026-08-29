require("dotenv").config();

const express = require("express");
const path = require("path");
const dns = require("dns").promises;
const net = require("net");
const helmet = require("helmet");
const compression = require("compression");
const cors = require("cors");
const morgan = require("morgan");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_WEB_RISK_API_KEY = process.env.GOOGLE_WEB_RISK_API_KEY || "";
const PHISHTANK_APP_KEY = process.env.PHISHTANK_APP_KEY || "";
const DATABASE_URL = process.env.DATABASE_URL || "";

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("tiny"));

const ALLOWED_TYPES = new Set(["seller", "job", "link", "contact", "text"]);

const demoApprovedReports = [
  {
    code: "DEMO-1001",
    target: "demo-shop.example",
    targetKey: "demo-shop.example",
    type: "seller",
    status: "approved",
    statusLabel: "Демо-запис",
    reason: "Приклад: скарги на вимогу повної передоплати без безпечного способу оплати.",
    updatedAt: "демо"
  },
  {
    code: "DEMO-1002",
    target: "@demo_fast_job",
    targetKey: "@demo_fast_job",
    type: "job",
    status: "approved",
    statusLabel: "Демо-запис",
    reason: "Приклад: вакансія просить внесок для «активації» завдань.",
    updatedAt: "демо"
  }
];

const demoAlerts = [
  {
    id: "DEMO-78425",
    target: "@demo_fast_job",
    type: "job",
    score: 92,
    level: "very-high",
    label: "Дуже високий ризик",
    reasons: [
      "Демо: обіцянка нереалістичного доходу та платна активація"
    ],
    updatedAt: "демо"
  },
  {
    id: "DEMO-78412",
    target: "demo-shop.example",
    type: "seller",
    score: 76,
    level: "high",
    label: "Високий ризик",
    reasons: [
      "Демо: повна передоплата та кілька сигналів ризику"
    ],
    updatedAt: "демо"
  }
];

let pool = null;
let databaseReady = false;
const memoryPendingReports = [];

if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: DATABASE_URL.includes("localhost")
      ? false
      : { rejectUnauthorized: false }
  });
}

async function initDatabase() {
  if (!pool) return;

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS community_reports (
        id BIGSERIAL PRIMARY KEY,
        code TEXT UNIQUE NOT NULL,
        target TEXT NOT NULL,
        target_key TEXT NOT NULL,
        type TEXT NOT NULL,
        reason TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reports_target_key ON community_reports(target_key)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reports_status ON community_reports(status)`);
    databaseReady = true;
    console.log("Database: connected");
  } catch (error) {
    databaseReady = false;
    console.error("Database init failed:", error.message);
  }
}

function normalizeText(value = "") {
  return String(value).trim().toLowerCase();
}

function compactSpaces(value = "") {
  return String(value).replace(/\s+/g, " ").trim();
}

function normalizeTargetKey(value = "") {
  const raw = compactSpaces(value).toLowerCase();
  if (!raw) return "";

  const phoneDigits = raw.replace(/\D/g, "");
  if (/^[+\d\s().-]{8,}$/.test(raw) && phoneDigits.length >= 8) {
    return phoneDigits;
  }

  const telegramMatch = raw.match(/(?:https?:\/\/)?t\.me\/([a-z0-9_]{4,})/i);
  if (telegramMatch) return `@${telegramMatch[1].toLowerCase()}`;

  const usernameMatch = raw.match(/^@([a-z0-9_]{4,})$/i);
  if (usernameMatch) return `@${usernameMatch[1].toLowerCase()}`;

  try {
    const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const parsed = new URL(withProtocol);
    if (parsed.hostname && parsed.hostname.includes(".")) {
      return parsed.hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
    }
  } catch {}

  return raw.slice(0, 220);
}

function extractFirstUrl(value = "") {
  const text = String(value).trim();
  const protocolMatch = text.match(/https?:\/\/[^\s<>"']+/i);
  if (protocolMatch) return protocolMatch[0].replace(/[),.;!?]+$/, "");

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
  return Number.isNaN(date.getTime()) ? null : date;
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
        headers: { Accept: "application/rdap+json, application/json" }
      }
    );

    if (!response.ok) return { ok: false, status: response.status };

    const data = await response.json();
    const registrationDate = parseRdapRegistrationDate(data);

    return {
      ok: true,
      registrationDate: registrationDate ? registrationDate.toISOString() : null,
      ageDays: registrationDate
        ? Math.max(0, Math.floor((Date.now() - registrationDate.getTime()) / 86400000))
        : null
    };
  } catch (error) {
    return { ok: false, error: error.name || "rdap_failed" };
  } finally {
    clearTimeout(timer);
  }
}

async function checkGoogleWebRisk(url) {
  if (!GOOGLE_WEB_RISK_API_KEY) {
    return { configured: false, matches: [] };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);

  try {
    const params = new URLSearchParams();
    params.append("threatTypes", "MALWARE");
    params.append("threatTypes", "SOCIAL_ENGINEERING");
    params.append("threatTypes", "UNWANTED_SOFTWARE");
    params.set("uri", url);
    params.set("key", GOOGLE_WEB_RISK_API_KEY);

    const response = await fetch(
      `https://webrisk.googleapis.com/v1/uris:search?${params.toString()}`,
      { signal: controller.signal }
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
    const threat = data?.threat;

    return {
      configured: true,
      ok: true,
      matches: threat ? [threat] : []
    };
  } catch (error) {
    return {
      configured: true,
      ok: false,
      error: error.name || "web_risk_failed",
      matches: []
    };
  } finally {
    clearTimeout(timer);
  }
}

async function checkPhishTank(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);

  try {
    const body = new URLSearchParams();
    body.set("url", url);
    body.set("format", "json");
    if (PHISHTANK_APP_KEY) body.set("app_key", PHISHTANK_APP_KEY);

    const response = await fetch("http://checkurl.phishtank.com/checkurl/", {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Accept": "application/json",
        "User-Agent": "phishtank/safedeal"
      },
      body: body.toString()
    });

    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        rateLimited: response.status === 509 || response.status === 429,
        hasKey: Boolean(PHISHTANK_APP_KEY),
        inDatabase: false,
        verified: false,
        valid: false
      };
    }

    const data = await response.json();
    const rawResults = data?.results || {};
    const result = rawResults?.url0 || rawResults;
    const toBool = (value) => {
      if (value === true || value === 1) return true;
      const normalized = String(value ?? "").trim().toLowerCase();
      return ["true", "1", "y", "yes"].includes(normalized);
    };

    return {
      ok: true,
      status: response.status,
      rateLimited: false,
      hasKey: Boolean(PHISHTANK_APP_KEY),
      inDatabase: toBool(result?.in_database),
      verified: toBool(result?.verified),
      valid: toBool(result?.valid),
      phishId: result?.phish_id ? String(result.phish_id) : null
    };
  } catch (error) {
    return {
      ok: false,
      error: error.name || "phishtank_failed",
      rateLimited: false,
      hasKey: Boolean(PHISHTANK_APP_KEY),
      inDatabase: false,
      verified: false,
      valid: false
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
    return { ok: false, reasons: ["Не вдалося розпізнати адресу посилання"], technical: {} };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { ok: false, reasons: ["Дозволені тільки HTTP/HTTPS-посилання"], technical: {} };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    (net.isIP(hostname) && isPrivateOrReservedIp(hostname))
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
      technical: { hostname, dns: dnsResult.addresses }
    };
  }

  const [rdap, webRisk, phishTank] = await Promise.all([
    lookupRdap(hostname),
    checkGoogleWebRisk(rawUrl),
    checkPhishTank(rawUrl)
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

  if (parsed.username || parsed.password) {
    points += 18;
    reasons.push("URL містить логін або пароль перед адресою домену — це може маскувати справжню адресу");
  }

  if (net.isIP(hostname)) {
    points += 14;
    reasons.push("Замість доменного імені використовується пряма IP-адреса");
  }

  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    points += 14;
    reasons.push("Домен використовує Punycode; візуально він може імітувати іншу назву");
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

  if (webRisk.configured) {
    if (webRisk.matches.length > 0) {
      points += 65;
      reasons.push("Google Web Risk повернув збіг із базою небезпечних URL");
    } else if (webRisk.ok) {
      facts.push("Google Web Risk не повернув відомих збігів для цього URL");
    } else {
      facts.push("Google Web Risk підключений, але перевірка тимчасово не відповіла");
    }
  } else {
    facts.push("Google Web Risk ще не підключений до SafeDeal");
  }

  if (phishTank.ok) {
    if (phishTank.inDatabase && phishTank.verified && phishTank.valid) {
      points += 70;
      reasons.push("PhishTank має підтверджений активний запис про фішинг для цього URL");
    } else if (phishTank.inDatabase) {
      points += 20;
      reasons.push("URL є в базі PhishTank, але запис не підтверджений як активний фішинг");
    } else {
      facts.push("PhishTank не знайшов цей URL у своїй базі фішингу");
    }
  } else if (phishTank.rateLimited) {
    facts.push("PhishTank тимчасово перевищив ліміт запитів; перевірка не виконана");
  } else {
    facts.push("PhishTank тимчасово не відповів; результат за цим джерелом невідомий");
  }

  const suspiciousHostTokens = [
    "secure-login",
    "verify-account",
    "payment-confirm",
    "wallet-verify",
    "bonus-gift",
    "account-verify",
    "confirm-payment"
  ];

  if (suspiciousHostTokens.some((token) => hostname.includes(token))) {
    points += 12;
    reasons.push("У домені є слова, типові для фішингових сторінок");
  }

  if (hostname.split(".").length >= 5) {
    points += 6;
    reasons.push("Домен має незвично багато рівнів піддоменів");
  }

  if (["bit.ly", "tinyurl.com", "cutt.ly", "t.co", "is.gd"].includes(hostname)) {
    points += 8;
    reasons.push("Скорочене посилання приховує кінцеву адресу");
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
      webRiskConfigured: webRisk.configured,
      webRiskOk: Boolean(webRisk.ok),
      webRiskStatus: webRisk.status || null,
      webRiskMatches: webRisk.matches.length,
      phishTankOk: Boolean(phishTank.ok),
      phishTankHasKey: Boolean(phishTank.hasKey),
      phishTankRateLimited: Boolean(phishTank.rateLimited),
      phishTankInDatabase: Boolean(phishTank.inDatabase),
      phishTankVerified: Boolean(phishTank.verified),
      phishTankValid: Boolean(phishTank.valid),
      phishTankPhishId: phishTank.phishId || null
    }
  };
}

function analyzeTextSignals(type, input) {
  const text = normalizeText(input);
  let score = 8;
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
    /\b(500|1000|2000|3000|5000)\s*(\$|usd|дол)|\bза\s*день\b|легк(і|ий)\s*гроші|без\s*досвіду.*(висок|зароб)/i;
  const deposit =
    /депозит|передоплат|активац|страхов(ий|ка)\s*внесок|внести\s*кошти|поповн(ити|ення)\s*баланс/i;
  const cardData =
    /cvv|cvc|номер\s*карт|термін\s*дії|код\s*(з|із)\s*sms|pin|парол|одноразов(ий|ого)\s*код/i;
  const urgency =
    /терміново|прямо\s*зараз|10\s*хвилин|5\s*хвилин|обмежен(а|ий)\s*час|тільки\s*сьогодні/i;
  const suspiciousFile = /\.apk\b|\.exe\b|\.scr\b|\.msi\b|\.zip\b/i;
  const shortener = /bit\.ly|tinyurl|t\.co|cutt\.ly|goo\.gl|is\.gd/i;
  const telegram = /t\.me\/|telegram|@\w{4,}/i;

  if (moneyPromises.test(text)) add(22, "Є агресивна або нереалістична обіцянка заробітку");

  if (deposit.test(text)) {
    add(26, "Просять депозит / передоплату / платну активацію");
    actions.add("Не переказуйте гроші за «активацію роботи», «страхування» або доступ до завдань.");
  }

  if (cardData.test(text)) {
    add(30, "Є запит на чутливі банківські або авторизаційні дані");
    actions.add("Не вводьте повні реквізити картки, CVV, PIN або SMS-коди.");
  }

  if (urgency.test(text)) add(10, "Використовується тиск або штучна терміновість");

  if (suspiciousFile.test(text)) {
    add(18, "Є згадка або посилання на потенційно небезпечне завантаження");
  }

  if (shortener.test(text)) {
    add(8, "Використовується скорочене посилання, яке приховує кінцеву адресу");
  }

  if (type === "job") {
    if (telegram.test(text)) {
      add(6, "Вакансія переводить спілкування в Telegram");
    }

    if (/став(ити|те)\s*лайк|оцінювати\s*товар|викуп\s*товар|task\s*scam|виконувати\s*завдання.*комісі/i.test(text)) {
      add(24, "Опис схожий на схему з платними завданнями / фіктивним викупом товару");
      actions.add("Не поповнюйте баланс і не «викуповуйте» товари за власні кошти для отримання комісії.");
    }

    if (/отримувати\s*переказ|приймати\s*гроші.*карт|транзит.*карт|передавати\s*кошти.*далі/i.test(text)) {
      add(30, "Пропонують використовувати вашу картку для приймання або транзиту чужих коштів");
      actions.add("Не використовуйте особисту картку як транзитний рахунок для незнайомих осіб.");
    }

    if (/без\s*співбесід|без\s*резюме|без\s*оформлення|без\s*договору/i.test(text)) {
      add(8, "Є ознаки роботи без звичайної перевірки роботодавця або оформлення");
    }
  }

  if (type === "seller") {
    if (/тільки\s*передоплат|повн(а|у)\s*передоплат|без\s*налож|на\s*карт(у|ку)|скиньте\s*кошти/i.test(text)) {
      add(18, "Продавець наполягає на передоплаті або прямому переказі");
      actions.add("За можливості використовуйте післяплату або сервіс із захистом покупця.");
    }

    if (/ціна.*(на\s*)?(30|40|50|60|70)%.*ниж|вдвічі\s*дешев|значно\s*дешевше\s*ринку/i.test(text)) {
      add(14, "Заявлена ціна виглядає суттєво нижчою за типову");
    }

    if (/не\s*можу.*відео|без\s*відеодзвін|не\s*покажу.*товар/i.test(text)) {
      add(10, "Продавець уникає додаткової перевірки товару");
    }
  }

  if (type === "contact") {
    if (/перейдімо|пиши|напиши.*(telegram|whatsapp|вайбер|viber)/i.test(text)) {
      add(5, "Співрозмовник намагається перевести контакт в інший месенджер");
    }
  }

  return { score, reasons, actions };
}

async function getApprovedDbReports() {
  if (!databaseReady || !pool) return [];
  try {
    const { rows } = await pool.query(`
      SELECT code, target, target_key, type, reason, details, status, updated_at
      FROM community_reports
      WHERE status = 'approved'
      ORDER BY updated_at DESC
      LIMIT 500
    `);
    return rows.map((row) => ({
      code: row.code,
      target: row.target,
      targetKey: row.target_key,
      type: row.type,
      reason: row.reason,
      details: row.details,
      status: row.status,
      statusLabel: "Перевірено модерацією",
      updatedAt: new Date(row.updated_at).toLocaleDateString("uk-UA")
    }));
  } catch (error) {
    console.error("Approved reports query failed:", error.message);
    return [];
  }
}

async function findCommunityMatches(input) {
  const text = normalizeText(input);
  const candidates = new Set();

  const url = extractFirstUrl(input);
  if (url) {
    try {
      candidates.add(new URL(url).hostname.toLowerCase().replace(/^www\./, ""));
    } catch {}
  }

  for (const match of text.matchAll(/@([a-z0-9_]{4,})/gi)) {
    candidates.add(`@${match[1].toLowerCase()}`);
  }

  for (const match of text.matchAll(/[+\d][\d\s().-]{7,}/g)) {
    const digits = match[0].replace(/\D/g, "");
    if (digits.length >= 8) candidates.add(digits);
  }

  for (const match of text.matchAll(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi)) {
    candidates.add(match[0].toLowerCase());
  }

  const approved = [...demoApprovedReports, ...(await getApprovedDbReports())];
  const matches = approved.filter((report) => {
    const key = normalizeTargetKey(report.targetKey || report.target);
    if (!key) return false;
    return candidates.has(key) || (key.length >= 8 && text.includes(key));
  });

  return matches;
}

async function analyzeInput(type, input) {
  const safeType = ALLOWED_TYPES.has(type) ? type : "seller";
  const textAnalysis = analyzeTextSignals(safeType, input);
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
  } else if (safeType === "link") {
    reasons.push("У введених даних не знайдено коректного URL");
    score += 8;
  }

  const communityMatches = await findCommunityMatches(input);
  if (communityMatches.length) {
    const moderatedMatches = communityMatches.filter((x) => !String(x.code).startsWith("DEMO-"));
    if (moderatedMatches.length) {
      const points = Math.min(28, 12 + (moderatedMatches.length - 1) * 5);
      score += points;
      reasons.push(`У модерованій базі SafeDeal знайдено збігів: ${moderatedMatches.length}`);
      actions.add("Перегляньте записи в базі скарг і перевірте факти перед оплатою або передачею даних.");
    }
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
    type: safeType,
    score,
    level,
    label,
    reasons: [...new Set(reasons)],
    facts: [...new Set(facts)],
    actions: [...actions],
    technical,
    communityMatches: communityMatches.length,
    disclaimer:
      "Це автоматична оцінка ризику, а не твердження про шахрайство, юридичний висновок чи гарантія безпеки. Перевіряйте факти самостійно."
  };
}

function makeReportCode() {
  return `C-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
}

function validateReportBody(body = {}) {
  const target = compactSpaces(body.target || "");
  const type = ALLOWED_TYPES.has(body.type) && body.type !== "text" ? body.type : "seller";
  const reason = compactSpaces(body.reason || "");
  const details = compactSpaces(body.details || "");

  if (target.length < 3 || target.length > 240) return { ok: false, error: "invalid_target" };
  if (reason.length < 5 || reason.length > 500) return { ok: false, error: "invalid_reason" };
  if (details.length > 2000) return { ok: false, error: "details_too_long" };

  const forbiddenSecrets = /\b(cvv|cvc|pin)\b|код\s*(з|із)\s*sms|парол/i;
  if (forbiddenSecrets.test(`${reason} ${details}`)) {
    return { ok: false, error: "sensitive_data_not_allowed" };
  }

  return {
    ok: true,
    target,
    targetKey: normalizeTargetKey(target),
    type,
    reason,
    details
  };
}

const rateBuckets = new Map();
function rateLimit({ windowMs = 60 * 60 * 1000, max = 80 } = {}) {
  return (req, res, next) => {
    const key = req.ip || req.socket.remoteAddress || "unknown";
    const now = Date.now();
    const current = rateBuckets.get(key);

    if (!current || current.resetAt <= now) {
      rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    current.count += 1;
    if (current.count > max) {
      return res.status(429).json({ ok: false, error: "rate_limited" });
    }

    next();
  };
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "safedeal",
    webRiskConfigured: Boolean(GOOGLE_WEB_RISK_API_KEY),
    phishTankEnabled: true,
    phishTankKeyConfigured: Boolean(PHISHTANK_APP_KEY),
    databaseConfigured: Boolean(DATABASE_URL),
    databaseReady
  });
});

app.get("/api/community-alerts", (req, res) => {
  res.json({ ok: true, items: demoAlerts, demo: true });
});

app.get("/api/reports", async (req, res) => {
  const q = normalizeText(req.query.q || "").slice(0, 200);
  const type = String(req.query.type || "all");

  try {
    const dbItems = await getApprovedDbReports();
    const all = [...dbItems, ...demoApprovedReports];
    const items = all
      .filter((item) => type === "all" || item.type === type)
      .filter((item) => {
        if (!q) return true;
        return normalizeText(`${item.target} ${item.reason} ${item.details || ""}`).includes(q);
      })
      .slice(0, 50);

    res.json({
      ok: true,
      items,
      demo: items.some((x) => String(x.code).startsWith("DEMO-")),
      databaseReady
    });
  } catch (error) {
    console.error("Reports search error:", error);
    res.status(500).json({ ok: false, error: "reports_failed" });
  }
});

app.post("/api/reports", rateLimit({ max: 20 }), async (req, res) => {
  const valid = validateReportBody(req.body || {});
  if (!valid.ok) {
    return res.status(400).json({ ok: false, error: valid.error });
  }

  const code = makeReportCode();
  const report = {
    code,
    target: valid.target,
    targetKey: valid.targetKey,
    type: valid.type,
    reason: valid.reason,
    details: valid.details,
    status: "pending",
    createdAt: new Date().toISOString()
  };

  try {
    if (databaseReady && pool) {
      await pool.query(
        `INSERT INTO community_reports
          (code, target, target_key, type, reason, details, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending')`,
        [code, valid.target, valid.targetKey, valid.type, valid.reason, valid.details]
      );
    } else {
      memoryPendingReports.unshift(report);
      if (memoryPendingReports.length > 200) memoryPendingReports.pop();
    }

    res.status(201).json({
      ok: true,
      report: { code, status: "pending" },
      persistent: databaseReady
    });
  } catch (error) {
    console.error("Report submit error:", error);
    res.status(500).json({ ok: false, error: "report_submit_failed" });
  }
});

app.get("/api/reports/status/:code", async (req, res) => {
  const code = String(req.params.code || "").slice(0, 80);

  try {
    if (databaseReady && pool) {
      const { rows } = await pool.query(
        `SELECT code, status, created_at, updated_at FROM community_reports WHERE code = $1 LIMIT 1`,
        [code]
      );
      if (!rows.length) return res.status(404).json({ ok: false, error: "not_found" });
      return res.json({ ok: true, report: rows[0] });
    }

    const found = memoryPendingReports.find((x) => x.code === code);
    if (!found) return res.status(404).json({ ok: false, error: "not_found" });
    res.json({ ok: true, report: { code: found.code, status: found.status, createdAt: found.createdAt } });
  } catch (error) {
    res.status(500).json({ ok: false, error: "status_failed" });
  }
});

app.post("/api/check", rateLimit({ max: 80 }), async (req, res) => {
  const { type = "seller", input = "" } = req.body || {};

  if (!String(input).trim()) {
    return res.status(400).json({ ok: false, error: "input_required" });
  }

  if (String(input).length > 12000) {
    return res.status(413).json({ ok: false, error: "input_too_long" });
  }

  try {
    const report = await analyzeInput(type, input);
    res.json({ ok: true, report });
  } catch (error) {
    console.error("SafeDeal check error:", error);
    res.status(500).json({ ok: false, error: "check_failed" });
  }
});

app.use(express.static(__dirname));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

async function start() {
  await initDatabase();
  app.listen(PORT, () => {
    console.log(`SafeDeal started on port ${PORT}`);
    console.log(`Google Web Risk: ${GOOGLE_WEB_RISK_API_KEY ? "configured" : "not configured"}`);
    console.log(`PhishTank: enabled (${PHISHTANK_APP_KEY ? "API key configured" : "keyless / lower rate limit"})`);
    console.log(`Database: ${databaseReady ? "ready" : DATABASE_URL ? "configured but unavailable" : "not configured"}`);
  });
}

start().catch((error) => {
  console.error("SafeDeal startup error:", error);
  process.exit(1);
});
