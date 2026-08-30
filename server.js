require("dotenv").config();

const express = require("express");
const path = require("path");
const dns = require("dns").promises;
const net = require("net");
const http = require("http");
const https = require("https");
const tls = require("tls");
const crypto = require("crypto");
const { domainToUnicode } = require("url");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_WEB_RISK_API_KEY = process.env.GOOGLE_WEB_RISK_API_KEY || "";
const PHISHTANK_APP_KEY = process.env.PHISHTANK_APP_KEY || "";
const URLHAUS_AUTH_KEY = process.env.URLHAUS_AUTH_KEY || "";
const ABUSECH_AUTH_KEY = process.env.ABUSECH_AUTH_KEY || URLHAUS_AUTH_KEY;
const DATABASE_URL = process.env.DATABASE_URL || "";
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_FROM = process.env.RESEND_FROM || "SafeDeal <onboarding@resend.dev>";
const APP_BASE_URL = String(process.env.APP_BASE_URL || "https://safedeal-sqlg.onrender.com").replace(/\/+$/, "");
const SHOW_DEMO_DATA = String(process.env.SHOW_DEMO_DATA || "false").toLowerCase() === "true";
const APP_VERSION = "9.0.0";

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: "same-site" } }));
app.use((req, res, next) => {
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  if (req.path.startsWith("/api/") || req.path === "/admin") res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(compression());
app.use(express.json({ limit: "768kb", type: ["application/json", "application/*+json"] }));
app.use(express.urlencoded({ extended: false, limit: "256kb" }));
app.use(morgan("tiny"));

const ALLOWED_TYPES = new Set(["seller", "job", "link", "contact", "phone", "text", "facebook", "instagram", "whatsapp", "viber", "olx"]);

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
    await pool.query(`ALTER TABLE community_reports ADD COLUMN IF NOT EXISTS moderator_note TEXT NOT NULL DEFAULT ''`);
    await pool.query(`ALTER TABLE community_reports ADD COLUMN IF NOT EXISTS moderated_at TIMESTAMPTZ`);
    await pool.query(`ALTER TABLE community_reports ADD COLUMN IF NOT EXISTS submitter_client_id TEXT`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reports_target_key ON community_reports(target_key)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reports_status ON community_reports(status)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reports_submitter_client ON community_reports(submitter_client_id)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS client_profiles (
        client_id TEXT PRIMARY KEY,
        nickname TEXT NOT NULL DEFAULT 'Гість',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        nickname TEXT NOT NULL DEFAULT 'Гість',
        email_verified BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_login_at TIMESTAMPTZ
      )
    `);

    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS login_locked_until TIMESTAMPTZ`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        token_hash TEXT PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_reset_requests (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_requests(user_id, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_reset_expires ON password_reset_requests(expires_at)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS report_appeals (
        id UUID PRIMARY KEY,
        report_code TEXT NOT NULL,
        message TEXT NOT NULL,
        contact TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        moderator_note TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_report_appeals_status_created ON report_appeals(status, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_report_appeals_report_code ON report_appeals(report_code)`);

    await pool.query(`ALTER TABLE community_reports ADD COLUMN IF NOT EXISTS submitter_user_id UUID`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reports_submitter_user ON community_reports(submitter_user_id)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS check_history (
        id BIGSERIAL PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES client_profiles(client_id) ON DELETE CASCADE,
        report_id TEXT NOT NULL,
        type TEXT NOT NULL,
        input_preview TEXT NOT NULL,
        score INTEGER NOT NULL,
        level TEXT NOT NULL,
        label TEXT NOT NULL,
        reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(client_id, report_id)
      )
    `);
    await pool.query(`ALTER TABLE check_history ADD COLUMN IF NOT EXISTS user_id UUID`);

    // Evidence-backed archive for reviews that were previously public and later
    // disappeared/changed. SafeDeal only displays rows marked verified; absence
    // of a row must never be presented as proof that a platform deleted a review.
    await pool.query(`
      CREATE TABLE IF NOT EXISTS review_evidence (
        id BIGSERIAL PRIMARY KEY,
        target_key TEXT NOT NULL,
        platform TEXT NOT NULL DEFAULT '',
        source_url TEXT NOT NULL DEFAULT '',
        archived_text TEXT NOT NULL DEFAULT '',
        summary TEXT NOT NULL DEFAULT '',
        evidence_type TEXT NOT NULL DEFAULT 'snapshot_diff',
        first_seen_at TIMESTAMPTZ,
        missing_at TIMESTAMPTZ,
        status TEXT NOT NULL DEFAULT 'verified',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_review_evidence_target ON review_evidence(target_key, status, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_review_evidence_platform ON review_evidence(platform, status, created_at DESC)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS target_snapshots (
        id BIGSERIAL PRIMARY KEY,
        target_key TEXT NOT NULL,
        type TEXT NOT NULL,
        score INTEGER NOT NULL DEFAULT 0,
        label TEXT NOT NULL DEFAULT '',
        scheme_key TEXT NOT NULL DEFAULT '',
        complaint_count INTEGER NOT NULL DEFAULT 0,
        review_count INTEGER NOT NULL DEFAULT 0,
        snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_target_snapshots_target ON target_snapshots(target_key, type, created_at DESC)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS object_entities (
        id BIGSERIAL PRIMARY KEY,
        target_key TEXT NOT NULL,
        type TEXT NOT NULL,
        entity_kind TEXT NOT NULL,
        entity_value TEXT NOT NULL,
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(target_key, type, entity_kind, entity_value)
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_object_entities_value ON object_entities(entity_kind, entity_value, last_seen_at DESC)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS watch_items (
        id BIGSERIAL PRIMARY KEY,
        owner_key TEXT NOT NULL,
        target_key TEXT NOT NULL,
        type TEXT NOT NULL,
        target_preview TEXT NOT NULL DEFAULT '',
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(owner_key, target_key, type)
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_watch_items_owner ON watch_items(owner_key, active, updated_at DESC)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS watch_events (
        id BIGSERIAL PRIMARY KEY,
        owner_key TEXT NOT NULL,
        target_key TEXT NOT NULL,
        type TEXT NOT NULL,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        before_score INTEGER,
        after_score INTEGER,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_watch_events_owner ON watch_events(owner_key, created_at DESC)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS shared_checks (
        share_id TEXT PRIMARY KEY,
        report JSONB NOT NULL,
        input_preview TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS image_fingerprints (
        id BIGSERIAL PRIMARY KEY,
        ahash TEXT NOT NULL,
        target_key TEXT NOT NULL DEFAULT '',
        target_preview TEXT NOT NULL DEFAULT '',
        source_label TEXT NOT NULL DEFAULT 'SafeDeal user check',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_image_fingerprints_hash ON image_fingerprints(ahash, created_at DESC)`);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_check_history_client_created ON check_history(client_id, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_check_history_user_created ON check_history(user_id, created_at DESC)`);
    await pool.query(`DELETE FROM auth_sessions WHERE expires_at <= NOW()`);
    await pool.query(`DELETE FROM password_reset_requests WHERE expires_at <= NOW() OR used_at IS NOT NULL`);
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

function getClientId(req) {
  const value = String(req.get("x-client-id") || "").trim();
  return /^[a-zA-Z0-9_-]{12,80}$/.test(value) ? value : "";
}

function normalizeEmail(value = "") {
  return String(value).trim().toLowerCase().slice(0, 254);
}

function validEmail(value = "") {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
}

function validNewPassword(value = "") {
  const password = String(value || "");
  return password.length >= 10 && password.length <= 128 && /[A-Za-zА-Яа-яІіЇїЄє]/.test(password) && /\d/.test(password);
}

function parseCookies(req) {
  const header = String(req.headers.cookie || "");
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 1) continue;
    const key = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    try { out[key] = decodeURIComponent(value); } catch { out[key] = value; }
  }
  return out;
}

function sessionTokenHash(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) reject(error); else resolve(derivedKey);
    });
  });
}

async function createPasswordHash(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = await scryptAsync(password, salt);
  return `scrypt$${salt}$${hash.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const expected = Buffer.from(parts[2], "hex");
  if (!expected.length) return false;
  const actual = await scryptAsync(password, parts[1]);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function setSessionCookie(res, token) {
  const maxAge = 30 * 24 * 60 * 60;
  res.setHeader("Set-Cookie", `sd_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`);
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", "sd_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
}

async function getAuthUser(req) {
  if (!databaseReady || !pool) return null;
  const token = parseCookies(req).sd_session || "";
  if (!token || token.length > 200) return null;
  const tokenHash = sessionTokenHash(token);
  const { rows } = await pool.query(
    `SELECT u.id, u.email, u.nickname, u.email_verified, u.created_at
     FROM auth_sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.expires_at > NOW() LIMIT 1`,
    [tokenHash]
  );
  return rows[0] || null;
}

async function createAuthSession(res, userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const tokenHash = sessionTokenHash(token);
  await pool.query(
    `INSERT INTO auth_sessions (token_hash, user_id, expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '30 days')`,
    [tokenHash, userId]
  );
  setSessionCookie(res, token);
}

async function sendPasswordResetEmail(email, resetToken) {
  if (!RESEND_API_KEY) return false;

  const resetUrl = new URL("/reset-password", APP_BASE_URL);
  resetUrl.searchParams.set("token", resetToken);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: RESEND_FROM,
        to: [email],
        subject: "Відновлення пароля SafeDeal",
        text: `Хтось запросив зміну пароля SafeDeal. Посилання діє 30 хвилин: ${resetUrl.toString()}\n\nЯкщо це були не ви — просто проігноруйте цей лист.`,
        html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#0b1727">
          <h2>Відновлення пароля SafeDeal</h2>
          <p>Ми отримали запит на зміну пароля вашого акаунта.</p>
          <p><a href="${resetUrl.toString()}" style="display:inline-block;padding:12px 18px;background:#2587ff;color:#fff;text-decoration:none;border-radius:10px;font-weight:700">Створити новий пароль</a></p>
          <p>Посилання дійсне 30 хвилин і може бути використане лише один раз.</p>
          <p style="color:#667085;font-size:13px">Якщо ви не надсилали цей запит — просто проігноруйте лист.</p>
        </div>`
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      console.error("Password reset email failed:", response.status, body.slice(0, 180));
      return false;
    }
    return true;
  } catch (error) {
    console.error("Password reset email failed:", error.name === "AbortError" ? "timeout" : error.message);
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function attachAnonymousDataToUser(userId, clientId) {
  if (!databaseReady || !pool || !userId || !clientId) return;
  await ensureClientProfile(clientId);
  await pool.query(`UPDATE check_history SET user_id = $1 WHERE client_id = $2 AND user_id IS NULL`, [userId, clientId]);
  await pool.query(`UPDATE community_reports SET submitter_user_id = $1 WHERE submitter_client_id = $2 AND submitter_user_id IS NULL`, [userId, clientId]);
}

async function ensureClientProfile(clientId) {
  if (!databaseReady || !pool || !clientId) return false;
  await pool.query(
    `INSERT INTO client_profiles (client_id) VALUES ($1)
     ON CONFLICT (client_id) DO UPDATE SET last_seen_at = NOW()`,
    [clientId]
  );
  return true;
}

async function saveCheckHistory(clientId, userId, report, input) {
  if (!databaseReady || !pool || !clientId || !report) return false;
  await ensureClientProfile(clientId);
  await pool.query(
    `INSERT INTO check_history
      (client_id, user_id, report_id, type, input_preview, score, level, label, reasons)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
     ON CONFLICT (client_id, report_id) DO UPDATE SET user_id = COALESCE(check_history.user_id, EXCLUDED.user_id)`,
    [
      clientId,
      userId || null,
      String(report.id || `R-${Date.now()}`).slice(0, 80),
      String(report.type || "seller").slice(0, 24),
      compactSpaces(input || "").slice(0, 500),
      Math.max(0, Math.min(100, Number(report.score) || 0)),
      String(report.level || "low").slice(0, 24),
      String(report.label || "").slice(0, 80),
      JSON.stringify(Array.isArray(report.reasons) ? report.reasons.slice(0, 20) : [])
    ]
  );
  return true;
}

function normalizeTargetKey(value = "") {
  const raw = compactSpaces(value).toLowerCase();
  if (!raw) return "";

  const phoneDigits = raw.replace(/\D/g, "");
  if (/^[+\d\s().-]{8,}$/.test(raw) && phoneDigits.length >= 8) {
    const normalizedPhone = extractPhoneTarget(raw);
    return normalizedPhone?.valid ? normalizedPhone.digits : phoneDigits;
  }

  const telegramMatch = raw.match(/(?:https?:\/\/)?t\.me\/([a-z0-9_]{4,})/i);
  if (telegramMatch) return `@${telegramMatch[1].toLowerCase()}`;

  const usernameMatch = raw.match(/^@([a-z0-9_]{4,})$/i);
  if (usernameMatch) return `@${usernameMatch[1].toLowerCase()}`;


  try {
    const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const parsed = new URL(withProtocol);
    const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
    const path = decodeURIComponent(parsed.pathname || "/").replace(/\/+/g, "/").replace(/\/$/, "");

    if (host === "instagram.com" && /^\/[a-z0-9._]{2,30}$/i.test(path)) {
      return `instagram:${path.toLowerCase()}`;
    }
    if ((host === "facebook.com" || host === "m.facebook.com" || host === "fb.com") && path.length > 1) {
      return `facebook:${path.toLowerCase().slice(0, 170)}`;
    }
    if ((host === "wa.me" || host === "api.whatsapp.com" || host === "whatsapp.com")) {
      const digits = `${path} ${parsed.searchParams.get("phone") || ""}`.replace(/\D/g, "");
      if (digits.length >= 8) return digits;
    }
    if ((host === "invite.viber.com" || host === "viber.com" || host === "vb.me") && path.length > 1) {
      return `viber:${host}${path}`.slice(0, 220);
    }
    if (host.startsWith("olx.") && path.length > 1) {
      return `olx:${host}${path}`.slice(0, 220);
    }
  } catch {}

  try {
    const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const parsed = new URL(withProtocol);
    if (parsed.hostname && parsed.hostname.includes(".")) {
      return parsed.hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
    }
  } catch {}

  return raw.slice(0, 220);
}


function extractPhoneTarget(input = "") {
  const raw = compactSpaces(input || "");
  if (!raw) return null;

  const match = raw.match(/(?:\+?\d[\d\s().-]{6,}\d)/);
  if (!match) return null;

  const original = compactSpaces(match[0]);
  let digits = original.replace(/\D/g, "");
  if (digits.length < 8 || digits.length > 15) return null;

  // Ukrainian local mobile/landline notation: 0XXXXXXXXX -> +380XXXXXXXXX.
  if (digits.length === 10 && digits.startsWith("0")) {
    digits = `38${digits}`;
  }

  const normalized = `+${digits}`;
  const isUkraine = digits.length === 12 && digits.startsWith("380");
  const validE164 = digits.length >= 8 && digits.length <= 15 && !/^0+$/.test(digits);

  return {
    original,
    digits,
    normalized,
    valid: validE164,
    country: isUkraine ? "Україна (+380)" : "Країну автоматично не підтверджено"
  };
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


const BRAND_PROFILES = [
  {
    brand: "Google",
    aliases: ["google", "gmail"],
    officialDomains: ["google.com", "gmail.com", "googleusercontent.com", "gstatic.com", "googleapis.com", "youtube.com"]
  },
  {
    brand: "PayPal",
    aliases: ["paypal"],
    officialDomains: ["paypal.com"]
  },
  {
    brand: "Apple",
    aliases: ["apple", "icloud"],
    officialDomains: ["apple.com", "icloud.com"]
  },
  {
    brand: "Microsoft",
    aliases: ["microsoft", "outlook", "office", "onedrive"],
    officialDomains: ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com", "onedrive.com"]
  },
  {
    brand: "Amazon",
    aliases: ["amazon"],
    officialDomains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.pl", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca", "amazon.co.jp"]
  },
  {
    brand: "Facebook",
    aliases: ["facebook"],
    officialDomains: ["facebook.com", "fb.com", "fb.me", "meta.com"]
  },
  {
    brand: "Instagram",
    aliases: ["instagram"],
    officialDomains: ["instagram.com"]
  },
  {
    brand: "Telegram",
    aliases: ["telegram"],
    officialDomains: ["telegram.org", "t.me"]
  },
  {
    brand: "WhatsApp",
    aliases: ["whatsapp"],
    officialDomains: ["whatsapp.com", "wa.me"]
  },
  {
    brand: "Viber",
    aliases: ["viber"],
    officialDomains: ["viber.com", "invite.viber.com", "vb.me"]
  },
  {
    brand: "Steam",
    aliases: ["steam", "steamcommunity", "steampowered"],
    officialDomains: ["steampowered.com", "steamcommunity.com", "steamgames.com"]
  },
  {
    brand: "Discord",
    aliases: ["discord"],
    officialDomains: ["discord.com", "discord.gg"]
  },
  {
    brand: "Binance",
    aliases: ["binance"],
    officialDomains: ["binance.com"]
  },
  {
    brand: "ПриватБанк",
    aliases: ["privatbank", "privat24", "приватбанк", "приват24"],
    officialDomains: ["privatbank.ua", "privat24.ua"]
  },
  {
    brand: "monobank",
    aliases: ["monobank"],
    officialDomains: ["monobank.ua"]
  },
  {
    brand: "OLX",
    aliases: ["olx"],
    officialDomains: ["olx.ua", "olx.pl", "olx.ro", "olx.bg", "olx.kz", "olx.uz", "olx.pt"]
  },
  {
    brand: "Нова пошта",
    aliases: ["novaposhta", "nova poshta", "нова пошта", "новапошта"],
    officialDomains: ["novaposhta.ua"]
  }
];

const COMMON_MULTI_LEVEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk",
  "com.ua", "net.ua", "org.ua", "gov.ua",
  "com.au", "net.au", "org.au",
  "co.jp", "co.kr", "co.in", "com.br", "com.tr"
]);

const CONFUSABLE_MAP = new Map(Object.entries({
  // Cyrillic look-alikes.
  "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ї": "i", "ј": "j", "ӏ": "l", "ԛ": "q",
  // Greek look-alikes.
  "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p", "τ": "t", "υ": "y", "χ": "x", "ν": "v",
  // ASCII digit/symbol substitutions often used in typosquatting.
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"
}));

function isOfficialBrandHost(hostname, profile) {
  const host = String(hostname || "").toLowerCase().replace(/^www\./, "");
  return profile.officialDomains.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

function sameOfficialBrandFamilyHost(a, b) {
  const hostA = String(a || "").toLowerCase().replace(/^www\./, "");
  const hostB = String(b || "").toLowerCase().replace(/^www\./, "");
  if (!hostA || !hostB) return false;

  return BRAND_PROFILES.some((profile) =>
    isOfficialBrandHost(hostA, profile) && isOfficialBrandHost(hostB, profile)
  );
}

function siteKey(hostname = "") {
  const labels = String(hostname).toLowerCase().replace(/^www\./, "").split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const suffix2 = labels.slice(-2).join(".");
  if (COMMON_MULTI_LEVEL_SUFFIXES.has(suffix2) && labels.length >= 3) {
    return labels.slice(-3).join(".");
  }
  return suffix2;
}

function sameSiteHost(a, b) {
  if (!a || !b) return false;
  return siteKey(a) === siteKey(b);
}

function scriptKinds(value = "") {
  const kinds = [];
  if (/\p{Script=Latin}/u.test(value)) kinds.push("latin");
  if (/\p{Script=Cyrillic}/u.test(value)) kinds.push("cyrillic");
  if (/\p{Script=Greek}/u.test(value)) kinds.push("greek");
  return kinds;
}

function visualSkeleton(value = "") {
  let normalized = String(value)
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[\u0300-\u036f]/g, "");

  let out = "";
  for (const char of normalized) out += CONFUSABLE_MAP.get(char) || char;

  return out
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/[^a-z0-9]/g, "");
}

function levenshteinDistance(a = "", b = "") {
  const x = String(a);
  const y = String(b);
  if (x === y) return 0;
  if (!x.length) return y.length;
  if (!y.length) return x.length;

  let prev = Array.from({ length: y.length + 1 }, (_, i) => i);
  for (let i = 1; i <= x.length; i++) {
    const curr = [i];
    for (let j = 1; j <= y.length; j++) {
      curr[j] = Math.min(
        curr[j - 1] + 1,
        prev[j] + 1,
        prev[j - 1] + (x[i - 1] === y[j - 1] ? 0 : 1)
      );
    }
    prev = curr;
  }
  return prev[y.length];
}

function analyzeDomainSpoof(rawUrl, parsed) {
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  const unicodeHostname = domainToUnicode(hostname) || hostname;
  const labels = unicodeHostname.split(".").filter(Boolean);
  const punycode = hostname.split(".").some((label) => label.startsWith("xn--"));
  const mixedScriptLabels = labels.filter((label) => {
    if (!/[^\x00-\x7F]/.test(label)) return false;
    return scriptKinds(label).length >= 2;
  });

  const authorityMatch = String(rawUrl).match(/^https?:\/\/([^/?#]*)/i);
  const rawAuthority = authorityMatch ? authorityMatch[1] : "";
  const encodedAuthority = /%[0-9a-f]{2}/i.test(rawAuthority);
  const bidiOrInvisible = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u.test(String(rawUrl));
  const encodedSequences = (String(rawUrl).match(/%[0-9a-f]{2}/gi) || []).length;
  const longUrl = String(rawUrl).length > 220;
  const longHostname = hostname.length > 70;
  const nonStandardPort = Boolean(parsed.port) && !(
    (parsed.protocol === "https:" && parsed.port === "443") ||
    (parsed.protocol === "http:" && parsed.port === "80")
  );

  let brandImpersonation = false;
  let brandTarget = null;
  let brandKind = null;
  let brandEvidence = null;
  let brandDistance = null;

  for (const profile of BRAND_PROFILES) {
    if (isOfficialBrandHost(hostname, profile)) continue;

    for (const unicodeLabel of labels) {
      const plainLabel = unicodeLabel.toLowerCase().replace(/[^\p{L}\p{N}-]/gu, "");
      const skeleton = visualSkeleton(plainLabel);

      for (const alias of profile.aliases) {
        const aliasSkeleton = visualSkeleton(alias);
        if (!aliasSkeleton || skeleton.length < 4) continue;

        if (skeleton === aliasSkeleton && plainLabel !== alias) {
          brandImpersonation = true;
          brandTarget = profile.brand;
          brandKind = "visual";
          brandEvidence = unicodeLabel;
          brandDistance = 0;
          break;
        }

        const distance = levenshteinDistance(skeleton, aliasSkeleton);
        const maxDistance = aliasSkeleton.length >= 8 ? 1 : (aliasSkeleton.length >= 5 ? 1 : 0);
        if (distance <= maxDistance && skeleton !== aliasSkeleton) {
          brandImpersonation = true;
          brandTarget = profile.brand;
          brandKind = "typo";
          brandEvidence = unicodeLabel;
          brandDistance = distance;
          break;
        }

        if (skeleton.includes(aliasSkeleton) && skeleton !== aliasSkeleton && aliasSkeleton.length >= 5) {
          brandImpersonation = true;
          brandTarget = profile.brand;
          brandKind = "keyword";
          brandEvidence = unicodeLabel;
          brandDistance = null;
          break;
        }
      }
      if (brandImpersonation) break;
    }
    if (brandImpersonation) break;
  }

  return {
    unicodeHostname,
    punycode,
    mixedScript: mixedScriptLabels.length > 0,
    mixedScriptLabels: mixedScriptLabels.slice(0, 3),
    brandImpersonation,
    brandTarget,
    brandKind,
    brandEvidence,
    brandDistance,
    encodedAuthority,
    bidiOrInvisible,
    encodedSequences,
    longUrl,
    longHostname,
    nonStandardPort
  };
}

function scoreToLevel(score) {
  if (score >= 76) return { level: "very-high", label: "Критичний ризик" };
  if (score >= 51) return { level: "high", label: "Високий ризик" };
  if (score >= 26) return { level: "medium", label: "Підвищений ризик" };
  if (score <= 10) return { level: "low", label: "Дуже низький ризик" };
  return { level: "low", label: "Низький ризик" };
}


function buildHumanVerdict({ score, type, telegram, phone, phoneModeratedMatches = 0, sellerModeratedMatches = 0, sellerExactPhoneMatches = 0, moderatedMatchesCount = 0, platform = null }) {
  const telegramLimited =
    type === "contact" &&
    telegram &&
    telegram.kind !== "invite" &&
    !telegram.publicPreviewOk &&
    !telegram.publicPostsOk;

  const privateInviteLimited = type === "contact" && telegram?.kind === "invite";

  const platformLimited =
    PLATFORM_CHECKS[type] &&
    platform &&
    (!platform.ok || (platform.limited && moderatedMatchesCount === 0));



  if (type === "phone" && !phone?.valid) {
    return {
      kind: "limited",
      title: "Не вдалося розпізнати номер",
      text: "Введіть повний номер телефону, бажано у міжнародному форматі, наприклад +380…",
      evidence: "Номер не перевірено"
    };
  }

  if (type === "phone" && phone?.valid && phoneModeratedMatches === 0 && score < 26) {
    return {
      kind: "ok",
      title: "Збігів у базі SafeDeal не знайдено",
      text: "Цей номер не збігся з модерованими скаргами SafeDeal. Це не підтверджує особу власника номера і не гарантує безпеку угоди.",
      evidence: "Перевірено точний номер"
    };
  }

  if (type === "phone" && phoneModeratedMatches > 0) {
    return {
      kind: score >= 51 ? "danger" : "warning",
      title: "Є підтверджені скарги на цей номер",
      text: `У модерованій базі SafeDeal знайдено підтверджених скарг: ${phoneModeratedMatches}. Перегляньте записи та не переказуйте гроші без додаткової перевірки.`,
      evidence: `Точних збігів: ${phoneModeratedMatches}`
    };
  }

  if (type === "seller" && sellerModeratedMatches > 0) {
    const exactText = sellerExactPhoneMatches > 0
      ? ` Точних збігів за номером телефону: ${sellerExactPhoneMatches}.`
      : "";
    return {
      kind: score >= 51 ? "danger" : "warning",
      title: "Є попередження щодо цього продавця",
      text: `У модерованій базі SafeDeal знайдено підтверджених скарг: ${sellerModeratedMatches}.${exactText} Перевірте деталі перед оплатою або передачею даних.`,
      evidence: `Підтверджених збігів: ${sellerModeratedMatches}`
    };
  }

  if (moderatedMatchesCount > 0) {
    return {
      kind: score >= 51 ? "danger" : "warning",
      title: "Є підтверджені попередження у базі SafeDeal",
      text: `Знайдено модерованих збігів: ${moderatedMatchesCount}. Це не є доказом шахрайства, але перед оплатою або передачею даних потрібна додаткова перевірка.`,
      evidence: `Модерованих збігів: ${moderatedMatchesCount}`
    };
  }


  if (platformLimited && score < 26) {
    return {
      kind: "limited",
      title: "Недостатньо публічних даних",
      text: `SafeDeal перевірив доступні сигнали ${platform?.label || "платформи"} та базу скарг, але цих даних недостатньо, щоб назвати профіль безпечним.`,
      evidence: moderatedMatchesCount > 0 ? `Збігів у базі: ${moderatedMatchesCount}` : "Точних підтверджених збігів не знайдено"
    };
  }

  if ((telegramLimited || privateInviteLimited) && score < 26) {
    return {
      kind: "limited",
      title: "Недостатньо даних для точної оцінки",
      text: "SafeDeal не бачить достатньо публічної інформації про цей Telegram. Завантажте скріншот пропозиції або вставте її текст.",
      evidence: "Обмежені дані"
    };
  }

  if (score >= 76) {
    return {
      kind: "danger",
      title: "Дуже високий ризик",
      text: "Знайдено кілька сильних сигналів ризику. Не надсилайте гроші, документи, паролі або коди підтвердження.",
      evidence: telegram?.publicPostsOk ? "Перевірено публічні пости" : "Сильні сигнали"
    };
  }

  if (score >= 51) {
    return {
      kind: "danger",
      title: "Високий ризик",
      text: "Є серйозні підозрілі ознаки. Не поспішайте виконувати інструкції та не переказуйте гроші без незалежної перевірки.",
      evidence: telegram?.publicPostsOk ? "Перевірено публічні пости" : "Є сильні сигнали"
    };
  }

  if (score >= 26) {
    return {
      kind: "warning",
      title: "Є підозрілі ознаки",
      text: "SafeDeal знайшов сигнали, які потребують додаткової перевірки. Перегляньте причини нижче.",
      evidence: telegram?.publicPostsOk ? "Перевірено публічні пости" : "Часткова перевірка"
    };
  }

  return {
    kind: "ok",
    title: "Явних ознак шахрайства не знайдено",
    text: "У доступних SafeDeal даних немає сильних типових сигналів ризику. Це не гарантія безпеки — перевіряйте факти перед оплатою або передачею даних.",
    evidence: telegram?.publicPostsOk ? `Перевірено публічні пости: ${telegram.recentPostsCount}` : "Перевірено доступні дані"
  };
}

function parseRdapRegistrationDate(rdap) {
  const events = Array.isArray(rdap?.events) ? rdap.events : [];
  const preferredActions = new Set(["registration", "registered", "creation", "created"]);
  const candidates = events
    .filter((event) => preferredActions.has(String(event?.eventAction || "").toLowerCase()))
    .map((event) => new Date(event?.eventDate))
    .filter((date) => !Number.isNaN(date.getTime()));

  if (!candidates.length) return null;
  candidates.sort((a, b) => a.getTime() - b.getTime());
  return candidates[0];
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

async function fetchJsonWithTimeout(url, timeoutMs = 4500, headers = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers
    });
    if (!response.ok) return { ok: false, status: response.status, data: null };
    const data = await response.json();
    return { ok: true, status: response.status, data };
  } catch (error) {
    return { ok: false, error: error.name || "fetch_failed", data: null };
  } finally {
    clearTimeout(timer);
  }
}

let rdapBootstrapCache = { expiresAt: 0, data: null };

async function getRdapBootstrap() {
  if (rdapBootstrapCache.data && rdapBootstrapCache.expiresAt > Date.now()) {
    return rdapBootstrapCache.data;
  }

  const result = await fetchJsonWithTimeout(
    "https://data.iana.org/rdap/dns.json",
    4500,
    { Accept: "application/json", "User-Agent": "SafeDeal/1.0" }
  );

  if (!result.ok || !Array.isArray(result.data?.services)) return null;
  rdapBootstrapCache = {
    data: result.data,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000
  };
  return result.data;
}

async function getRegistryRdapBase(hostname) {
  const labels = String(hostname).toLowerCase().split(".").filter(Boolean);
  const tld = labels.at(-1);
  if (!tld) return null;

  const bootstrap = await getRdapBootstrap();
  if (!bootstrap) return null;

  for (const service of bootstrap.services || []) {
    const zones = Array.isArray(service?.[0]) ? service[0].map((x) => String(x).toLowerCase()) : [];
    const bases = Array.isArray(service?.[1]) ? service[1] : [];
    if (zones.includes(tld) && bases.length) return String(bases[0]);
  }
  return null;
}

function rdapResultFromData(data, source) {
  const registrationDate = parseRdapRegistrationDate(data);
  return {
    ok: true,
    source,
    registrationDate: registrationDate ? registrationDate.toISOString() : null,
    ageDays: registrationDate
      ? Math.max(0, Math.floor((Date.now() - registrationDate.getTime()) / 86400000))
      : null
  };
}

async function lookupRdap(hostname) {
  // Fast public proxy first.
  const publicResult = await fetchJsonWithTimeout(
    `https://rdap.org/domain/${encodeURIComponent(hostname)}`,
    4500,
    { Accept: "application/rdap+json, application/json", "User-Agent": "SafeDeal/1.0" }
  );

  if (publicResult.ok) {
    const parsed = rdapResultFromData(publicResult.data, "rdap.org");
    if (Number.isFinite(parsed.ageDays)) return parsed;
  }

  // Fallback to the authoritative registry selected from IANA's RDAP bootstrap.
  const base = await getRegistryRdapBase(hostname);
  if (base) {
    const registryUrl = `${base.replace(/\/?$/, "/")}domain/${encodeURIComponent(hostname)}`;
    const registryResult = await fetchJsonWithTimeout(
      registryUrl,
      5000,
      { Accept: "application/rdap+json, application/json", "User-Agent": "SafeDeal/1.0" }
    );
    if (registryResult.ok) return rdapResultFromData(registryResult.data, "registry");
  }

  return {
    ok: Boolean(publicResult.ok),
    source: publicResult.ok ? "rdap.org" : null,
    registrationDate: null,
    ageDays: null,
    status: publicResult.status || null,
    error: publicResult.error || "rdap_failed"
  };
}

function cleanHeaderValue(value = "") {
  return String(value).replace(/[\r\n]/g, " ").slice(0, 500);
}

async function resolvePublicAddress(hostname) {
  const result = await lookupDomain(hostname);
  if (!result.ok || !result.addresses.length) {
    return { ok: false, error: result.error || "dns_lookup_failed", addresses: [] };
  }
  if (result.hasPrivateAddress) {
    return { ok: false, error: "private_address", addresses: result.addresses };
  }
  const address = result.addresses.find((ip) => net.isIPv4(ip)) || result.addresses[0];
  if (!address || isPrivateOrReservedIp(address)) {
    return { ok: false, error: "no_public_address", addresses: result.addresses };
  }
  return { ok: true, address, family: net.isIPv6(address) ? 6 : 4, addresses: result.addresses };
}

function requestPublicUrlOnce(url, { timeoutMs = 6500, maxBytes = 280000 } = {}) {
  return new Promise(async (resolve) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return resolve({ ok: false, error: "invalid_url" });
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return resolve({ ok: false, error: "unsupported_protocol" });
    }

    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
    const target = await resolvePublicAddress(hostname);
    if (!target.ok) return resolve({ ok: false, error: target.error, hostname });

    const isHttps = parsed.protocol === "https:";
    const client = isHttps ? https : http;
    const port = parsed.port ? Number(parsed.port) : (isHttps ? 443 : 80);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return resolve({ ok: false, error: "invalid_port", hostname });
    }

    const options = {
      protocol: parsed.protocol,
      hostname: target.address,
      family: target.family,
      port,
      method: "GET",
      path: `${parsed.pathname || "/"}${parsed.search || ""}`,
      headers: {
        Host: parsed.host,
        "User-Agent": "SafeDeal-Security-Scanner/1.0",
        Accept: "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.2",
        "Accept-Encoding": "identity",
        Connection: "close"
      },
      agent: false
    };

    if (isHttps) {
      options.servername = hostname;
      // This scanner sends no credentials or cookies. We allow the handshake so
      // we can inspect sites with broken certificates, and report that separately.
      options.rejectUnauthorized = false;
    }

    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    const req = client.request(options, (res) => {
      const chunks = [];
      let total = 0;
      let truncated = false;

      res.on("data", (chunk) => {
        if (truncated) return;
        total += chunk.length;
        if (total > maxBytes) {
          truncated = true;
          const allowed = Math.max(0, maxBytes - (total - chunk.length));
          if (allowed) chunks.push(chunk.subarray(0, allowed));
          res.destroy();
          return;
        }
        chunks.push(chunk);
      });

      const done = () => {
        const socket = res.socket;
        let peer = null;
        let certHostError = null;
        if (isHttps && socket?.getPeerCertificate) {
          try {
            peer = socket.getPeerCertificate(true);
            if (peer && Object.keys(peer).length) {
              const err = tls.checkServerIdentity(hostname, peer);
              certHostError = err ? err.message : null;
            }
          } catch (error) {
            certHostError = error.message || "certificate_check_failed";
          }
        }

        finish({
          ok: true,
          status: Number(res.statusCode || 0),
          headers: res.headers || {},
          body: Buffer.concat(chunks).toString("utf8"),
          truncated,
          hostname,
          address: target.address,
          protocol: parsed.protocol,
          tls: isHttps ? {
            authorized: Boolean(socket?.authorized) && !certHostError,
            authorizationError: socket?.authorizationError || certHostError || null,
            validFrom: peer?.valid_from || null,
            validTo: peer?.valid_to || null,
            issuer: peer?.issuer?.O || peer?.issuer?.CN || null,
            subject: peer?.subject?.CN || null,
            protocol: socket?.getProtocol?.() || null
          } : null
        });
      };

      res.on("end", done);
      res.on("close", done);
    });

    req.setTimeout(timeoutMs, () => req.destroy(new Error("timeout")));
    req.on("error", (error) => finish({ ok: false, error: error.message || "request_failed", hostname }));
    req.end();
  });
}


function escapeRegex(value = "") {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizedVisiblePageText(html = "") {
  return compactSpaces(
    String(html)
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
      .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
      .replace(/<noscript\b[\s\S]*?<\/noscript>/gi, " ")
      .replace(/<svg\b[\s\S]*?<\/svg>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;|&#160;/gi, " ")
      .replace(/&amp;/gi, "&")
      .replace(/&quot;|&#34;/gi, '"')
      .replace(/&#39;|&apos;/gi, "'")
  ).slice(0, 120000);
}

function extractProminentPageText(html = "", title = "") {
  const source = String(html).slice(0, 280000);
  const parts = [title];
  const patterns = [
    /<(?:h1|h2)\b[^>]*>([\s\S]*?)<\/(?:h1|h2)>/gi,
    /<img\b[^>]*\balt\s*=\s*["']([^"']{1,160})["'][^>]*>/gi,
    /<(?:button|a)\b[^>]*>([^<>]{1,120})<\/(?:button|a)>/gi
  ];
  for (const re of patterns) {
    let count = 0;
    for (const match of source.matchAll(re)) {
      parts.push(String(match[1] || "").replace(/<[^>]+>/g, " "));
      if (++count >= 30) break;
    }
  }
  for (const match of source.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = match[0];
    if (!/(?:property|name)\s*=\s*["'](?:og:title|twitter:title|application-name|apple-mobile-web-app-title)["']/i.test(tag)) continue;
    const content = tag.match(/content\s*=\s*["']([^"']{1,200})["']/i);
    if (content) parts.push(content[1]);
  }
  return compactSpaces(parts.join(" ")).slice(0, 20000);
}

function aliasPresent(text = "", alias = "") {
  const hay = String(text).toLowerCase();
  const needle = String(alias).toLowerCase().trim();
  if (!needle) return false;
  if (/^[a-z0-9]+$/i.test(needle)) {
    const re = new RegExp(`(^|[^a-z0-9])${escapeRegex(needle)}([^a-z0-9]|$)`, "i");
    return re.test(hay);
  }
  return hay.includes(needle);
}

function detectPageBrandIdentity(html = "", pageUrl = "", title = "", sensitive = false) {
  let hostname = "";
  try { hostname = new URL(pageUrl).hostname.toLowerCase().replace(/^www\./, ""); } catch {}

  const prominent = extractProminentPageText(html, title);
  const visible = normalizedVisiblePageText(html);
  const officialHostProfile = BRAND_PROFILES.find((profile) => isOfficialBrandHost(hostname, profile)) || null;
  let best = null;

  for (const profile of BRAND_PROFILES) {
    const official = isOfficialBrandHost(hostname, profile);
    for (const alias of profile.aliases) {
      const inTitle = aliasPresent(title, alias);
      const inProminent = inTitle || aliasPresent(prominent, alias);
      const inVisible = aliasPresent(visible, alias);
      if (!inProminent && !(sensitive && inVisible)) continue;

      const strength = inTitle ? 4 : inProminent ? 3 : 2;

      // A legitimate official platform page can mention/link to other brands
      // (for example Viber mentioning Facebook). Do not call that impersonation
      // unless the page also requests sensitive credentials/payment/OTP.
      if (officialHostProfile && officialHostProfile.brand !== profile.brand && !sensitive) {
        continue;
      }

      const candidate = {
        detected: true,
        brand: profile.brand,
        alias,
        official,
        mismatch: !official,
        evidence: inTitle ? "title" : inProminent ? "prominent" : "sensitive-page",
        strength
      };
      if (!best || candidate.strength > best.strength) best = candidate;
    }
  }

  return best || {
    detected: false,
    brand: null,
    alias: null,
    official: false,
    mismatch: false,
    evidence: null,
    strength: 0
  };
}

function analyzeHtmlPage(html = "", pageUrl = "") {
  const text = String(html).slice(0, 280000);
  const lower = text.toLowerCase();
  const hasForm = /<form\b/i.test(text);
  const loginForm = /type\s*=\s*["']?password\b/i.test(text) || /autocomplete\s*=\s*["'](?:current-password|new-password)/i.test(text);
  const paymentForm = /(autocomplete\s*=\s*["'](?:cc-number|cc-csc|cc-exp)|name\s*=\s*["'][^"']*(?:card.?number|cvv|cvc|card.?expiry|expir)|id\s*=\s*["'][^"']*(?:card.?number|cvv|cvc))/i.test(text);
  const otpField = /(autocomplete\s*=\s*["']one-time-code|name\s*=\s*["'][^"']*(?:otp|sms.?code|verification.?code))/i.test(text);
  const walletSecretRequest = /(seed phrase|recovery phrase|secret phrase|private key|mnemonic phrase)/i.test(lower);
  const executableDownload = /href\s*=\s*["'][^"']+\.(?:apk|exe|msi|scr|bat|cmd)(?:[?#"'])/i.test(text);

  let externalFormAction = false;
  let pageHostname = "";
  try { pageHostname = new URL(pageUrl).hostname.toLowerCase(); } catch {}

  if (hasForm && pageHostname) {
    const actionRegex = /<form\b[^>]*\baction\s*=\s*["']([^"']+)["']/gi;
    for (const match of text.matchAll(actionRegex)) {
      try {
        const action = new URL(match[1], pageUrl);
        if (["http:", "https:"].includes(action.protocol) && action.hostname.toLowerCase() !== pageHostname) {
          externalFormAction = true;
          break;
        }
      } catch {}
    }
  }

  const titleMatch = text.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? compactSpaces(titleMatch[1].replace(/<[^>]+>/g, " ")).slice(0, 120) : "";
  const brandIdentity = detectPageBrandIdentity(
    text,
    pageUrl,
    title,
    loginForm || paymentForm || otpField
  );

  return {
    hasForm,
    loginForm,
    paymentForm,
    otpField,
    walletSecretRequest,
    executableDownload,
    externalFormAction,
    title,
    pageBrandDetected: Boolean(brandIdentity.detected),
    pageBrandTarget: brandIdentity.brand || null,
    pageBrandAlias: brandIdentity.alias || null,
    pageBrandOfficialDomain: Boolean(brandIdentity.official),
    pageBrandMismatch: Boolean(brandIdentity.mismatch),
    pageBrandEvidence: brandIdentity.evidence || null,
    pageBrandStrength: Number(brandIdentity.strength || 0)
  };
}

async function inspectRemotePage(rawUrl) {
  let current;
  try { current = new URL(rawUrl); } catch { return { ok: false, error: "invalid_url" }; }

  const initialProtocol = current.protocol;
  const initialHostname = current.hostname.toLowerCase();
  const chain = [];
  let last = null;

  for (let i = 0; i <= 3; i++) {
    const one = await requestPublicUrlOnce(current.href);
    if (!one.ok) {
      return {
        ok: false,
        error: one.error || "page_request_failed",
        redirects: chain.length,
        finalUrl: current.href,
        finalHostname: current.hostname.toLowerCase(),
        chain
      };
    }

    last = one;
    chain.push({
      status: one.status,
      hostname: current.hostname.toLowerCase(),
      protocol: current.protocol.replace(":", "")
    });

    const location = cleanHeaderValue(one.headers?.location || "");
    if ([301, 302, 303, 307, 308].includes(one.status) && location && i < 3) {
      let next;
      try { next = new URL(location, current); } catch { break; }
      if (!["http:", "https:"].includes(next.protocol)) break;
      current = next;
      continue;
    }
    break;
  }

  if (!last) return { ok: false, error: "page_request_failed" };

  const contentType = String(last.headers?.["content-type"] || "").toLowerCase();
  const canInspectBody = !contentType || contentType.includes("html") || contentType.includes("text/");
  const page = canInspectBody ? analyzeHtmlPage(last.body || "", current.href) : {
    hasForm: false,
    loginForm: false,
    paymentForm: false,
    otpField: false,
    walletSecretRequest: false,
    executableDownload: false,
    externalFormAction: false,
    title: "",
    pageBrandDetected: false,
    pageBrandTarget: null,
    pageBrandAlias: null,
    pageBrandOfficialDomain: false,
    pageBrandMismatch: false,
    pageBrandEvidence: null,
    pageBrandStrength: 0
  };

  const finalHostname = current.hostname.toLowerCase();
  const finalProtocol = current.protocol;
  return {
    ok: true,
    status: last.status,
    redirects: Math.max(0, chain.length - 1),
    chain,
    finalUrl: current.href,
    finalHostname,
    finalProtocol: finalProtocol.replace(":", ""),
    crossHostRedirect: finalHostname !== initialHostname,
    httpsDowngrade: initialProtocol === "https:" && finalProtocol === "http:",
    contentType: contentType.slice(0, 120),
    truncated: Boolean(last.truncated),
    tls: last.tls,
    ...page
  };
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



async function checkUrlHaus(rawUrl, hostname) {
  if (!URLHAUS_AUTH_KEY) {
    return { configured: false, ok: false, match: false, hostMatch: false };
  }

  const doPost = async (endpoint, key, value) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 7000);

    try {
      const body = new URLSearchParams();
      body.set(key, value);

      const response = await fetch(`https://urlhaus-api.abuse.ch/v1/${endpoint}/`, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "Auth-Key": URLHAUS_AUTH_KEY,
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
          "Accept": "application/json",
          "User-Agent": "SafeDeal/1.0"
        },
        body: body.toString()
      });

      if (!response.ok) {
        return { ok: false, status: response.status, data: null };
      }

      const data = await response.json();
      return { ok: true, status: response.status, data };
    } catch (error) {
      return { ok: false, error: error.name || "urlhaus_failed", data: null };
    } finally {
      clearTimeout(timer);
    }
  };

  const exact = await doPost("url", "url", rawUrl);
  if (!exact.ok) {
    return {
      configured: true,
      ok: false,
      status: exact.status || null,
      error: exact.error || null,
      authError: exact.status === 401 || exact.status === 403,
      match: false,
      hostMatch: false
    };
  }

  const exactStatus = String(exact.data?.query_status || "").toLowerCase();
  if (exactStatus === "ok") {
    return {
      configured: true,
      ok: true,
      match: true,
      hostMatch: false,
      queryStatus: exactStatus,
      urlStatus: String(exact.data?.url_status || "").toLowerCase(),
      threat: String(exact.data?.threat || ""),
      dateAdded: exact.data?.date_added || null,
      tags: Array.isArray(exact.data?.tags) ? exact.data.tags.slice(0, 8) : [],
      reference: exact.data?.urlhaus_reference || null
    };
  }

  // If the exact path is unknown, check whether the host itself has malware URLs.
  // This is scored more cautiously because one compromised/shared host does not
  // prove that every URL on that host is malicious.
  const host = await doPost("host", "host", hostname);
  if (!host.ok) {
    return {
      configured: true,
      ok: true,
      match: false,
      hostCheckOk: false,
      hostMatch: false,
      queryStatus: exactStatus || "no_results",
      hostStatus: host.status || null
    };
  }

  const hostStatus = String(host.data?.query_status || "").toLowerCase();
  const hostCount = Number(host.data?.url_count || 0);
  return {
    configured: true,
    ok: true,
    match: false,
    hostCheckOk: true,
    hostMatch: hostStatus === "ok" && hostCount > 0,
    queryStatus: exactStatus || "no_results",
    hostQueryStatus: hostStatus,
    hostUrlCount: Number.isFinite(hostCount) ? hostCount : 0,
    hostReference: host.data?.urlhaus_reference || null
  };
}


async function checkThreatFox(rawUrl, hostname) {
  if (!ABUSECH_AUTH_KEY) {
    return {
      configured: false,
      ok: false,
      authError: false,
      match: false,
      matchType: null,
      item: null
    };
  }

  const search = async (term) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 7000);

    try {
      const response = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
        method: "POST",
        signal: controller.signal,
        headers: {
          "Auth-Key": ABUSECH_AUTH_KEY,
          "Content-Type": "application/json",
          "Accept": "application/json",
          "User-Agent": "SafeDeal/1.0"
        },
        body: JSON.stringify({
          query: "search_ioc",
          search_term: term,
          exact_match: true
        })
      });

      if (!response.ok) {
        return {
          ok: false,
          status: response.status,
          authError: response.status === 401 || response.status === 403,
          data: null
        };
      }

      const data = await response.json();
      return { ok: true, status: response.status, authError: false, data };
    } catch (error) {
      return {
        ok: false,
        status: null,
        authError: false,
        error: error.name || "threatfox_failed",
        data: null
      };
    } finally {
      clearTimeout(timer);
    }
  };

  const summarize = (result, matchType) => {
    if (!result?.ok) return null;

    const status = String(result.data?.query_status || "").toLowerCase();
    const rows = Array.isArray(result.data?.data) ? result.data.data : [];

    if (status !== "ok" || rows.length === 0) {
      return {
        configured: true,
        ok: true,
        authError: false,
        match: false,
        matchType: null,
        queryStatus: status || "no_result",
        item: null
      };
    }

    const first = rows[0] || {};
    return {
      configured: true,
      ok: true,
      authError: false,
      match: true,
      matchType,
      queryStatus: status,
      item: {
        ioc: first.ioc ? String(first.ioc) : null,
        iocType: first.ioc_type ? String(first.ioc_type) : null,
        threatType: first.threat_type ? String(first.threat_type) : null,
        threatTypeDesc: first.threat_type_desc ? String(first.threat_type_desc) : null,
        malware: first.malware_printable ? String(first.malware_printable)
          : first.malware ? String(first.malware)
          : null,
        confidence: Number.isFinite(Number(first.confidence_level))
          ? Number(first.confidence_level)
          : null,
        firstSeen: first.first_seen ? String(first.first_seen) : null,
        lastSeen: first.last_seen ? String(first.last_seen) : null,
        reference: first.reference ? String(first.reference) : null
      }
    };
  };

  const exactUrl = await search(rawUrl);
  if (!exactUrl.ok) {
    return {
      configured: true,
      ok: false,
      authError: Boolean(exactUrl.authError),
      status: exactUrl.status || null,
      error: exactUrl.error || null,
      match: false,
      matchType: null,
      item: null
    };
  }

  const urlSummary = summarize(exactUrl, "url");
  if (urlSummary?.match) return urlSummary;

  const domain = await search(hostname);
  if (!domain.ok) {
    return {
      configured: true,
      ok: false,
      authError: Boolean(domain.authError),
      status: domain.status || null,
      error: domain.error || null,
      match: false,
      matchType: null,
      item: null
    };
  }

  const domainSummary = summarize(domain, "domain");
  return domainSummary || {
    configured: true,
    ok: true,
    authError: false,
    match: false,
    matchType: null,
    item: null
  };
}

async function checkPhishDestroy(hostname) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);

  try {
    const response = await fetch(
      `https://api.destroy.tools/v1/check?domain=${encodeURIComponent(hostname)}`,
      {
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          "User-Agent": "SafeDeal/1.0"
        }
      }
    );

    if (!response.ok) {
      return { ok: false, status: response.status, threat: false };
    }

    const data = await response.json();
    return {
      ok: true,
      status: response.status,
      threat: data?.threat === true,
      riskScore: Number.isFinite(Number(data?.risk_score)) ? Number(data.risk_score) : 0,
      severity: String(data?.severity || "").toLowerCase(),
      active: data?.active === true,
      flags: Array.isArray(data?.flags) ? data.flags : [],
      matchedKeywords: Array.isArray(data?.matched_keywords) ? data.matched_keywords : []
    };
  } catch (error) {
    return {
      ok: false,
      error: error.name || "phishdestroy_failed",
      threat: false
    };
  } finally {
    clearTimeout(timer);
  }
}

function isSharedPlatformHost(hostname = "") {
  const host = String(hostname || "").toLowerCase().replace(/^www\./, "");
  const sharedHosts = [
    "t.me", "telegram.me", "telegram.dog",
    "wa.me", "whatsapp.com", "api.whatsapp.com",
    "facebook.com", "m.facebook.com", "fb.com", "fb.me",
    "instagram.com",
    "viber.com", "invite.viber.com", "vb.me",
    "olx.ua", "olx.pl", "olx.ro", "olx.bg", "olx.kz", "olx.uz", "olx.com"
  ];
  return sharedHosts.some((domain) => host === domain || host.endsWith(`.${domain}`));
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
  const spoof = analyzeDomainSpoof(rawUrl, parsed);

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

  const [rdap, webRisk, phishTank, phishDestroy, urlHaus, threatFox, remotePage] = await Promise.all([
    lookupRdap(hostname),
    checkGoogleWebRisk(rawUrl),
    checkPhishTank(rawUrl),
    checkPhishDestroy(hostname),
    checkUrlHaus(rawUrl, hostname),
    checkThreatFox(rawUrl, hostname),
    inspectRemotePage(rawUrl)
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

  if (spoof.bidiOrInvisible) {
    points += 45;
    reasons.push("URL містить невидимі або bidi-символи, які можуть підміняти порядок чи вигляд адреси");
  }

  if (spoof.punycode) {
    points += 18;
    reasons.push("Домен використовує Punycode; візуально він може імітувати іншу назву");
    if (spoof.unicodeHostname && spoof.unicodeHostname !== hostname) {
      facts.push(`Punycode декодується як: ${spoof.unicodeHostname}`);
    }
  }

  if (spoof.mixedScript) {
    points += 30;
    reasons.push("В одному доменному імені змішані різні алфавіти (наприклад латиниця й кирилиця) — типовий прийом homograph-фішингу");
  }

  if (spoof.brandImpersonation) {
    const kindPoints = spoof.brandKind === "visual" ? 38 : spoof.brandKind === "typo" ? 30 : 18;
    points += kindPoints;
    const detail = spoof.brandEvidence ? ` (${spoof.brandEvidence})` : "";
    reasons.push(`Домен схожий на підміну бренду ${spoof.brandTarget || "відомого сервісу"}${detail}`);
  }

  if (spoof.encodedAuthority) {
    points += 16;
    reasons.push("У частині URL з адресою сайту використано percent-encoding, що може приховувати справжній домен");
  }

  if (spoof.encodedSequences >= 8) {
    points += 6;
    reasons.push("URL містить незвично багато закодованих символів");
  }

  if (spoof.nonStandardPort) {
    points += 6;
    reasons.push(`URL використовує нестандартний порт ${parsed.port}`);
  }

  if (spoof.longHostname) {
    points += 6;
    reasons.push("Доменне ім’я незвично довге й може маскувати важливі частини адреси");
  } else if (spoof.longUrl) {
    points += 4;
    reasons.push("Посилання незвично довге; перевірте кінцевий домен і параметри URL");
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

  if (phishDestroy.ok) {
    if (phishDestroy.threat) {
      if (isSharedPlatformHost(hostname)) {
        facts.push(`PhishDestroy має доменний сигнал для спільного домену ${hostname}; без точного збігу конкретного посилання цей доменний сигнал не додає ризику профілю`);
      } else {
        const severityPoints = phishDestroy.severity === "critical" ? 65
          : phishDestroy.severity === "high" ? 55
          : phishDestroy.severity === "medium" ? 35
          : 25;
        points += severityPoints;
        reasons.push(`PhishDestroy позначив домен як загрозу (${phishDestroy.severity || "ризик"})`);
      }
    } else {
      facts.push("PhishDestroy не знайшов домен у своїх активних списках загроз");
    }
  } else {
    facts.push("PhishDestroy тимчасово не відповів; результат за цим джерелом невідомий");
  }

  if (!urlHaus.configured) {
    facts.push("URLhaus ще не підключений до SafeDeal");
  } else if (!urlHaus.ok) {
    if (urlHaus.authError) {
      facts.push("URLhaus не прийняв Auth-Key; перевір ключ у Render");
    } else {
      facts.push("URLhaus тимчасово не відповів; результат за цим джерелом невідомий");
    }
  } else if (urlHaus.match) {
    const isOnline = urlHaus.urlStatus === "online";
    points += isOnline ? 78 : 58;
    reasons.push(
      isOnline
        ? "URLhaus має точний активний запис: це посилання відоме як джерело шкідливого ПЗ"
        : "URLhaus має точний запис про це посилання як джерело шкідливого ПЗ (зараз може бути офлайн)"
    );
    if (urlHaus.threat) facts.push(`URLhaus: тип загрози — ${urlHaus.threat}`);
  } else if (urlHaus.hostMatch) {
    if (isSharedPlatformHost(hostname)) {
      facts.push(`URLhaus знає ${urlHaus.hostUrlCount || 1} шкідливих URL на спільному домені ${hostname}, але точного збігу цього посилання немає — це не додає ризику конкретному профілю або контакту`);
    } else {
      points += 24;
      reasons.push(`URLhaus знає ${urlHaus.hostUrlCount || 1} шкідливих URL на цьому хості; точного збігу поточного URL немає`);
    }
  } else {
    facts.push("URLhaus не знайшов точного URL або відомих malware-URL на цьому хості");
  }

  if (!threatFox.configured) {
    facts.push("ThreatFox ще не підключений до SafeDeal");
  } else if (!threatFox.ok) {
    if (threatFox.authError) {
      facts.push("ThreatFox не прийняв abuse.ch Auth-Key; перевір ключ у Render");
    } else {
      facts.push("ThreatFox тимчасово не відповів; результат за цим джерелом невідомий");
    }
  } else if (threatFox.match) {
    const confidence = Number(threatFox.item?.confidence);
    const confidenceBonus = Number.isFinite(confidence)
      ? (confidence >= 90 ? 8 : confidence >= 70 ? 4 : 0)
      : 0;
    const malwareText = threatFox.item?.malware
      ? `; пов’язано з ${threatFox.item.malware}`
      : "";
    const typeText = threatFox.item?.threatTypeDesc || threatFox.item?.threatType || "відомим IOC";

    if (threatFox.matchType !== "url" && isSharedPlatformHost(hostname)) {
      facts.push(`ThreatFox має доменний IOC для спільного домену ${hostname}, але не точний IOC цього посилання — доменний збіг не додає ризику конкретному профілю або контакту`);
    } else {
      const basePoints = threatFox.matchType === "url" ? 68 : 52;
      points += basePoints + confidenceBonus;
      reasons.push(
        threatFox.matchType === "url"
          ? `ThreatFox має точний IOC для цього URL (${typeText}${malwareText})`
          : `ThreatFox має активний IOC для домену ${hostname} (${typeText}${malwareText})`
      );
    }

    if (Number.isFinite(confidence)) {
      facts.push(`ThreatFox: confidence ${confidence}%`);
    }
  } else {
    facts.push("ThreatFox не знайшов активного IOC для цього URL або домену");
  }

  if (remotePage.ok) {
    facts.push(`Сторінка відповіла HTTP ${remotePage.status || "—"}`);

    if (remotePage.redirects > 0) {
      facts.push(`Редиректів: ${remotePage.redirects}; кінцевий домен: ${remotePage.finalHostname}`);
      if (!sameSiteHost(hostname, remotePage.finalHostname) &&
          !sameOfficialBrandFamilyHost(hostname, remotePage.finalHostname)) {
        points += 10;
        reasons.push(`Посилання перенаправляє на інший сайт: ${remotePage.finalHostname}`);
      } else if (!sameSiteHost(hostname, remotePage.finalHostname) &&
                 sameOfficialBrandFamilyHost(hostname, remotePage.finalHostname)) {
        facts.push(`Редирект веде між офіційними доменами одного сервісу: ${hostname} → ${remotePage.finalHostname}`);
      }
    }

    if (remotePage.httpsDowngrade) {
      points += 24;
      reasons.push("HTTPS-посилання перенаправляє на незахищений HTTP");
    }

    if (remotePage.tls) {
      if (remotePage.tls.authorized) {
        const validTo = remotePage.tls.validTo ? new Date(remotePage.tls.validTo) : null;
        if (validTo && !Number.isNaN(validTo.getTime())) {
          facts.push(`TLS-сертифікат дійсний до ${validTo.toISOString().slice(0, 10)}`);
        } else {
          facts.push("TLS-сертифікат пройшов перевірку");
        }
      } else {
        points += 22;
        reasons.push("TLS-сертифікат сторінки не пройшов перевірку");
      }
    }

    if (remotePage.loginForm) facts.push("На сторінці знайдена форма входу з паролем");
    if (remotePage.paymentForm) facts.push("На сторінці знайдені поля платіжної картки");
    if (remotePage.otpField) facts.push("На сторінці знайдено поле одноразового коду / OTP");

    if (remotePage.pageBrandDetected) {
      if (remotePage.pageBrandOfficialDomain) {
        facts.push(`Вміст сторінки згадує ${remotePage.pageBrandTarget}; кінцевий домен входить до списку офіційних доменів цього бренду`);
      } else if (remotePage.pageBrandMismatch) {
        const sensitiveBrandForm = remotePage.loginForm || remotePage.paymentForm || remotePage.otpField;
        points += sensitiveBrandForm ? 48 : 22;
        reasons.push(
          sensitiveBrandForm
            ? `Сторінка представляється як ${remotePage.pageBrandTarget}, просить чутливі дані, але домен ${remotePage.finalHostname} не належить до відомих офіційних доменів бренду`
            : `Сторінка помітно використовує бренд ${remotePage.pageBrandTarget}, але домен ${remotePage.finalHostname} не належить до відомих офіційних доменів бренду`
        );
      }
    }

    if (remotePage.loginForm && remotePage.finalProtocol === "http") {
      points += 38;
      reasons.push("Сторінка просить пароль через незахищене HTTP-з’єднання");
    }

    if (remotePage.paymentForm && remotePage.finalProtocol === "http") {
      points += 45;
      reasons.push("Платіжна форма працює через незахищене HTTP-з’єднання");
    }

    if (remotePage.externalFormAction) {
      points += 10;
      reasons.push("Форма на сторінці надсилає дані на інший домен — перевірте адресу отримувача");
    }

    if (remotePage.walletSecretRequest) {
      points += 50;
      reasons.push("Сторінка містить запит на seed/recovery phrase або приватний ключ криптогаманця");
    }

    if (remotePage.executableDownload) {
      points += 12;
      reasons.push("На сторінці знайдено посилання на виконуваний файл (APK/EXE/MSI тощо)");
    }

    if (remotePage.loginForm && Number.isFinite(rdap.ageDays) && rdap.ageDays <= 30) {
      points += 18;
      reasons.push("Форма входу розміщена на дуже новому домені");
    }

    if (remotePage.paymentForm && Number.isFinite(rdap.ageDays) && rdap.ageDays <= 30) {
      points += 22;
      reasons.push("Платіжна форма розміщена на дуже новому домені");
    }
  } else {
    facts.push("Безпечний скан сторінки/редиректів тимчасово не вдалося виконати");
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
      unicodeHostname: spoof.unicodeHostname || hostname,
      punycode: Boolean(spoof.punycode),
      mixedScript: Boolean(spoof.mixedScript),
      mixedScriptLabels: spoof.mixedScriptLabels || [],
      brandImpersonation: Boolean(spoof.brandImpersonation),
      brandTarget: spoof.brandTarget || null,
      brandKind: spoof.brandKind || null,
      brandEvidence: spoof.brandEvidence || null,
      brandDistance: Number.isFinite(spoof.brandDistance) ? spoof.brandDistance : null,
      encodedAuthority: Boolean(spoof.encodedAuthority),
      encodedSequences: Number(spoof.encodedSequences || 0),
      bidiOrInvisible: Boolean(spoof.bidiOrInvisible),
      nonStandardPort: Boolean(spoof.nonStandardPort),
      longHostname: Boolean(spoof.longHostname),
      longUrl: Boolean(spoof.longUrl),
      dns: dnsResult.addresses,
      dnsOk: Boolean(dnsResult.ok),
      dnsError: dnsResult.error || null,
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
      phishTankPhishId: phishTank.phishId || null,
      phishDestroyOk: Boolean(phishDestroy.ok),
      phishDestroyThreat: Boolean(phishDestroy.threat),
      phishDestroyRiskScore: Number(phishDestroy.riskScore || 0),
      phishDestroySeverity: phishDestroy.severity || null,
      phishDestroyActive: Boolean(phishDestroy.active),
      urlHausConfigured: Boolean(urlHaus.configured),
      urlHausOk: Boolean(urlHaus.ok),
      urlHausAuthError: Boolean(urlHaus.authError),
      urlHausStatus: urlHaus.status || null,
      urlHausMatch: Boolean(urlHaus.match),
      urlHausUrlStatus: urlHaus.urlStatus || null,
      urlHausThreat: urlHaus.threat || null,
      urlHausHostMatch: Boolean(urlHaus.hostMatch),
      urlHausHostUrlCount: Number(urlHaus.hostUrlCount || 0),
      threatFoxConfigured: Boolean(threatFox.configured),
      threatFoxOk: Boolean(threatFox.ok),
      threatFoxAuthError: Boolean(threatFox.authError),
      threatFoxMatch: Boolean(threatFox.match),
      threatFoxMatchType: threatFox.matchType || null,
      threatFoxIoc: threatFox.item?.ioc || null,
      threatFoxIocType: threatFox.item?.iocType || null,
      threatFoxThreatType: threatFox.item?.threatType || null,
      threatFoxThreatTypeDesc: threatFox.item?.threatTypeDesc || null,
      threatFoxMalware: threatFox.item?.malware || null,
      threatFoxConfidence: Number.isFinite(Number(threatFox.item?.confidence))
        ? Number(threatFox.item.confidence)
        : null,
      rdapSource: rdap.source || null,
      pageScanOk: Boolean(remotePage.ok),
      pageScanError: remotePage.error || null,
      pageStatus: remotePage.status || null,
      redirectCount: Number(remotePage.redirects || 0),
      finalHostname: remotePage.finalHostname || hostname,
      finalProtocol: remotePage.finalProtocol || parsed.protocol.replace(":", ""),
      crossHostRedirect: Boolean(remotePage.crossHostRedirect),
      finalDifferentSite: Boolean(remotePage.ok && !sameSiteHost(hostname, remotePage.finalHostname || hostname)),
      httpsDowngrade: Boolean(remotePage.httpsDowngrade),
      tlsPresent: Boolean(remotePage.tls),
      tlsAuthorized: remotePage.tls ? Boolean(remotePage.tls.authorized) : null,
      tlsValidTo: remotePage.tls?.validTo || null,
      tlsIssuer: remotePage.tls?.issuer || null,
      tlsProtocol: remotePage.tls?.protocol || null,
      pageHasForm: Boolean(remotePage.hasForm),
      loginForm: Boolean(remotePage.loginForm),
      paymentForm: Boolean(remotePage.paymentForm),
      otpField: Boolean(remotePage.otpField),
      externalFormAction: Boolean(remotePage.externalFormAction),
      walletSecretRequest: Boolean(remotePage.walletSecretRequest),
      executableDownload: Boolean(remotePage.executableDownload),
      pageTitle: remotePage.title || null,
      pageBrandDetected: Boolean(remotePage.pageBrandDetected),
      pageBrandTarget: remotePage.pageBrandTarget || null,
      pageBrandAlias: remotePage.pageBrandAlias || null,
      pageBrandOfficialDomain: Boolean(remotePage.pageBrandOfficialDomain),
      pageBrandMismatch: Boolean(remotePage.pageBrandMismatch),
      pageBrandEvidence: remotePage.pageBrandEvidence || null,
      pageBrandStrength: Number(remotePage.pageBrandStrength || 0)
    }
  };
}


function decodeHtmlText(value = "") {
  return String(value)
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#(\d+);/g, (_, n) => {
      try { return String.fromCodePoint(Number(n)); } catch { return _; }
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => {
      try { return String.fromCodePoint(parseInt(n, 16)); } catch { return _; }
    });
}

function extractHtmlMeta(html = "", key = "") {
  const escaped = String(key).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const patterns = [
    new RegExp(`<meta[^>]+(?:property|name)=["']${escaped}["'][^>]+content=["']([^"']*)["'][^>]*>`, "i"),
    new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+(?:property|name)=["']${escaped}["'][^>]*>`, "i")
  ];
  for (const pattern of patterns) {
    const match = String(html).match(pattern);
    if (match) return compactSpaces(decodeHtmlText(match[1]));
  }
  return "";
}

function extractTelegramTarget(input = "", allowBare = false) {
  const raw = String(input || "").trim();
  if (!raw) return null;

  const invite = raw.match(/(?:https?:\/\/)?(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog)\/(?:joinchat\/|\+)([A-Za-z0-9_-]{8,})/i);
  if (invite) {
    return {
      kind: "invite",
      username: null,
      inviteCode: invite[1],
      normalized: `https://t.me/+${invite[1]}`,
      publicUrl: null
    };
  }

  const link = raw.match(/(?:https?:\/\/)?(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog)\/(?:s\/)?([A-Za-z0-9_]{5,32})(?:[/?#]|$)/i);
  if (link) {
    const username = link[1].toLowerCase();
    return {
      kind: "username",
      username,
      inviteCode: null,
      normalized: `@${username}`,
      publicUrl: `https://t.me/${username}`
    };
  }

  const at = raw.match(/(?:^|[\s([{])@([A-Za-z0-9_]{5,32})(?=$|[\s)\]},.!?:;])/);
  if (at) {
    const username = at[1].toLowerCase();
    return {
      kind: "username",
      username,
      inviteCode: null,
      normalized: `@${username}`,
      publicUrl: `https://t.me/${username}`
    };
  }

  if (allowBare && /^[A-Za-z0-9_]{5,32}$/.test(raw)) {
    const username = raw.toLowerCase();
    return {
      kind: "username",
      username,
      inviteCode: null,
      normalized: `@${username}`,
      publicUrl: `https://t.me/${username}`
    };
  }

  return null;
}


function telegramHtmlToText(fragment = "") {
  return compactSpaces(
    decodeHtmlText(
      String(fragment)
        .replace(/<br\s*\/?>/gi, "\n")
        .replace(/<\/p>/gi, "\n")
        .replace(/<[^>]+>/g, " ")
    )
  );
}

function extractTelegramRecentPosts(html = "") {
  const posts = [];
  const source = String(html || "");
  const pattern = /<div[^>]+class=["'][^"']*tgme_widget_message_text[^"']*["'][^>]*>([\s\S]*?)<\/div>/gi;
  let match;
  while ((match = pattern.exec(source)) && posts.length < 20) {
    const text = telegramHtmlToText(match[1]);
    if (text && text.length >= 2) posts.push(text.slice(0, 1200));
  }
  return [...new Set(posts)];
}

async function fetchTelegramHtml(url, timeoutMs = 6500) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 SafeDeal/1.0",
        "Accept": "text/html,application/xhtml+xml"
      }
    });
    const html = (await response.text()).slice(0, 900000);
    return { ok: response.ok, status: response.status, html, error: null };
  } catch (error) {
    return { ok: false, status: null, html: "", error: error.name || "telegram_fetch_failed" };
  } finally {
    clearTimeout(timer);
  }
}

async function inspectTelegramPublic(target) {
  if (!target) return null;

  if (target.kind === "invite") {
    return {
      target: target.normalized,
      username: null,
      kind: "invite",
      publicUrl: null,
      publicPreviewOk: false,
      publicPostsOk: false,
      recentPostsCount: 0,
      recentPosts: [],
      recentPostsText: "",
      status: null,
      title: null,
      description: null,
      audienceText: null,
      fetchError: null
    };
  }

  const page = await fetchTelegramHtml(target.publicUrl, 6500);
  const html = page.html || "";
  const title = extractHtmlMeta(html, "og:title") ||
    compactSpaces(decodeHtmlText((html.match(/<title[^>]*>([^<]{1,300})<\/title>/i) || [])[1] || ""));
  const description = extractHtmlMeta(html, "og:description") || extractHtmlMeta(html, "description");
  const extra = compactSpaces(decodeHtmlText((html.match(/class=["'][^"']*tgme_page_extra[^"']*["'][^>]*>([\s\S]*?)<\/div>/i) || [])[1] || "")
    .replace(/<[^>]+>/g, " "));

  const combined = `${title} ${description} ${extra}`.toLowerCase();
  let kind = "account_or_channel";
  if (target.username.endsWith("bot") || /\bbot\b|бот/i.test(combined)) kind = "bot";
  else if (/\bsubscribers?\b|підписник|подписчик/i.test(combined)) kind = "channel";
  else if (/\bmembers?\b|учасник|участник/i.test(combined)) kind = "group";

  const genericOnly = !description && /^telegram(?::\s*contact)?/i.test(title || "");
  const publicPreviewOk = page.ok && Boolean(title || description) && !genericOnly;

  // Public channel/group stream. This is still only data Telegram exposes publicly.
  const stream = await fetchTelegramHtml(`https://t.me/s/${encodeURIComponent(target.username)}`, 6000);
  const recentPosts = stream.ok ? extractTelegramRecentPosts(stream.html) : [];
  const publicPostsOk = recentPosts.length > 0;

  return {
    target: target.normalized,
    username: target.username,
    kind,
    publicUrl: target.publicUrl,
    publicPreviewOk,
    publicPostsOk,
    recentPostsCount: recentPosts.length,
    recentPosts,
    recentPostsText: recentPosts.join("\n").slice(0, 12000),
    status: page.status,
    title: title ? title.slice(0, 180) : null,
    description: description ? description.slice(0, 900) : null,
    audienceText: extra ? extra.slice(0, 160) : null,
    fetchError: page.error || stream.error || null
  };
}

function analyzeTelegramSignals(target, preview) {
  let points = 0;
  const reasons = [];
  const facts = [];
  const actions = [];

  if (!target) return { points, reasons, facts, actions };

  facts.push(`Telegram-ціль: ${target.normalized}`);
  facts.push("t.me є офіційним доменом Telegram, але це не підтверджує надійність конкретного акаунта чи каналу.");

  if (target.kind === "invite") {
    facts.push("Це приватне Telegram-запрошення: SafeDeal не бачить публічні пости до вступу.");
    actions.push("Для точнішої перевірки завантажте скріншот пропозиції або вставте її текст.");
    actions.push("Не вступайте в невідомі приватні групи лише заради «верифікації», заробітку або отримання виплати.");
    return { points, reasons, facts, actions };
  }

  const username = String(target.username || "").toLowerCase();
  const publicText = normalizeText(
    `${preview?.title || ""} ${preview?.description || ""} ${preview?.recentPostsText || ""}`
  );

  const brandWords = /(privat|приват|mono|olx|nova|novaposhta|steam|telegram|google|gmail|paypal|binance|bank|банк)/i;
  const supportWords = /(support|help|security|admin|manager|official|verify|verification|service|підтрим|служб|адмін|менедж)/i;

  if (brandWords.test(username) && supportWords.test(username)) {
    points += 18;
    reasons.push("Назва Telegram-акаунта схожа на підтримку або представника відомого бренду, але офіційність не підтверджена");
    actions.push("Знайдіть Telegram-контакт через офіційний сайт бренду, а не через отримане повідомлення.");
  }

  if (/(crypto|invest|trade|profit|airdrop|bonus|earn|zarob|work|job)/i.test(username)) {
    points += 5;
    reasons.push("Назва Telegram-акаунта пов’язана із заробітком, інвестиціями або бонусами — потрібна додаткова перевірка");
  }

  if (preview?.publicPreviewOk) {
    facts.push(`Публічне прев’ю Telegram доступне${preview.title ? `: ${preview.title}` : ""}`);
  } else {
    facts.push("Публічне прев’ю Telegram не вдалося підтвердити.");
  }

  if (preview?.publicPostsOk) {
    facts.push(`SafeDeal проаналізував останні публічні повідомлення: ${preview.recentPostsCount}.`);
  } else {
    facts.push("Публічні повідомлення каналу не вдалося прочитати; для точнішої оцінки потрібен скріншот або текст пропозиції.");
  }

  const sensitive = /seed\s*phrase|private\s*key|recovery\s*phrase|cvv|cvc|sms\s*code|код\s*(з|із)\s*sms|парол|pin\b/i;
  const guaranteed = /гарантован.*(дохід|прибут|зароб)|guaranteed.*profit|100%.*(profit|прибут)|без\s*ризику|безризиков/i;
  const deposit = /депозит|передоплат|activation fee|активац|внесок|поповн.*баланс|комісі.*для.*(виплат|вивод)|оплат.*щоб.*отрим/i;
  const task = /став(ити|те|имо)?\s*(лайк|вподоб)|лайк(и|ів)?|підпис(атися|ка|ки)|subscribe|оцін(ити|ювати).*(товар|відео|готел|заклад)|відгук|review|викон(ати|увати)\s*(прост|завдан)|task\b/i;
  const earning = /зароб|дохід|оплат|виплат|платимо|отрим(ай|уйте|ати).*(\$|usd|дол|грн|uah|євро|eur|грош)|за\s*(день|годину|лайк|завдан)|комісі/i;
  const highAmountUsd = /(?:\$|usd|дол(?:ар)?(?:ів)?)\s*(?:[1-9]\d{2,}|[5-9]\d)|(?:[1-9]\d{2,}|[5-9]\d)\s*(?:\$|usd|дол(?:ар)?(?:ів)?)/i;
  const highAmountUah = /(?:[3-9]\d{3}|[1-9]\d{4,})\s*(?:грн|uah)|(?:грн|uah)\s*(?:[3-9]\d{3}|[1-9]\d{4,})/i;
  const urgency = /терміново|прямо\s*зараз|лише\s*сьогодні|тільки\s*сьогодні|залишилось.*місц|limited\s*time/i;

  if (sensitive.test(publicText)) {
    points += 40;
    reasons.push("У публічних матеріалах є запит або згадка критично чутливих даних: пароль, SMS-код, PIN/CVV або ключі доступу");
    actions.push("Не передавайте паролі, SMS-коди, PIN, CVV або ключі від криптогаманця.");
  }

  if (guaranteed.test(publicText)) {
    points += 24;
    reasons.push("У публічних матеріалах є нереалістична або гарантована обіцянка прибутку");
  }

  const looksLikeTaskJob = task.test(publicText) && earning.test(publicText);
  if (looksLikeTaskJob) {
    points += 38;
    reasons.push("Публічні повідомлення схожі на схему «просте завдання за гроші» — лайки, підписки, оцінки або відгуки за оплату");
    actions.push("Не вносьте власні кошти для продовження «завдань» або збільшення виплати.");
  }

  if (looksLikeTaskJob && (highAmountUsd.test(publicText) || highAmountUah.test(publicText))) {
    points += 22;
    reasons.push("За дуже прості дії обіцяють непропорційно високу оплату — це сильний сигнал ризику");
  }

  if (deposit.test(publicText)) {
    points += 30;
    reasons.push("Є ознаки вимоги депозиту, передоплати, платної активації або поповнення балансу");
    actions.push("Не сплачуйте «активацію», «депозит», «податок», «страховку» чи «комісію для отримання виплати».");
  }

  if (urgency.test(publicText)) {
    points += 8;
    reasons.push("Використовується тиск або штучна терміновість");
  }

  return { points, reasons, facts, actions };
}

function analyzeTextSignals(type, input) {
  const text = normalizeText(input);
  // Risk score is evidence-based: no detected signal starts at 0, not an arbitrary baseline.
  let score = 0;
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
  const depositRefund =
    /депозит.{0,90}(поверн|вернеться|разом.{0,30}зароб)|поверн.{0,60}депозит/i;
  const cardData =
    /cvv|cvc|номер\s*карт|термін\s*дії|код\s*(з|із)\s*sms|pin|парол|одноразов(ий|ого)\s*код/i;
  const urgency =
    /терміново|прямо\s*зараз|\b(?:5|10|15|30)\s*хвилин|протягом\s*(?:12|24|48)\s*годин|обмежен(а|ий)\s*час|тільки\s*сьогодні/i;
  const accountThreat =
    /акаунт.{0,60}(заблок|обмеж|видален)|буде.{0,35}(заблок|обмеж|видален)|уникнути.{0,35}(блокув|обмеж)|доступ.{0,35}(призупин|закрит)/i;
  const verifyData =
    /підтверд(ити|іть|ьте).{0,45}(дан|особ|акаунт|адрес|платіж)|верифікац.{0,45}(акаунт|дан|особ)|онов(ити|іть|лення).{0,35}(дан|адрес)/i;
  const clickLink =
    /перейдіть.{0,35}(за\s*)?посил|натисніть.{0,35}посил|відкрийте.{0,35}посил|перейти.{0,35}посил/i;
  const suspiciousFile = /\.apk\b|\.exe\b|\.scr\b|\.msi\b|\.zip\b/i;
  const shortener = /bit\.ly|tinyurl|t\.co|cutt\.ly|goo\.gl|is\.gd/i;
  const telegram = /t\.me\/|telegram|@\w{4,}/i;

  if (moneyPromises.test(text)) add(22, "Є агресивна або нереалістична обіцянка заробітку");

  if (deposit.test(text)) {
    add(type === "job" ? 38 : 26, type === "job"
      ? "Для початку роботи просять внести депозит / оплатити активацію"
      : "Просять депозит / передоплату / платну активацію");
    actions.add("Не переказуйте гроші за «активацію роботи», «страхування» або доступ до завдань.");
  }

  if (type === "job" && depositRefund.test(text)) {
    add(12, "Обіцяють повернути депозит після виконання завдань — це типова ознака ризикової схеми");
  }

  if (cardData.test(text)) {
    add(30, "Є запит на чутливі банківські або авторизаційні дані");
    actions.add("Не вводьте повні реквізити картки, CVV, PIN або SMS-коди.");
  }

  if (urgency.test(text)) add(12, "Використовується тиск або штучна терміновість");
  if (accountThreat.test(text)) {
    add(20, "Повідомлення лякає блокуванням або обмеженням акаунта");
    actions.add("Не переходьте за посиланням із такого повідомлення. Відкрийте офіційний застосунок або сайт вручну.");
  }
  if (verifyData.test(text)) add(14, "Просять терміново підтвердити або оновити особисті дані");
  if (clickLink.test(text)) add(12, "Повідомлення підштовхує перейти за посиланням для підтвердження дії");

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

    if (/став(ити|те)\s*лайк|лайк(и|ів).{0,40}(грн|оплат|зароб)|оцінювати\s*товар|викуп\s*товар|task\s*scam|виконувати\s*(?:прост[іи]?\s*)?завдання|за\s*кожн(е|е\s*виконане)\s*завдання/i.test(text)) {
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
      candidates.add(normalizeTargetKey(url));
      candidates.add(new URL(url).hostname.toLowerCase().replace(/^www\./, ""));
    } catch {}
  }

  for (const match of text.matchAll(/@([a-z0-9_]{4,})/gi)) {
    candidates.add(`@${match[1].toLowerCase()}`);
  }

  for (const match of text.matchAll(/[+\d][\d\s().-]{7,}/g)) {
    const digits = match[0].replace(/\D/g, "");
    const normalizedPhone = extractPhoneTarget(match[0]);
    if (normalizedPhone?.valid) candidates.add(normalizedPhone.digits);
    else if (digits.length >= 8) candidates.add(digits);
  }

  for (const match of text.matchAll(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi)) {
    candidates.add(match[0].toLowerCase());
  }

  const approved = [...(SHOW_DEMO_DATA ? demoApprovedReports : []), ...(await getApprovedDbReports())];
  const matches = approved.filter((report) => {
    const key = normalizeTargetKey(report.targetKey || report.target);
    if (!key) return false;
    return candidates.has(key) || (key.length >= 8 && text.includes(key));
  });

  return matches;
}


const PLATFORM_CHECKS = {
  facebook: {
    label: "Facebook",
    domains: ["facebook.com", "m.facebook.com", "fb.com", "fb.me"]
  },
  instagram: {
    label: "Instagram",
    domains: ["instagram.com"]
  },
  whatsapp: {
    label: "WhatsApp",
    domains: ["wa.me", "whatsapp.com", "api.whatsapp.com"]
  },
  viber: {
    label: "Viber",
    domains: ["viber.com", "invite.viber.com", "vb.me"]
  },
  olx: {
    label: "OLX",
    domains: ["olx.ua", "olx.pl", "olx.ro", "olx.bg", "olx.kz", "olx.uz", "olx.com"]
  }
};

function normalizedHostFromInput(input = "") {
  const url = extractFirstUrl(input);
  if (!url) return null;
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

function hostMatchesPlatform(host, domains = []) {
  if (!host) return false;
  return domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

function extractPlatformProfileKey(type, input = "") {
  const cfg = PLATFORM_CHECKS[type];
  if (!cfg) return null;

  const url = extractFirstUrl(input);
  if (url) {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
      if (!hostMatchesPlatform(host, cfg.domains)) {
        return {
          ok: false,
          label: cfg.label,
          normalized: url,
          host,
          reason: `Посилання не використовує офіційний домен ${cfg.label}`
        };
      }

      let path = decodeURIComponent(parsed.pathname || "/").replace(/\/+/g, "/");
      if (path.length > 180) path = path.slice(0, 180);

      if (type === "whatsapp") {
        const phoneDigits = `${path} ${parsed.searchParams.get("phone") || ""}`.replace(/\D/g, "");
        if (phoneDigits.length >= 8) {
          return { ok: true, label: cfg.label, normalized: `+${phoneDigits}`, host, publicUrl: url, phoneDigits };
        }
      }

      return {
        ok: true,
        label: cfg.label,
        normalized: `${host}${path}`.replace(/\/$/, ""),
        host,
        publicUrl: url
      };
    } catch {}
  }

  if (type === "instagram") {
    const handle = compactSpaces(input).match(/^@?([A-Za-z0-9._]{2,30})$/);
    if (handle) {
      return {
        ok: true,
        limited: true,
        label: cfg.label,
        normalized: `@${handle[1].toLowerCase()}`,
        publicUrl: `https://www.instagram.com/${encodeURIComponent(handle[1])}/`
      };
    }
  }

  if (type === "facebook") {
    const handle = compactSpaces(input).match(/^@?([A-Za-z0-9.]{3,80})$/);
    if (handle) {
      return {
        ok: true,
        limited: true,
        label: cfg.label,
        normalized: handle[1].toLowerCase(),
        publicUrl: `https://www.facebook.com/${encodeURIComponent(handle[1])}`
      };
    }
  }

  if (type === "whatsapp" || type === "viber") {
    const phone = extractPhoneTarget(input);
    if (phone?.valid) {
      return {
        ok: true,
        limited: true,
        label: cfg.label,
        normalized: phone.normalized,
        phoneDigits: phone.digits
      };
    }
  }

  return {
    ok: false,
    limited: true,
    label: cfg.label,
    normalized: compactSpaces(input).slice(0, 180),
    reason: `Не вдалося розпізнати коректні дані ${cfg.label}`
  };
}

function analyzeReviewEvidence(input = "") {
  const text = compactSpaces(input);
  const reasons = [];
  const facts = [];
  let points = 0;

  if (!/відгук|review|оцінк|rating|зір/i.test(text)) {
    return { points, reasons, facts, suspicious: false };
  }

  const repetitive = /(чудов(ий|а|о).{0,40})\1|(?:рекомендую.{0,35}){3,}|(?:все супер.{0,35}){3,}/i.test(text);
  if (repetitive) {
    points += 8;
    reasons.push("У наданих відгуках є ознаки повторюваних або шаблонних формулювань");
  }

  const positiveBurst =
    /(?:10|20|30|50|100)\+?\s*(?:позитивн|5[\s-]*зір).{0,80}(?:день|годин|тижд)/i.test(text) ||
    /(?:за день|за добу|за кілька годин).{0,60}(?:відгук|оцінок).{0,40}(?:10|20|30|50|100)/i.test(text);
  if (positiveBurst) {
    points += 10;
    reasons.push("Опис вказує на незвично швидкий сплеск позитивних відгуків");
  }

  const hiddenEvidence =
    /видален(і|о|ий)\s+негативн|прихован(і|о)\s+відгук|відгук.*зник|негативн.*зник/i.test(text);
  if (hiddenEvidence) {
    points += 10;
    reasons.push("Є надані ознаки, що частина негативних відгуків могла бути прихована або видалена");
    facts.push("Це обережний сигнал на основі наданих даних, а не підтвердження факту видалення відгуків платформою.");
  }

  if (!reasons.length) {
    facts.push("У тексті згадуються відгуки, але недостатньо даних, щоб робити висновок про їхню достовірність або видалення.");
  }

  return { points, reasons, facts, suspicious: reasons.length > 0 };
}


const REVIEW_ARCHIVE_TYPES = new Set(["seller", "contact", "facebook", "instagram", "whatsapp", "viber", "olx"]);

async function getVerifiedReviewEvidence(type, input) {
  if (!REVIEW_ARCHIVE_TYPES.has(type)) {
    return { available: false, confirmedCount: 0, items: [], note: "Для цього типу перевірки архів відгуків не застосовується." };
  }

  const targetKey = normalizeTargetKey(input);
  const items = [];

  if (databaseReady && pool && targetKey) {
    try {
      const { rows } = await pool.query(
        `SELECT platform, source_url, archived_text, summary, evidence_type, first_seen_at, missing_at, created_at
         FROM review_evidence
         WHERE target_key = $1 AND status = 'verified'
         ORDER BY COALESCE(missing_at, created_at) DESC
         LIMIT 100`,
        [targetKey]
      );
      for (const row of rows) {
        items.push({
          status: "confirmed",
          platform: row.platform || typeLabelServer(type),
          sourceUrl: row.source_url || "",
          summary: compactSpaces(row.summary || row.archived_text || "Збережений відгук без короткого опису").slice(0, 600),
          archivedText: compactSpaces(row.archived_text || "").slice(0, 1200),
          evidenceType: row.evidence_type || "snapshot_diff",
          firstSeenAt: row.first_seen_at || null,
          missingAt: row.missing_at || null
        });
      }
    } catch (error) {
      console.error("Review evidence lookup failed:", error.message);
    }
  }

  return {
    available: true,
    confirmedCount: items.length,
    items,
    note: items.length
      ? "Показані лише записи, для яких SafeDeal має збережене підтвердження: попередній знімок/архів і факт подальшої відсутності або зміни."
      : "SafeDeal не знайшов підтверджених доказів видалених або прихованих відгуків. Відсутність доказів не означає, що таких відгуків ніколи не було."
  };
}

function typeLabelServer(type) {
  return ({
    seller: "Продавець", contact: "Telegram", facebook: "Facebook", instagram: "Instagram",
    whatsapp: "WhatsApp", viber: "Viber", olx: "OLX", job: "Вакансія", link: "Посилання",
    phone: "Номер телефону", text: "Текст"
  })[type] || "Джерело";
}

function buildPlainLanguageSummary({ score, type, reasons = [], technical = null, moderatedMatchesCount = 0, reviewArchive = null }) {
  const reasonText = reasons.join(" ").toLowerCase();
  const subject = ({
    link: "посилання", contact: "Telegram-профіль", facebook: "Facebook-профіль",
    instagram: "Instagram-профіль", whatsapp: "WhatsApp-контакт", viber: "Viber-контакт",
    olx: "OLX-оголошення або продавця", seller: "продавця", job: "вакансію",
    phone: "номер телефону", text: "текст повідомлення"
  })[type] || "введені дані";

  if (technical?.brandImpersonation || technical?.pageBrandMismatch || /підміна|схоже на .*бренд|домен інший/.test(reasonText)) {
    return `Ми перевірили ${subject} і знайшли ознаки, що адреса або сторінка може маскуватися під відомий сервіс. Назва схожа на оригінальну, але адреса відрізняється. Такі підміни часто використовують, щоб виманити пароль, дані картки або гроші.`;
  }
  if (type === "job" && /депозит|активац|платними завданнями|викуп/.test(reasonText)) {
    return "У цій вакансії є небезпечна ознака: перед початком роботи просять внести власні гроші або оплатити «активацію». Такі схеми часто починаються з невеликих виплат, а потім вимагають більших депозитів. Справжній роботодавець зазвичай не просить платити за можливість працювати.";
  }
  if (/блокуванням|підтвердити або оновити|перейти за посиланням|штучна терміновість/.test(reasonText)) {
    return `Ми перевірили ${subject}. Повідомлення створює поспіх або лякає блокуванням і підштовхує перейти за посиланням чи підтвердити дані. Це поширена схема фішингу — безпечніше самостійно відкрити офіційний застосунок або сайт, а не користуватися посиланням із повідомлення.`;
  }
  if (moderatedMatchesCount > 0) {
    return `Ми перевірили ${subject} і знайшли збіг із модерованими скаргами SafeDeal. Це не доводить шахрайство саме по собі, але є вагомою причиною не поспішати з оплатою та перевірити деталі скарг.`;
  }
  if (reviewArchive?.confirmedCount > 0) {
    return `Ми перевірили ${subject} і знайшли підтверджені архівні дані про відгуки, які раніше були доступні, а пізніше зникли або змінилися. Відкрийте розділ «Видалені / приховані відгуки», щоб побачити збережені докази.`;
  }
  if (score >= 76) {
    return `Ми перевірили ${subject} і знайшли кілька сильних ознак небезпеки. Не переказуйте гроші та не передавайте паролі, SMS-коди чи дані картки, доки не перевірите іншу сторону незалежним способом.`;
  }
  if (score >= 51) {
    return `Ми перевірили ${subject} і знайшли кілька суттєвих ознак ризику. Це не означає автоматично, що перед вами шахрай, але перед оплатою або передачею даних потрібна додаткова перевірка.`;
  }
  if (score >= 26) {
    return `Ми перевірили ${subject} і знайшли окремі підозрілі ознаки. Вони можуть мати нормальне пояснення, але краще перевірити адресу, співрозмовника та умови угоди перед будь-якою оплатою.`;
  }
  return `Ми перевірили ${subject} і не знайшли сильних відомих ознак ризику в доступних даних. Це не гарантія безпеки: перед оплатою все одно перевіряйте особу, реквізити та адресу сайту.`;
}



function classifyScamScheme({ type, score, reasons = [], technical = null }) {
  const text = reasons.join(" ").toLowerCase();
  const schemes = [
    { key: "fake_job", label: "Фейкова вакансія / платні завдання", re: /ваканс|депозит|активац|платними завданнями|викуп товар|початку роботи/ },
    { key: "phishing", label: "Фішинг / викрадення даних", re: /фіш|блокування|підтвердити|оновити.*дан|парол|sms|otp|підміна|маскуватися/ },
    { key: "fake_delivery", label: "Фейкова доставка", re: /достав|адрес.*підтверд|посилання.*підтверд/ },
    { key: "advance_payment", label: "Шахрайство з передоплатою", re: /передоплат|депозит|переказ.*грош|оплат/ },
    { key: "fake_shop", label: "Підроблений магазин / сайт", re: /бренд|домен.*не належить|підроб|маскується|схоже на.*сайт/ },
    { key: "account_takeover", label: "Спроба викрадення акаунта", re: /акаунт.*заблок|одноразов.*код|otp|парол/ },
    { key: "malware", label: "Шкідливе ПЗ / небезпечне завантаження", re: /malware|шкідлив|apk|exe|seed|private key/ }
  ];
  const found = schemes.find((x) => x.re.test(text));
  if (found) return { ...found, confidence: score >= 70 ? "high" : score >= 40 ? "medium" : "low" };
  if (score <= 10) return { key: "none_detected", label: "Типову шахрайську схему не виявлено", confidence: "medium" };
  return { key: "mixed_risk", label: "Змішані ознаки ризику", confidence: score >= 60 ? "medium" : "low" };
}

function confidenceForEvidence(text = "", kind = "signal") {
  const t = String(text).toLowerCase();
  if (/модерован|точний.*збіг|urlhaus.*точн|threatfox.*точн|web risk.*збіг|підтверджен.*архів|старий знімок|той самий номер/.test(t)) return "high";
  if (/tls|https|dns|rdap|домен|редирект|форма|публічн|відгук/.test(t)) return "medium";
  if (kind === "positive") return "medium";
  return "low";
}

function buildEvidenceBundle({ score, reasons = [], facts = [], technical = null, moderatedMatches = [], reviewArchive = null }) {
  const items = [];
  const seen = new Set();
  const push = (kind, title, detail, source = "SafeDeal analysis", confidence = null) => {
    const key = `${kind}|${title}|${detail}`;
    if (seen.has(key)) return;
    seen.add(key);
    items.push({ kind, title: String(title || "").slice(0,160), detail: String(detail || "").slice(0,700), source, confidence: confidence || confidenceForEvidence(`${title} ${detail}`, kind) });
  };
  reasons.forEach((reason) => push("risk", "Сигнал ризику", reason));
  moderatedMatches.slice(0,20).forEach((item) => push("confirmed", `Модерована скарга ${item.code || ""}`.trim(), item.reason || item.details || "Є підтверджений запис у базі скарг SafeDeal.", "SafeDeal moderated reports", "high"));
  (reviewArchive?.items || []).slice(0,30).forEach((item) => push("confirmed", "Архівний відгук / знімок", item.summary || item.archivedText || "Є збережений архівний доказ.", item.sourceUrl || "SafeDeal archive", "high"));
  if (technical) {
    if (technical.tlsAuthorized === true) push("positive","TLS/HTTPS перевірено","Сертифікат сторінки пройшов перевірку.","TLS scan","medium");
    if (technical.webRiskOk && Number(technical.webRiskMatches||0)===0) push("positive","Google Web Risk","Відомих збігів загроз не знайдено.","Google Web Risk","high");
    if (technical.phishTankOk && !technical.phishTankInDatabase) push("positive","PhishTank","Збігів у доступній базі не знайдено.","PhishTank","medium");
    if (technical.urlHausOk && !technical.urlHausMatch && !technical.urlHausHostMatch) push("positive","URLhaus","Точного malware-збігу не знайдено.","URLhaus","high");
    if (technical.threatFoxOk && !technical.threatFoxMatch) push("positive","ThreatFox","Активного IOC-збігу не знайдено.","ThreatFox","high");
    if (technical.pageScanOk && !technical.pageBrandMismatch && !technical.httpsDowngrade) push("positive","Перевірка сторінки","Не виявлено підміни бренду або downgrade HTTPS→HTTP.","Safe page scan","medium");
  }
  if (score <= 10 && !moderatedMatches.length) push("positive","Скарги SafeDeal","Підтверджених збігів у модерованій базі скарг не знайдено.","SafeDeal moderated reports","high");
  facts.slice(0,20).forEach((fact) => {
    if (/не знайдено|офіційн|дійсн|пройшов перевірку|не має прямого доступу/i.test(fact)) push("context","Контекст перевірки",fact,"SafeDeal analysis","medium");
  });
  return {
    total: items.length, confirmed: items.filter(x=>x.kind==="confirmed").length, risk: items.filter(x=>x.kind==="risk").length, positive: items.filter(x=>x.kind==="positive").length, items,
    note: score <= 10 ? "Низький ризик означає, що значних ознак небезпеки не знайдено в доступних даних. Це не гарантія повної безпеки." : "SafeDeal розділяє підтверджені докази, технічні сигнали та слабші індикатори. Це оцінка ризику, а не юридичний висновок."
  };
}

function extractObjectEntities(type, input, report = {}) {
  const text = String(input || ""); const entities=[]; const add=(kind,value)=>{const v=compactSpaces(value||"").toLowerCase(); if(v && v.length<=300 && !entities.some(x=>x.kind===kind&&x.value===v)) entities.push({kind,value:v});};
  for (const m of text.matchAll(/(?:\+?\d[\d\s().-]{7,}\d)/g)) { const p=extractPhoneTarget(m[0]); if(p?.valid) add("phone",p.digits); }
  for (const m of text.matchAll(/https?:\/\/[^\s<>"']+/gi)) { try { const u=new URL(m[0]); add("domain",u.hostname.toLowerCase().replace(/^www\./,"")); add("url",`${u.hostname.toLowerCase().replace(/^www\./,"")}${u.pathname}`.replace(/\/+$/,"")); } catch {} }
  for (const m of text.matchAll(/(?:^|\s)@([a-zA-Z0-9_]{4,32})\b/g)) add("username",`@${m[1].toLowerCase()}`);
  for (const m of text.matchAll(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi)) add("email",m[0].toLowerCase());
  if(report?.phone?.normalized) add("phone",String(report.phone.normalized).replace(/\D/g,""));
  if(report?.telegram?.username) add("telegram",`@${String(report.telegram.username).toLowerCase()}`);
  if(report?.technical?.hostname) add("domain",String(report.technical.hostname).toLowerCase().replace(/^www\./,""));
  return entities.slice(0,50);
}

async function getOwnerKey(req) {
  const user = await getAuthUser(req); if(user?.id) return `user:${user.id}`; const clientId=getClientId(req); return clientId?`client:${clientId}`:"";
}
async function getRelatedObjects(targetKey,type,entities=[]) {
  if(!databaseReady||!pool||!targetKey||!entities.length) return [];
  const values=entities.map(x=>`${x.kind}:${x.value}`);
  try {
    const {rows}=await pool.query(`SELECT DISTINCT e2.target_key,e2.type,e1.entity_kind,e1.entity_value,MAX(e2.last_seen_at) OVER (PARTITION BY e2.target_key,e2.type) AS last_seen_at FROM object_entities e1 JOIN object_entities e2 ON e1.entity_kind=e2.entity_kind AND e1.entity_value=e2.entity_value WHERE (e1.entity_kind||':'||e1.entity_value)=ANY($1::text[]) AND NOT (e2.target_key=$2 AND e2.type=$3) ORDER BY last_seen_at DESC LIMIT 30`,[values,targetKey,type]);
    return rows.map(row=>({targetKey:row.target_key,type:row.type,matchedBy:row.entity_kind,matchedValue:row.entity_value,confidence:row.entity_kind==="phone"?"high":["email","telegram"].includes(row.entity_kind)?"high":"medium",note:row.entity_kind==="phone"?"Пов’язано однаковим номером телефону. Це сильний зв’язок, але не доводить, що профілями керує одна й та сама людина.":`Пов’язано за ознакою: ${row.entity_kind}. Це сигнал зв’язку, а не доказ тотожності власника.`}));
  } catch(error){console.error("Related objects lookup failed:",error.message); return [];}
}
async function persistEntities(targetKey,type,entities=[]) {
  if(!databaseReady||!pool||!targetKey) return;
  for(const item of entities){try{await pool.query(`INSERT INTO object_entities (target_key,type,entity_kind,entity_value) VALUES ($1,$2,$3,$4) ON CONFLICT (target_key,type,entity_kind,entity_value) DO UPDATE SET last_seen_at=NOW()`,[targetKey,type,item.kind,item.value]);}catch(error){console.error("Entity persist failed:",error.message);}}
}
function snapshotDiff(previous,current) {
  if(!previous) return {firstCheck:true,changed:false,items:[],scoreDelta:0};
  const items=[]; const delta=Number(current.score||0)-Number(previous.score||0);
  if(Math.abs(delta)>=5) items.push(`Ризик змінився: ${previous.score}/100 → ${current.score}/100`);
  if(Number(current.complaintCount||0)!==Number(previous.complaintCount||0)) items.push(`Кількість підтверджених скарг: ${previous.complaintCount||0} → ${current.complaintCount||0}`);
  if(Number(current.reviewCount||0)!==Number(previous.reviewCount||0)) items.push(`Архівних/підтверджених відгуків: ${previous.reviewCount||0} → ${current.reviewCount||0}`);
  if(String(current.schemeKey||"")!==String(previous.schemeKey||"")&&previous.schemeKey) items.push("Змінився тип найбільш ймовірної ризикової схеми.");
  return {firstCheck:false,changed:items.length>0,items,scoreDelta:delta};
}
async function saveTargetSnapshot({targetKey,type,report,input}) {
  if(!databaseReady||!pool||!targetKey) return {firstCheck:true,changed:false,items:[],scoreDelta:0};
  try{
    const prev=await pool.query(`SELECT score,scheme_key,complaint_count,review_count,created_at FROM target_snapshots WHERE target_key=$1 AND type=$2 ORDER BY created_at DESC LIMIT 1`,[targetKey,type]);
    const row=prev.rows[0]; const previous=row?{score:Number(row.score||0),schemeKey:row.scheme_key||"",complaintCount:Number(row.complaint_count||0),reviewCount:Number(row.review_count||0),createdAt:row.created_at}:null;
    const current={score:Number(report.score||0),schemeKey:report.scamScheme?.key||"",complaintCount:Number(report.communityMatches?.length||0),reviewCount:Number(report.reviewArchive?.confirmedCount||0)};
    const diff=snapshotDiff(previous,current);
    await pool.query(`INSERT INTO target_snapshots (target_key,type,score,label,scheme_key,complaint_count,review_count,snapshot) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,[targetKey,type,current.score,report.label||"",current.schemeKey,current.complaintCount,current.reviewCount,JSON.stringify({targetPreview:compactSpaces(input).slice(0,500),reasons:report.reasons||[],facts:report.facts||[],scheme:report.scamScheme||null,technical:report.technical||null})]);
    return {...diff,previousAt:previous?.createdAt||null};
  }catch(error){console.error("Snapshot save failed:",error.message); return {firstCheck:true,changed:false,items:[],scoreDelta:0};}
}
async function createWatchEventIfNeeded(ownerKey,targetKey,type,changes,score) {
  if(!databaseReady||!pool||!ownerKey||!targetKey||!changes?.changed) return false;
  try{const watched=await pool.query(`SELECT 1 FROM watch_items WHERE owner_key=$1 AND target_key=$2 AND type=$3 AND active=TRUE LIMIT 1`,[ownerKey,targetKey,type]); if(!watched.rowCount) return false; const before=Number(score||0)-Number(changes.scoreDelta||0); await pool.query(`INSERT INTO watch_events (owner_key,target_key,type,event_type,message,before_score,after_score) VALUES ($1,$2,$3,'change',$4,$5,$6)`,[ownerKey,targetKey,type,changes.items.join(" • ").slice(0,1000),before,Number(score||0)]); return true;}catch(error){console.error("Watch event create failed:",error.message); return false;}
}
function hammingDistanceHex64(a,b){const x=String(a||"").toLowerCase(),y=String(b||"").toLowerCase(); if(!/^[0-9a-f]{16}$/.test(x)||!/^[0-9a-f]{16}$/.test(y))return 64;let d=0;for(let i=0;i<16;i++){let n=parseInt(x[i],16)^parseInt(y[i],16);while(n){d+=n&1;n>>=1;}}return d;}


async function analyzeInput(type, input) {
  const safeType = ALLOWED_TYPES.has(type) ? type : "seller";
  const textAnalysis = analyzeTextSignals(safeType, input);
  let score = textAnalysis.score;
  const reasons = [...textAnalysis.reasons];
  const facts = [];
  const actions = new Set(textAnalysis.actions);
  let technical = null;
  const detectedPhone = extractPhoneTarget(input);
  const phone = safeType === "phone" ? detectedPhone : null;

  if (safeType === "phone") {
    if (!phone?.valid) {
      reasons.push("Не вдалося розпізнати коректний номер телефону");
      actions.add("Введіть номер повністю, бажано у форматі +код країни та номер.");
    } else {
      facts.push(`Нормалізований номер: ${phone.normalized}`);
      facts.push(`Країна: ${phone.country}`);
      facts.push("SafeDeal не визначає особу власника номера лише за номером телефону.");
      actions.add("Якщо співрозмовник представляється банком або компанією, передзвоніть за номером з офіційного сайту цієї організації.");
    }
  }


  let platform = null;
  if (PLATFORM_CHECKS[safeType]) {
    platform = extractPlatformProfileKey(safeType, input);
    const cfg = PLATFORM_CHECKS[safeType];

    if (!platform?.ok) {
      score += 5;
      reasons.push(platform?.reason || `Не вдалося розпізнати дані ${cfg.label}`);
      actions.add(`Вставте повне офіційне посилання ${cfg.label}${safeType === "whatsapp" || safeType === "viber" ? " або номер телефону" : ""}.`);
    } else {
      facts.push(`${cfg.label}: ${platform.normalized}`);
      facts.push(`Офіційний домен або формат ${cfg.label} сам по собі не підтверджує надійність конкретного профілю, продавця чи співрозмовника.`);

      if (platform.publicUrl) {
        const pUrl = await inspectUrl(platform.publicUrl);
        if (pUrl.ok) {
          score += pUrl.points;
          reasons.push(...pUrl.reasons);
          facts.push(...pUrl.facts);
          technical = pUrl.technical;
        } else {
          reasons.push(...pUrl.reasons);
          technical = pUrl.technical;
        }
      } else {
        facts.push(`SafeDeal не має прямого доступу до приватних даних ${cfg.label}; перевіряються лише введені дані, доступні публічні сигнали та база скарг.`);
      }

      if (platform.phoneDigits) {
        const p = extractPhoneTarget(platform.normalized);
        if (p?.valid) {
          facts.push(`Пов’язаний номер: ${p.normalized}`);
        }
      }
    }
  }

  const reviewEvidence = safeType === "seller" || safeType === "olx"
    ? analyzeReviewEvidence(input)
    : { points: 0, reasons: [], facts: [], suspicious: false };

  if (reviewEvidence.points) score += reviewEvidence.points;
  reasons.push(...reviewEvidence.reasons);
  facts.push(...reviewEvidence.facts);

  const telegramTarget = extractTelegramTarget(input, safeType === "contact");
  const telegram = telegramTarget ? await inspectTelegramPublic(telegramTarget) : null;
  if (telegramTarget) {
    const tgSignals = analyzeTelegramSignals(telegramTarget, telegram);
    score += tgSignals.points;
    reasons.push(...tgSignals.reasons);
    facts.push(...tgSignals.facts);
    tgSignals.actions.forEach((x) => actions.add(x));
  } else if (safeType === "contact") {
    score += 5;
    reasons.push("Не вдалося розпізнати Telegram @username або t.me-посилання");
    actions.add("Вставте точний @username або повне посилання t.me для точнішої перевірки.");
  }

  const detectedUrl = extractFirstUrl(input);

  if (detectedUrl && !PLATFORM_CHECKS[safeType]) {
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
  const moderatedMatches = communityMatches.filter((x) => !String(x.code).startsWith("DEMO-"));
  const exactPhoneModeratedMatches = detectedPhone?.valid
    ? moderatedMatches.filter((report) => normalizeTargetKey(report.targetKey || report.target) === detectedPhone.digits)
    : [];

  if (moderatedMatches.length) {
    // Every public complaint is moderated before it can influence risk. Exact
    // moderated matches use one scale across check modes: 1 → 35, 2 → 70, 3+ → 90.
    // This is a risk signal, not a legal finding that the target is fraudulent.
    const exactCount = exactPhoneModeratedMatches.length || moderatedMatches.length;
    const points = exactCount >= 3 ? 90 : exactCount * 35;
    score += points;

    if (safeType === "phone") {
      reasons.push(`Точний номер знайдено у модерованій базі скарг SafeDeal: ${exactPhoneModeratedMatches.length || moderatedMatches.length}`);
    } else if (safeType === "seller" && exactPhoneModeratedMatches.length > 0) {
      reasons.push(`На точний номер продавця є підтверджені скарги SafeDeal: ${exactPhoneModeratedMatches.length}`);
    } else {
      reasons.push(`У модерованій базі SafeDeal знайдено збігів: ${moderatedMatches.length}`);
    }

    actions.add("Перегляньте записи в базі скарг і перевірте факти перед оплатою або передачею даних.");
  } else if (safeType === "phone" && phone?.valid) {
    facts.push("Точних збігів номера у модерованій базі SafeDeal не знайдено.");
  }

  const reviewArchive = await getVerifiedReviewEvidence(safeType, input);

  score = Math.max(0, Math.min(100, score));
  const { level, label } = scoreToLevel(score);
  const verdict = buildHumanVerdict({
    score,
    type: safeType,
    telegram,
    phone,
    phoneModeratedMatches: safeType === "phone" ? exactPhoneModeratedMatches.length : 0,
    sellerModeratedMatches: safeType === "seller" ? moderatedMatches.length : 0,
    sellerExactPhoneMatches: safeType === "seller" ? exactPhoneModeratedMatches.length : 0,
    moderatedMatchesCount: moderatedMatches.length,
    platform
  });

  const plainSummary = buildPlainLanguageSummary({
    score,
    type: safeType,
    reasons,
    technical,
    moderatedMatchesCount: moderatedMatches.length,
    reviewArchive
  });

  const scamScheme = classifyScamScheme({ type: safeType, score, reasons, technical });
  const evidence = buildEvidenceBundle({ score, reasons, facts, technical, moderatedMatches, reviewArchive });

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
    verdict,
    plainSummary,
    scamScheme,
    evidence,
    reviewArchive,
    reasons: [...new Set(reasons)],
    facts: [...new Set(facts)],
    actions: [...actions],
    technical,
    telegram: telegram ? {
      target: telegram.target,
      username: telegram.username,
      kind: telegram.kind,
      publicUrl: telegram.publicUrl,
      publicPreviewOk: telegram.publicPreviewOk,
      publicPostsOk: telegram.publicPostsOk,
      recentPostsCount: telegram.recentPostsCount,
      status: telegram.status,
      title: telegram.title,
      description: telegram.description,
      audienceText: telegram.audienceText
    } : null,
    phone: phone?.valid ? {
      normalized: phone.normalized,
      country: phone.country,
      exactModeratedMatches: exactPhoneModeratedMatches.length
    } : null,
    platform: platform ? {
      type: safeType,
      label: platform.label,
      normalized: platform.normalized,
      publicUrl: platform.publicUrl || null,
      host: platform.host || null,
      limited: Boolean(platform.limited),
      ok: Boolean(platform.ok)
    } : null,
    reviewEvidence: reviewEvidence?.suspicious ? {
      suspicious: true,
      reasons: reviewEvidence.reasons
    } : null,
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
let lastRateCleanup = 0;
function cleanupRateBuckets(now = Date.now()) {
  if (now - lastRateCleanup < 5 * 60 * 1000) return;
  lastRateCleanup = now;
  for (const [key, value] of rateBuckets) {
    if (!value || value.resetAt <= now) rateBuckets.delete(key);
  }
}
function safeSecretEquals(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  if (!left.length || left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) {
    return res.status(503).json({ ok: false, error: "admin_not_configured" });
  }

  const supplied = String(req.get("x-admin-key") || "");
  if (!safeSecretEquals(supplied, ADMIN_KEY)) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  next();
}

function rateLimit({ windowMs = 60 * 60 * 1000, max = 80, scope = "route" } = {}) {
  return (req, res, next) => {
    const now = Date.now();
    cleanupRateBuckets(now);
    const ip = req.ip || req.socket.remoteAddress || "unknown";
    const routePart = scope === "global" ? "global" : `${req.method}:${req.path}`;
    const key = `${routePart}:${ip}`;
    const current = rateBuckets.get(key);

    if (!current || current.resetAt <= now) {
      rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
      res.setHeader("X-RateLimit-Limit", String(max));
      res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max - 1)));
      return next();
    }

    current.count += 1;
    res.setHeader("X-RateLimit-Limit", String(max));
    res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max - current.count)));
    if (current.count > max) {
      const retryAfter = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
      res.setHeader("Retry-After", String(retryAfter));
      return res.status(429).json({ ok: false, error: "rate_limited", retryAfter });
    }

    next();
  };
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "safedeal",
    version: APP_VERSION,
    uptimeSeconds: Math.floor(process.uptime()),
    webRiskConfigured: Boolean(GOOGLE_WEB_RISK_API_KEY),
    phishTankEnabled: true,
    phishTankKeyConfigured: Boolean(PHISHTANK_APP_KEY),
    urlHausConfigured: Boolean(URLHAUS_AUTH_KEY),
    threatFoxConfigured: Boolean(ABUSECH_AUTH_KEY),
    databaseConfigured: Boolean(DATABASE_URL),
    databaseReady,
    accountAuthReady: databaseReady,
    accountSecurityV62: databaseReady,
    passwordResetV63: databaseReady,
    passwordResetEmailConfigured: Boolean(RESEND_API_KEY),
    adminConfigured: Boolean(ADMIN_KEY)
  });
});

app.get("/api/community-alerts", async (req, res) => {
  if (!databaseReady || !pool) {
    return res.json({ ok: true, items: SHOW_DEMO_DATA ? demoAlerts : [], demo: SHOW_DEMO_DATA });
  }
  try {
    const { rows } = await pool.query(`
      SELECT target_key, MAX(target) AS target, MAX(type) AS type,
             COUNT(*)::int AS complaint_count, MAX(updated_at) AS updated_at,
             (ARRAY_AGG(reason ORDER BY updated_at DESC))[1] AS latest_reason
      FROM community_reports
      WHERE status = 'approved'
      GROUP BY target_key
      ORDER BY MAX(updated_at) DESC
      LIMIT 8
    `);
    const items = rows.map((row) => {
      const count = Number(row.complaint_count) || 1;
      const score = count >= 3 ? 90 : count * 35;
      const { level, label } = scoreToLevel(score);
      return {
        id: `COMM-${String(row.target_key).slice(0, 40)}`,
        target: row.target,
        type: row.type,
        score, level, label,
        reasons: [row.latest_reason || `Модерованих скарг: ${count}`],
        updatedAt: new Date(row.updated_at).toLocaleDateString("uk-UA")
      };
    });
    res.json({ ok: true, items: [...items, ...(SHOW_DEMO_DATA ? demoAlerts : [])].slice(0, 8), demo: SHOW_DEMO_DATA });
  } catch (error) {
    console.error("Community alerts error:", error.message);
    res.json({ ok: true, items: SHOW_DEMO_DATA ? demoAlerts : [], demo: SHOW_DEMO_DATA });
  }
});

app.get("/api/auth/me", rateLimit({ max: 240 }), async (req, res) => {
  try {
    const user = await getAuthUser(req);
    res.json({ ok: true, authenticated: Boolean(user), user: user ? { id: user.id, email: user.email, nickname: user.nickname, emailVerified: user.email_verified, createdAt: user.created_at } : null });
  } catch (error) {
    console.error("Auth me error:", error.message);
    res.status(500).json({ ok: false, error: "auth_failed" });
  }
});

app.post("/api/auth/register", rateLimit({ windowMs: 60 * 60 * 1000, max: 8 }), async (req, res) => {
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  const clientId = getClientId(req);
  if (!clientId) return res.status(400).json({ ok: false, error: "client_id_required" });
  const email = normalizeEmail(req.body?.email || "");
  const password = String(req.body?.password || "");
  let nickname = compactSpaces(req.body?.nickname || "").slice(0, 40);
  if (!validEmail(email)) return res.status(400).json({ ok: false, error: "invalid_email" });
  if (!validNewPassword(password)) return res.status(400).json({ ok: false, error: "weak_password" });

  try {
    await ensureClientProfile(clientId);
    if (nickname.length < 2) {
      const { rows } = await pool.query(`SELECT nickname FROM client_profiles WHERE client_id = $1 LIMIT 1`, [clientId]);
      nickname = compactSpaces(rows[0]?.nickname || "Гість").slice(0, 40) || "Гість";
    }
    const existing = await pool.query(`SELECT 1 FROM users WHERE email = $1 LIMIT 1`, [email]);
    if (existing.rows.length) return res.status(409).json({ ok: false, error: "email_exists" });
    const userId = crypto.randomUUID();
    const passwordHash = await createPasswordHash(password);
    const { rows } = await pool.query(
      `INSERT INTO users (id, email, password_hash, nickname, last_login_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING id, email, nickname, email_verified, created_at`,
      [userId, email, passwordHash, nickname]
    );
    await attachAnonymousDataToUser(userId, clientId);
    await createAuthSession(res, userId);
    const user = rows[0];
    res.status(201).json({ ok: true, authenticated: true, user: { id: user.id, email: user.email, nickname: user.nickname, emailVerified: user.email_verified, createdAt: user.created_at } });
  } catch (error) {
    console.error("Register error:", error.message);
    if (error.code === "23505") return res.status(409).json({ ok: false, error: "email_exists" });
    res.status(500).json({ ok: false, error: "register_failed" });
  }
});

app.post("/api/auth/login", rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }), async (req, res) => {
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  const clientId = getClientId(req);
  if (!clientId) return res.status(400).json({ ok: false, error: "client_id_required" });
  const email = normalizeEmail(req.body?.email || "");
  const password = String(req.body?.password || "");
  if (!validEmail(email) || !password) return res.status(400).json({ ok: false, error: "invalid_credentials" });
  try {
    const { rows } = await pool.query(
      `SELECT id, email, password_hash, nickname, email_verified, created_at,
              failed_login_count, login_locked_until
       FROM users WHERE email = $1 LIMIT 1`,
      [email]
    );
    const user = rows[0];

    // Keep response timing less revealing for unknown emails.
    if (!user) {
      await scryptAsync(password.slice(0, 128), "safedeal-missing-user");
      return res.status(401).json({ ok: false, error: "invalid_credentials" });
    }

    const lockedUntil = user.login_locked_until ? new Date(user.login_locked_until) : null;
    if (lockedUntil && lockedUntil.getTime() > Date.now()) {
      const retryAfterSeconds = Math.max(1, Math.ceil((lockedUntil.getTime() - Date.now()) / 1000));
      res.set("Retry-After", String(retryAfterSeconds));
      return res.status(429).json({ ok: false, error: "login_temporarily_locked", retryAfterSeconds });
    }

    const passwordOk = await verifyPassword(password, user.password_hash);
    if (!passwordOk) {
      const failed = Number(user.failed_login_count || 0) + 1;
      if (failed >= 5) {
        await pool.query(
          `UPDATE users SET failed_login_count = 0, login_locked_until = NOW() + INTERVAL '15 minutes', updated_at = NOW() WHERE id = $1`,
          [user.id]
        );
        return res.status(429).json({ ok: false, error: "login_temporarily_locked", retryAfterSeconds: 900 });
      }
      await pool.query(`UPDATE users SET failed_login_count = $1, updated_at = NOW() WHERE id = $2`, [failed, user.id]);
      return res.status(401).json({ ok: false, error: "invalid_credentials" });
    }

    await attachAnonymousDataToUser(user.id, clientId);
    await pool.query(
      `UPDATE users SET last_login_at = NOW(), failed_login_count = 0, login_locked_until = NULL, updated_at = NOW() WHERE id = $1`,
      [user.id]
    );
    await createAuthSession(res, user.id);
    res.json({ ok: true, authenticated: true, user: { id: user.id, email: user.email, nickname: user.nickname, emailVerified: user.email_verified, createdAt: user.created_at } });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ ok: false, error: "login_failed" });
  }
});

app.post("/api/auth/logout", rateLimit({ max: 120 }), async (req, res) => {
  try {
    const token = parseCookies(req).sd_session || "";
    if (databaseReady && pool && token) await pool.query(`DELETE FROM auth_sessions WHERE token_hash = $1`, [sessionTokenHash(token)]);
    clearSessionCookie(res);
    res.json({ ok: true });
  } catch {
    clearSessionCookie(res);
    res.json({ ok: true });
  }
});


app.post("/api/auth/change-password", rateLimit({ windowMs: 60 * 60 * 1000, max: 8 }), async (req, res) => {
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  try {
    const user = await getAuthUser(req);
    if (!user) return res.status(401).json({ ok: false, error: "auth_required" });
    const currentPassword = String(req.body?.currentPassword || "");
    const newPassword = String(req.body?.newPassword || "");
    if (!currentPassword) return res.status(400).json({ ok: false, error: "current_password_required" });
    if (!validNewPassword(newPassword)) return res.status(400).json({ ok: false, error: "weak_new_password" });
    if (currentPassword === newPassword) return res.status(400).json({ ok: false, error: "password_unchanged" });

    const { rows } = await pool.query(`SELECT password_hash FROM users WHERE id = $1 LIMIT 1`, [user.id]);
    if (!rows.length || !(await verifyPassword(currentPassword, rows[0].password_hash))) {
      return res.status(401).json({ ok: false, error: "current_password_invalid" });
    }

    const passwordHash = await createPasswordHash(newPassword);
    await pool.query(
      `UPDATE users SET password_hash = $1, password_changed_at = NOW(), failed_login_count = 0,
                        login_locked_until = NULL, updated_at = NOW() WHERE id = $2`,
      [passwordHash, user.id]
    );
    await pool.query(`DELETE FROM auth_sessions WHERE user_id = $1`, [user.id]);
    await createAuthSession(res, user.id);
    res.json({ ok: true, passwordChanged: true, otherSessionsRevoked: true });
  } catch (error) {
    console.error("Change password error:", error.message);
    res.status(500).json({ ok: false, error: "password_change_failed" });
  }
});

app.post("/api/auth/logout-all", rateLimit({ windowMs: 60 * 60 * 1000, max: 12 }), async (req, res) => {
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  try {
    const user = await getAuthUser(req);
    if (!user) {
      clearSessionCookie(res);
      return res.status(401).json({ ok: false, error: "auth_required" });
    }
    const result = await pool.query(`DELETE FROM auth_sessions WHERE user_id = $1`, [user.id]);
    clearSessionCookie(res);
    res.json({ ok: true, sessionsRevoked: result.rowCount || 0 });
  } catch (error) {
    clearSessionCookie(res);
    console.error("Logout all error:", error.message);
    res.status(500).json({ ok: false, error: "logout_all_failed" });
  }
});

app.post("/api/auth/forgot-password", rateLimit({ windowMs: 60 * 60 * 1000, max: 5 }), async (req, res) => {
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  const email = normalizeEmail(req.body?.email || "");
  if (!validEmail(email)) return res.status(400).json({ ok: false, error: "invalid_email" });

  try {
    const { rows } = await pool.query(`SELECT id FROM users WHERE email = $1 LIMIT 1`, [email]);
    if (rows.length) {
      const token = crypto.randomBytes(32).toString("base64url");
      const tokenHash = sessionTokenHash(token);
      await pool.query(`DELETE FROM password_reset_requests WHERE user_id = $1 AND used_at IS NULL`, [rows[0].id]);
      await pool.query(
        `INSERT INTO password_reset_requests (id, user_id, token_hash, expires_at)
         VALUES ($1, $2, $3, NOW() + INTERVAL '30 minutes')`,
        [crypto.randomUUID(), rows[0].id, tokenHash]
      );

      // Never return or log the reset token. Email delivery is best-effort.
      if (RESEND_API_KEY) await sendPasswordResetEmail(email, token);
    }

    // Always give the same response so callers cannot discover registered emails.
    res.json({ ok: true, accepted: true, emailDeliveryConfigured: Boolean(RESEND_API_KEY) });
  } catch (error) {
    console.error("Forgot password error:", error.message);
    res.status(500).json({ ok: false, error: "reset_request_failed" });
  }
});

app.post("/api/auth/reset-password", rateLimit({ windowMs: 60 * 60 * 1000, max: 10 }), async (req, res) => {
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });

  const token = String(req.body?.token || "").trim();
  const newPassword = String(req.body?.newPassword || "");
  if (!/^[A-Za-z0-9_-]{32,120}$/.test(token)) return res.status(400).json({ ok: false, error: "reset_invalid_or_expired" });
  if (!validNewPassword(newPassword)) return res.status(400).json({ ok: false, error: "weak_new_password" });

  const tokenHash = sessionTokenHash(token);
  const client = await pool.connect();
  let userId = null;
  try {
    await client.query("BEGIN");
    const { rows } = await client.query(
      `SELECT r.id, r.user_id, u.password_hash
       FROM password_reset_requests r
       JOIN users u ON u.id = r.user_id
       WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.expires_at > NOW()
       LIMIT 1 FOR UPDATE OF r`,
      [tokenHash]
    );

    if (!rows.length) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "reset_invalid_or_expired" });
    }

    userId = rows[0].user_id;
    if (await verifyPassword(newPassword, rows[0].password_hash)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "password_unchanged" });
    }

    const passwordHash = await createPasswordHash(newPassword);
    await client.query(
      `UPDATE users
       SET password_hash = $1, password_changed_at = NOW(), failed_login_count = 0,
           login_locked_until = NULL, updated_at = NOW()
       WHERE id = $2`,
      [passwordHash, userId]
    );
    await client.query(`UPDATE password_reset_requests SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL`, [userId]);
    await client.query(`DELETE FROM auth_sessions WHERE user_id = $1`, [userId]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Reset password error:", error.message);
    return res.status(500).json({ ok: false, error: "password_reset_failed" });
  } finally {
    client.release();
  }

  try {
    await createAuthSession(res, userId);
    res.json({ ok: true, passwordReset: true, signedIn: true });
  } catch (error) {
    console.error("Reset session creation failed:", error.message);
    res.json({ ok: true, passwordReset: true, signedIn: false });
  }
});

app.get("/api/reports", async (req, res) => {
  const q = normalizeText(req.query.q || "").slice(0, 200);
  const type = String(req.query.type || "all");

  try {
    const dbItems = await getApprovedDbReports();
    const all = [...dbItems, ...(SHOW_DEMO_DATA ? demoApprovedReports : [])];
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
  const clientId = getClientId(req);
  let authUser = null;
  try { authUser = await getAuthUser(req); } catch {}
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
      if (clientId) await ensureClientProfile(clientId);
      if (clientId || authUser?.id) {
        const duplicate = await pool.query(
          `SELECT code, status FROM community_reports
           WHERE target_key = $1
             AND created_at > NOW() - INTERVAL '10 minutes'
             AND (($2::text IS NOT NULL AND submitter_client_id = $2) OR ($3::uuid IS NOT NULL AND submitter_user_id = $3))
           ORDER BY created_at DESC LIMIT 1`,
          [valid.targetKey, clientId || null, authUser?.id || null]
        );
        if (duplicate.rows.length) {
          return res.status(200).json({ ok: true, duplicate: true, report: duplicate.rows[0], persistent: true });
        }
      }
      await pool.query(
        `INSERT INTO community_reports
          (code, target, target_key, type, reason, details, status, submitter_client_id, submitter_user_id)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)`,
        [code, valid.target, valid.targetKey, valid.type, valid.reason, valid.details, clientId || null, authUser?.id || null]
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

app.post("/api/appeals", rateLimit({ windowMs: 60 * 60 * 1000, max: 6 }), async (req, res) => {
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  const reportCode = compactSpaces(req.body?.reportCode || "").toUpperCase().slice(0, 80);
  const message = compactSpaces(req.body?.message || "").slice(0, 2000);
  const contact = compactSpaces(req.body?.contact || "").slice(0, 254);
  if (!reportCode || message.length < 20) return res.status(400).json({ ok: false, error: "invalid_appeal" });
  try {
    const report = await pool.query(`SELECT code FROM community_reports WHERE code = $1 AND status = 'approved' LIMIT 1`, [reportCode]);
    if (!report.rows.length) return res.status(404).json({ ok: false, error: "report_not_found" });
    const existing = await pool.query(`SELECT id FROM report_appeals WHERE report_code = $1 AND status = 'pending' AND created_at > NOW() - INTERVAL '24 hours' LIMIT 1`, [reportCode]);
    if (existing.rows.length) return res.json({ ok: true, accepted: true, duplicate: true });
    await pool.query(`INSERT INTO report_appeals (id, report_code, message, contact) VALUES ($1,$2,$3,$4)`, [crypto.randomUUID(), reportCode, message, contact]);
    res.status(201).json({ ok: true, accepted: true });
  } catch (error) {
    console.error("Appeal submit error:", error.message);
    res.status(500).json({ ok: false, error: "appeal_submit_failed" });
  }
});

app.get("/api/admin/appeals", requireAdmin, rateLimit({ max: 240 }), async (req, res) => {
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  const requestedStatus = String(req.query.status || "pending").toLowerCase();
  const allowed = new Set(["pending", "resolved", "rejected", "all"]);
  const status = allowed.has(requestedStatus) ? requestedStatus : "pending";
  const params = [];
  const where = status === "all" ? "" : "WHERE a.status = $1";
  if (status !== "all") params.push(status);
  try {
    const { rows } = await pool.query(
      `SELECT a.id, a.report_code, a.message, a.contact, a.status, a.moderator_note, a.created_at, a.updated_at, r.target
       FROM report_appeals a LEFT JOIN community_reports r ON r.code = a.report_code
       ${where} ORDER BY a.created_at DESC LIMIT 200`, params);
    res.json({ ok: true, items: rows, status });
  } catch (error) {
    console.error("Admin appeals load error:", error.message);
    res.status(500).json({ ok: false, error: "admin_appeals_failed" });
  }
});

app.patch("/api/admin/appeals/:id", requireAdmin, rateLimit({ max: 240 }), async (req, res) => {
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  const id = String(req.params.id || "");
  const status = String(req.body?.status || "").toLowerCase();
  const note = compactSpaces(req.body?.note || "").slice(0, 1000);
  if (!["pending", "resolved", "rejected"].includes(status) || !/^[0-9a-f-]{36}$/i.test(id)) return res.status(400).json({ ok: false, error: "invalid_appeal_update" });
  try {
    const { rows } = await pool.query(`UPDATE report_appeals SET status=$1, moderator_note=$2, updated_at=NOW() WHERE id=$3 RETURNING id,status,updated_at`, [status,note,id]);
    if (!rows.length) return res.status(404).json({ ok: false, error: "not_found" });
    res.json({ ok: true, appeal: rows[0] });
  } catch (error) {
    console.error("Admin appeal update error:", error.message);
    res.status(500).json({ ok: false, error: "appeal_update_failed" });
  }
});

app.get("/api/profile", rateLimit({ max: 240 }), async (req, res) => {
  const clientId = getClientId(req);
  if (!clientId) return res.status(400).json({ ok: false, error: "client_id_required" });
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  try {
    await ensureClientProfile(clientId);
    const user = await getAuthUser(req);
    if (user) {
      await attachAnonymousDataToUser(user.id, clientId);
      const { rows } = await pool.query(
        `SELECT u.nickname, u.created_at, u.updated_at,
                COALESCE((SELECT COUNT(*) FROM check_history WHERE user_id = u.id), 0)::int AS check_count,
                (SELECT MAX(created_at) FROM check_history WHERE user_id = u.id) AS last_check_at,
                COALESCE((SELECT COUNT(*) FROM community_reports WHERE submitter_user_id = u.id), 0)::int AS report_count,
                COALESCE((SELECT COUNT(*) FROM community_reports WHERE submitter_user_id = u.id AND status = 'pending'), 0)::int AS pending_count,
                COALESCE((SELECT COUNT(*) FROM community_reports WHERE submitter_user_id = u.id AND status = 'approved'), 0)::int AS approved_count,
                COALESCE((SELECT COUNT(*) FROM community_reports WHERE submitter_user_id = u.id AND status = 'rejected'), 0)::int AS rejected_count,
                COALESCE((SELECT COUNT(*) FROM auth_sessions WHERE user_id = u.id AND expires_at > NOW()), 0)::int AS active_session_count,
                u.password_changed_at
         FROM users u WHERE u.id = $1 LIMIT 1`, [user.id]);
      return res.json({ ok: true, profile: rows[0], account: { authenticated: true, email: user.email, emailVerified: user.email_verified, activeSessions: rows[0]?.active_session_count || 0, passwordChangedAt: rows[0]?.password_changed_at || null } });
    }
    const { rows } = await pool.query(
      `SELECT p.client_id, p.nickname, p.created_at, p.updated_at,
              COALESCE(h.check_count, 0)::int AS check_count, h.last_check_at,
              COALESCE(r.report_count, 0)::int AS report_count, COALESCE(r.pending_count, 0)::int AS pending_count,
              COALESCE(r.approved_count, 0)::int AS approved_count, COALESCE(r.rejected_count, 0)::int AS rejected_count
       FROM client_profiles p
       LEFT JOIN (SELECT client_id, COUNT(*) AS check_count, MAX(created_at) AS last_check_at FROM check_history WHERE client_id = $1 GROUP BY client_id) h ON h.client_id = p.client_id
       LEFT JOIN (SELECT submitter_client_id AS client_id, COUNT(*) AS report_count, COUNT(*) FILTER (WHERE status = 'pending') AS pending_count, COUNT(*) FILTER (WHERE status = 'approved') AS approved_count, COUNT(*) FILTER (WHERE status = 'rejected') AS rejected_count FROM community_reports WHERE submitter_client_id = $1 GROUP BY submitter_client_id) r ON r.client_id = p.client_id
       WHERE p.client_id = $1 LIMIT 1`, [clientId]);
    res.json({ ok: true, profile: rows[0], account: { authenticated: false } });
  } catch (error) {
    console.error("Profile load error:", error);
    res.status(500).json({ ok: false, error: "profile_failed" });
  }
});

app.patch("/api/profile", rateLimit({ max: 60 }), async (req, res) => {
  const clientId = getClientId(req);
  if (!clientId) return res.status(400).json({ ok: false, error: "client_id_required" });
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  const nickname = compactSpaces(req.body?.nickname || "").slice(0, 40);
  if (nickname.length < 2) return res.status(400).json({ ok: false, error: "invalid_nickname" });
  try {
    await ensureClientProfile(clientId);
    const user = await getAuthUser(req);
    if (user) {
      const { rows } = await pool.query(`UPDATE users SET nickname = $1, updated_at = NOW() WHERE id = $2 RETURNING id, nickname, created_at, updated_at`, [nickname, user.id]);
      return res.json({ ok: true, profile: rows[0] });
    }
    const { rows } = await pool.query(`UPDATE client_profiles SET nickname = $1, updated_at = NOW(), last_seen_at = NOW() WHERE client_id = $2 RETURNING client_id, nickname, created_at, updated_at`, [nickname, clientId]);
    res.json({ ok: true, profile: rows[0] });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ ok: false, error: "profile_update_failed" });
  }
});

app.get("/api/history", rateLimit({ max: 240 }), async (req, res) => {
  const clientId = getClientId(req);
  if (!clientId) return res.status(400).json({ ok: false, error: "client_id_required" });
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  try {
    await ensureClientProfile(clientId);
    const user = await getAuthUser(req);
    if (user) await attachAnonymousDataToUser(user.id, clientId);
    const { rows } = user
      ? await pool.query(`SELECT id, report_id, type, input_preview, score, level, label, reasons, created_at FROM check_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 200`, [user.id])
      : await pool.query(`SELECT id, report_id, type, input_preview, score, level, label, reasons, created_at FROM check_history WHERE client_id = $1 ORDER BY created_at DESC LIMIT 100`, [clientId]);
    res.json({ ok: true, items: rows, syncedAcrossDevices: Boolean(user) });
  } catch (error) {
    console.error("History load error:", error);
    res.status(500).json({ ok: false, error: "history_failed" });
  }
});

app.delete("/api/history", rateLimit({ max: 30 }), async (req, res) => {
  const clientId = getClientId(req);
  if (!clientId) return res.status(400).json({ ok: false, error: "client_id_required" });
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  try {
    const user = await getAuthUser(req);
    const result = user ? await pool.query(`DELETE FROM check_history WHERE user_id = $1`, [user.id]) : await pool.query(`DELETE FROM check_history WHERE client_id = $1`, [clientId]);
    res.json({ ok: true, deleted: result.rowCount || 0 });
  } catch {
    res.status(500).json({ ok: false, error: "history_clear_failed" });
  }
});

app.post("/api/history/import", rateLimit({ max: 10 }), async (req, res) => {
  const clientId = getClientId(req);
  if (!clientId) return res.status(400).json({ ok: false, error: "client_id_required" });
  if (!databaseReady || !pool) return res.status(503).json({ ok: false, error: "database_unavailable" });
  const items = Array.isArray(req.body?.items) ? req.body.items.slice(0, 30) : [];
  try {
    await ensureClientProfile(clientId);
    const user = await getAuthUser(req);
    let imported = 0;
    for (const item of items) {
      const reportId = String(item?.id || "").slice(0, 80);
      const input = compactSpaces(item?.input || "").slice(0, 500);
      if (!reportId || !input) continue;
      const score = Math.max(0, Math.min(100, Number(item?.score) || 0));
      const type = ALLOWED_TYPES.has(item?.type) ? item.type : "seller";
      const created = new Date(item?.createdAt || Date.now());
      const createdAt = Number.isNaN(created.getTime()) ? new Date() : created;
      const result = await pool.query(
        `INSERT INTO check_history (client_id, user_id, report_id, type, input_preview, score, level, label, reasons, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'[]'::jsonb,$9) ON CONFLICT (client_id, report_id) DO UPDATE SET user_id = COALESCE(check_history.user_id, EXCLUDED.user_id)`,
        [clientId, user?.id || null, reportId, type, input, score, String(item?.level || "low").slice(0,24), String(item?.label || "").slice(0,80), createdAt]);
      imported += result.rowCount || 0;
    }
    res.json({ ok: true, imported });
  } catch (error) {
    console.error("History import error:", error);
    res.status(500).json({ ok: false, error: "history_import_failed" });
  }
});

app.get("/api/admin/reports", requireAdmin, rateLimit({ max: 240 }), async (req, res) => {
  if (!databaseReady || !pool) {
    return res.status(503).json({ ok: false, error: "database_unavailable" });
  }

  const requestedStatus = String(req.query.status || "pending").toLowerCase();
  const allowedStatuses = new Set(["pending", "approved", "rejected", "all"]);
  const status = allowedStatuses.has(requestedStatus) ? requestedStatus : "pending";

  try {
    const params = [];
    const where = status === "all" ? "" : "WHERE status = $1";
    if (status !== "all") params.push(status);

    const { rows } = await pool.query(
      `SELECT id, code, target, target_key, type, reason, details, status,
              moderator_note, moderated_at, created_at, updated_at
       FROM community_reports
       ${where}
       ORDER BY created_at DESC
       LIMIT 200`,
      params
    );

    res.json({ ok: true, items: rows, status });
  } catch (error) {
    console.error("Admin reports load error:", error);
    res.status(500).json({ ok: false, error: "admin_reports_failed" });
  }
});

app.patch("/api/admin/reports/:code", requireAdmin, rateLimit({ max: 240 }), async (req, res) => {
  if (!databaseReady || !pool) {
    return res.status(503).json({ ok: false, error: "database_unavailable" });
  }

  const code = String(req.params.code || "").slice(0, 80);
  const status = String(req.body?.status || "").toLowerCase();
  const moderatorNote = compactSpaces(req.body?.note || "").slice(0, 1000);

  if (!new Set(["approved", "rejected", "pending"]).has(status)) {
    return res.status(400).json({ ok: false, error: "invalid_status" });
  }

  try {
    const { rows } = await pool.query(
      `UPDATE community_reports
       SET status = $1,
           moderator_note = $2,
           moderated_at = CASE WHEN $1 = 'pending' THEN NULL ELSE NOW() END,
           updated_at = NOW()
       WHERE code = $3
       RETURNING code, target, type, reason, details, status, moderator_note,
                 moderated_at, created_at, updated_at`,
      [status, moderatorNote, code]
    );

    if (!rows.length) return res.status(404).json({ ok: false, error: "not_found" });
    res.json({ ok: true, report: rows[0] });
  } catch (error) {
    console.error("Admin report update error:", error);
    res.status(500).json({ ok: false, error: "admin_update_failed" });
  }
});



const ADMIN_REVIEW_EVIDENCE_PLATFORMS = new Set(["seller", "contact", "facebook", "instagram", "whatsapp", "viber", "olx"]);

app.get("/api/admin/review-evidence", requireAdmin, rateLimit({ max: 240 }), async (req, res) => {
  if (!databaseReady || !pool) {
    return res.status(503).json({ ok: false, error: "database_unavailable" });
  }

  const rawTarget = compactSpaces(req.query.target || "").slice(0, 500);
  const targetKey = rawTarget ? normalizeTargetKey(rawTarget) : "";

  try {
    const params = [];
    let where = "";
    if (targetKey) {
      params.push(targetKey);
      where = "WHERE target_key = $1";
    }

    const { rows } = await pool.query(
      `SELECT id, target_key, platform, source_url, archived_text, summary,
              evidence_type, first_seen_at, missing_at, status, created_at
       FROM review_evidence
       ${where}
       ORDER BY created_at DESC
       LIMIT 200`,
      params
    );

    res.json({ ok: true, items: rows, targetKey });
  } catch (error) {
    console.error("Admin review evidence load error:", error);
    res.status(500).json({ ok: false, error: "admin_review_evidence_failed" });
  }
});

app.post("/api/admin/review-evidence", requireAdmin, rateLimit({ max: 120 }), async (req, res) => {
  if (!databaseReady || !pool) {
    return res.status(503).json({ ok: false, error: "database_unavailable" });
  }

  const rawTarget = compactSpaces(req.body?.target || "").slice(0, 500);
  const targetKey = normalizeTargetKey(rawTarget);
  const platform = String(req.body?.platform || "seller").toLowerCase();
  const sourceUrl = compactSpaces(req.body?.sourceUrl || "").slice(0, 1500);
  const archivedText = compactSpaces(req.body?.archivedText || "").slice(0, 5000);
  const summary = compactSpaces(req.body?.summary || "").slice(0, 1200);
  const evidenceType = compactSpaces(req.body?.evidenceType || "manual_archive").slice(0, 80) || "manual_archive";
  const firstSeenAt = req.body?.firstSeenAt ? new Date(req.body.firstSeenAt) : null;
  const missingAt = req.body?.missingAt ? new Date(req.body.missingAt) : null;

  if (!rawTarget || !targetKey) {
    return res.status(400).json({ ok: false, error: "target_required" });
  }
  if (!ADMIN_REVIEW_EVIDENCE_PLATFORMS.has(platform)) {
    return res.status(400).json({ ok: false, error: "invalid_platform" });
  }
  if (!archivedText && !summary) {
    return res.status(400).json({ ok: false, error: "review_text_required" });
  }
  if (firstSeenAt && Number.isNaN(firstSeenAt.getTime())) {
    return res.status(400).json({ ok: false, error: "invalid_first_seen_at" });
  }
  if (missingAt && Number.isNaN(missingAt.getTime())) {
    return res.status(400).json({ ok: false, error: "invalid_missing_at" });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO review_evidence
        (target_key, platform, source_url, archived_text, summary, evidence_type,
         first_seen_at, missing_at, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'verified')
       RETURNING id, target_key, platform, source_url, archived_text, summary,
                 evidence_type, first_seen_at, missing_at, status, created_at`,
      [
        targetKey,
        platform,
        sourceUrl,
        archivedText,
        summary || archivedText.slice(0, 500),
        evidenceType,
        firstSeenAt,
        missingAt
      ]
    );
    res.status(201).json({ ok: true, item: rows[0] });
  } catch (error) {
    console.error("Admin review evidence create error:", error);
    res.status(500).json({ ok: false, error: "admin_review_evidence_create_failed" });
  }
});

app.delete("/api/admin/review-evidence/:id", requireAdmin, rateLimit({ max: 120 }), async (req, res) => {
  if (!databaseReady || !pool) {
    return res.status(503).json({ ok: false, error: "database_unavailable" });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ ok: false, error: "invalid_id" });
  }

  try {
    const result = await pool.query(`DELETE FROM review_evidence WHERE id = $1`, [id]);
    if (!result.rowCount) return res.status(404).json({ ok: false, error: "not_found" });
    res.json({ ok: true, deleted: 1 });
  } catch (error) {
    console.error("Admin review evidence delete error:", error);
    res.status(500).json({ ok: false, error: "admin_review_evidence_delete_failed" });
  }
});

app.get("/privacy", (req, res) => {
  res.sendFile(path.join(__dirname, "privacy.html"));
});

app.get("/terms", (req, res) => {
  res.sendFile(path.join(__dirname, "terms.html"));
});

app.get("/reset-password", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile(path.join(__dirname, "reset.html"));
});

app.get("/admin", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile(path.join(__dirname, "admin.html"));
});


app.post("/api/watch", rateLimit({ max: 60 }), async (req,res)=>{if(!databaseReady||!pool)return res.status(503).json({ok:false,error:"database_unavailable"});const type=ALLOWED_TYPES.has(req.body?.type)?req.body.type:"seller";const input=String(req.body?.input||"").trim();if(!input)return res.status(400).json({ok:false,error:"input_required"});const ownerKey=await getOwnerKey(req);if(!ownerKey)return res.status(400).json({ok:false,error:"client_required"});const targetKey=normalizeTargetKey(input);await pool.query(`INSERT INTO watch_items (owner_key,target_key,type,target_preview,active,updated_at) VALUES ($1,$2,$3,$4,TRUE,NOW()) ON CONFLICT (owner_key,target_key,type) DO UPDATE SET target_preview=EXCLUDED.target_preview,active=TRUE,updated_at=NOW()`,[ownerKey,targetKey,type,compactSpaces(input).slice(0,300)]);res.json({ok:true,watching:true,targetKey});});
app.delete("/api/watch", rateLimit({ max:60 }), async(req,res)=>{if(!databaseReady||!pool)return res.status(503).json({ok:false,error:"database_unavailable"});const ownerKey=await getOwnerKey(req);const type=ALLOWED_TYPES.has(req.body?.type)?req.body.type:"seller";const targetKey=normalizeTargetKey(req.body?.input||"");if(!ownerKey||!targetKey)return res.status(400).json({ok:false,error:"invalid_request"});await pool.query(`UPDATE watch_items SET active=FALSE,updated_at=NOW() WHERE owner_key=$1 AND target_key=$2 AND type=$3`,[ownerKey,targetKey,type]);res.json({ok:true,watching:false});});
app.get("/api/watch", rateLimit({ max:120 }), async(req,res)=>{if(!databaseReady||!pool)return res.json({ok:true,items:[],events:[]});const ownerKey=await getOwnerKey(req);if(!ownerKey)return res.json({ok:true,items:[],events:[]});const [items,events]=await Promise.all([pool.query(`SELECT target_key,type,target_preview,created_at,updated_at FROM watch_items WHERE owner_key=$1 AND active=TRUE ORDER BY updated_at DESC LIMIT 100`,[ownerKey]),pool.query(`SELECT target_key,type,message,before_score,after_score,created_at FROM watch_events WHERE owner_key=$1 ORDER BY created_at DESC LIMIT 50`,[ownerKey])]);res.json({ok:true,items:items.rows,events:events.rows});});

app.post("/api/share-check", rateLimit({max:60}), async(req,res)=>{if(!databaseReady||!pool)return res.status(503).json({ok:false,error:"database_unavailable"});const report=req.body?.report;if(!report||typeof report!=="object")return res.status(400).json({ok:false,error:"report_required"});const shareId=crypto.randomBytes(8).toString("hex");await pool.query(`INSERT INTO shared_checks (share_id,report,input_preview) VALUES ($1,$2::jsonb,$3)`,[shareId,JSON.stringify(report),compactSpaces(req.body?.inputPreview||"").slice(0,300)]);res.json({ok:true,shareId,url:`${APP_BASE_URL}/share/${shareId}`,reportUrl:`${APP_BASE_URL}/report/${shareId}`});});
app.get("/api/shared/:id",rateLimit({max:180}),async(req,res)=>{if(!databaseReady||!pool)return res.status(503).json({ok:false,error:"database_unavailable"});const id=String(req.params.id||"");if(!/^[a-f0-9]{16}$/i.test(id))return res.status(400).json({ok:false,error:"invalid_id"});const {rows}=await pool.query(`SELECT share_id,report,input_preview,created_at FROM shared_checks WHERE share_id=$1 LIMIT 1`,[id]);if(!rows[0])return res.status(404).json({ok:false,error:"not_found"});res.json({ok:true,item:rows[0]});});

function sharedHtml(item,printMode=false){const r=item.report||{};const esc=v=>String(v??"").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));const ev=(r.evidence?.items||[]).slice(0,80).map(x=>`<li><b>${esc(x.title)}</b> — ${esc(x.detail)} <small>(${esc(x.confidence)})</small></li>`).join("");const ch=(r.changesSinceLastCheck?.items||[]).map(x=>`<li>${esc(x)}</li>`).join("");const rel=(r.relatedObjects||[]).map(x=>`<li>${esc(x.type)}: ${esc(x.targetKey)} — ${esc(x.note)}</li>`).join("");return `<!doctype html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SafeDeal Report ${esc(r.id||item.share_id)}</title><style>body{font-family:Arial,sans-serif;background:#07111f;color:#eef6ff;max-width:900px;margin:auto;padding:28px}article{background:#0d1a2b;border:1px solid #223750;border-radius:20px;padding:24px}.risk{font-size:34px;font-weight:900}.score,.muted{opacity:.65}.box{margin-top:18px;padding:16px;background:#101f32;border-radius:14px}li{margin:8px 0;line-height:1.45}.actions{display:flex;gap:10px;margin:18px 0}.actions a,.actions button{padding:11px 14px;border-radius:10px;border:0;text-decoration:none;background:#2086ff;color:#fff;font-weight:700}@media print{body{background:white;color:#111;padding:0}article{background:white;border:0}.actions{display:none}}</style></head><body><article><h1>SafeDeal Security Report</h1><div class="muted">ID: SD-${esc(item.share_id.toUpperCase())} · ${esc(new Date(item.created_at).toLocaleString("uk-UA"))}</div><div class="box"><div class="risk">${esc(r.label||"Результат")}</div><div class="score">${esc(r.score??0)}/100</div><h3>Ймовірна схема</h3><p>${esc(r.scamScheme?.label||"Не визначено")}</p><h3>Простими словами</h3><p>${esc(r.plainSummary||r.verdict?.text||"")}</p></div><div class="box"><h3>Докази та сигнали</h3><ul>${ev||"<li>Немає окремих доказів у збереженому результаті.</li>"}</ul><p class="muted">${esc(r.evidence?.note||"")}</p></div>${ch?`<div class="box"><h3>Що змінилося</h3><ul>${ch}</ul></div>`:""}${rel?`<div class="box"><h3>Пов’язані об’єкти</h3><ul>${rel}</ul></div>`:""}<div class="box"><h3>Рекомендації</h3><ul>${(r.actions||[]).map(x=>`<li>${esc(x)}</li>`).join("")}</ul></div><div class="actions"><a href="/?recheck=${encodeURIComponent(item.input_preview||"")}">Перевірити самому</a>${printMode?"":`<button onclick="window.print()">PDF / друк</button>`}</div><p class="muted">Результат актуальний на момент перевірки. Це оцінка доступних сигналів, не гарантія безпеки.</p></article></body></html>`;}
app.get("/share/:id",rateLimit({max:180}),async(req,res)=>{if(!databaseReady||!pool)return res.status(503).send("Database unavailable");const id=String(req.params.id||"");if(!/^[a-f0-9]{16}$/i.test(id))return res.status(400).send("Invalid report id");const {rows}=await pool.query(`SELECT share_id,report,input_preview,created_at FROM shared_checks WHERE share_id=$1 LIMIT 1`,[id]);if(!rows[0])return res.status(404).send("Report not found");res.type("html").send(sharedHtml(rows[0],false));});
app.get("/report/:id",rateLimit({max:180}),async(req,res)=>{if(!databaseReady||!pool)return res.status(503).send("Database unavailable");const id=String(req.params.id||"");if(!/^[a-f0-9]{16}$/i.test(id))return res.status(400).send("Invalid report id");const {rows}=await pool.query(`SELECT share_id,report,input_preview,created_at FROM shared_checks WHERE share_id=$1 LIMIT 1`,[id]);if(!rows[0])return res.status(404).send("Report not found");res.type("html").send(sharedHtml(rows[0],true));});

app.get("/api/passport",rateLimit({max:120}),async(req,res)=>{if(!databaseReady||!pool)return res.status(503).json({ok:false,error:"database_unavailable"});const type=ALLOWED_TYPES.has(req.query.type)?req.query.type:"seller";const input=String(req.query.input||"").trim();const targetKey=normalizeTargetKey(input);if(!targetKey)return res.status(400).json({ok:false,error:"input_required"});const er=await pool.query(`SELECT entity_kind,entity_value FROM object_entities WHERE target_key=$1 AND type=$2`,[targetKey,type]);const entities=er.rows.map(x=>({kind:x.entity_kind,value:x.entity_value}));const related=await getRelatedObjects(targetKey,type,entities);const [snapshots,complaints,archive]=await Promise.all([pool.query(`SELECT score,label,scheme_key,complaint_count,review_count,created_at FROM target_snapshots WHERE target_key=$1 AND type=$2 ORDER BY created_at DESC LIMIT 50`,[targetKey,type]),pool.query(`SELECT COUNT(*)::int AS count FROM community_reports WHERE target_key=$1 AND status='approved'`,[targetKey]),pool.query(`SELECT COUNT(*)::int AS count FROM review_evidence WHERE target_key=$1 AND status='verified'`,[targetKey])]);const rows=snapshots.rows;res.json({ok:true,passport:{targetKey,type,latest:rows[0]||null,checks:rows.length,approvedComplaints:Number(complaints.rows[0]?.count||0),archivedReviews:Number(archive.rows[0]?.count||0),history:rows.map(x=>({score:x.score,label:x.label,schemeKey:x.scheme_key,createdAt:x.created_at})),related}});});
app.post("/api/image-fingerprint",rateLimit({max:80}),async(req,res)=>{if(!databaseReady||!pool)return res.status(503).json({ok:false,error:"database_unavailable"});const ahash=String(req.body?.ahash||"").toLowerCase();if(!/^[0-9a-f]{16}$/.test(ahash))return res.status(400).json({ok:false,error:"invalid_hash"});const targetPreview=compactSpaces(req.body?.target||"").slice(0,300);const targetKey=normalizeTargetKey(targetPreview);const {rows}=await pool.query(`SELECT id,ahash,target_key,target_preview,source_label,created_at FROM image_fingerprints ORDER BY created_at DESC LIMIT 1000`);const matches=rows.map(row=>({...row,distance:hammingDistanceHex64(ahash,row.ahash)})).filter(row=>row.distance<=8&&(!targetKey||row.target_key!==targetKey)).sort((x,y)=>x.distance-y.distance).slice(0,20);await pool.query(`INSERT INTO image_fingerprints (ahash,target_key,target_preview) VALUES ($1,$2,$3)`,[ahash,targetKey,targetPreview]);res.json({ok:true,exactOrSimilarCount:matches.length,matches:matches.map(x=>({similarity:Math.max(0,Math.round((1-x.distance/64)*100)),target:x.target_preview,source:x.source_label,createdAt:x.created_at})),note:"Антифейк-фото порівнює зображення з власною історією SafeDeal. Це не глобальний reverse-image search по всьому інтернету."});});

app.post("/api/check", rateLimit({ max: 80 }), async (req, res) => {
  const { type = "seller", input = "", historyPreview = "" } = req.body || {};
  if (!String(input).trim()) return res.status(400).json({ ok:false, error:"input_required" });
  if (String(input).length > 12000) return res.status(413).json({ ok:false, error:"input_too_long" });
  try {
    const report = await analyzeInput(type, input);
    const clientId = getClientId(req);
    const authUser = (clientId && databaseReady) ? await getAuthUser(req) : null;
    let historySaved = false;
    if (clientId && databaseReady) {
      try { historySaved = await saveCheckHistory(clientId, authUser?.id || null, report, compactSpaces(historyPreview || input).slice(0,500)); }
      catch (historyError) { console.error("History save error:", historyError.message); }
    }
    const targetKey = normalizeTargetKey(input); report.targetKey = targetKey;
    if (databaseReady && pool && targetKey) {
      const entities=extractObjectEntities(report.type,input,report);
      await persistEntities(targetKey,report.type,entities);
      report.relatedObjects=await getRelatedObjects(targetKey,report.type,entities);
      report.changesSinceLastCheck=await saveTargetSnapshot({targetKey,type:report.type,report,input});
      const ownerKey=authUser?.id?`user:${authUser.id}`:(clientId?`client:${clientId}`:"");
      report.watchEventCreated=await createWatchEventIfNeeded(ownerKey,targetKey,report.type,report.changesSinceLastCheck,report.score);
      const watched=ownerKey?await pool.query(`SELECT 1 FROM watch_items WHERE owner_key=$1 AND target_key=$2 AND type=$3 AND active=TRUE LIMIT 1`,[ownerKey,targetKey,report.type]):{rowCount:0};
      report.isWatched=Boolean(watched.rowCount);
    } else {
      report.relatedObjects=[]; report.changesSinceLastCheck={firstCheck:true,changed:false,items:[],scoreDelta:0}; report.isWatched=false;
    }
    res.json({ok:true,report,historySaved});
  } catch(error) { console.error("SafeDeal check error:",error); res.status(500).json({ok:false,error:"check_failed"}); }
});

app.use(express.static(__dirname));

app.use((error, req, res, next) => {
  console.error("Unhandled request error:", error?.message || "unknown_error");
  if (res.headersSent) return next(error);
  res.status(500).json({ ok: false, error: "internal_error" });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

async function start() {
  await initDatabase();
  app.listen(PORT, () => {
    console.log(`SafeDeal ${APP_VERSION} started on port ${PORT}`);
    console.log(`Google Web Risk: ${GOOGLE_WEB_RISK_API_KEY ? "configured" : "not configured"}`);
    console.log(`PhishTank: enabled (${PHISHTANK_APP_KEY ? "API key configured" : "keyless / lower rate limit"})`);
    console.log(`URLhaus: ${URLHAUS_AUTH_KEY ? "configured" : "not configured"}`);
    console.log(`ThreatFox: ${ABUSECH_AUTH_KEY ? "configured" : "not configured"}`);
    console.log(`Database: ${databaseReady ? "ready" : DATABASE_URL ? "configured but unavailable" : "not configured"}`);
    console.log(`Admin moderation: ${ADMIN_KEY ? "configured" : "not configured"}`);
    console.log(`Password reset email: ${RESEND_API_KEY ? "configured" : "not configured"}`);
  });
}

start().catch((error) => {
  console.error("SafeDeal startup error:", error);
  process.exit(1);
});
