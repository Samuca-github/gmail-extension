import { CONFIG } from "./config.js";

// =============================================================
//  AUTH — apenas Supabase (e-mail + senha)
//  Gmail API — chrome.identity.getAuthToken + OAuth Client "Chrome Extension" no manifest
// =============================================================

const STORAGE_KEY = "supabase_session";

async function saveSession(session) {
  const enriched = {
    ...session,
    expires_at: Math.floor(Date.now() / 1000) + (session.expires_in ?? 3600),
  };
  await chrome.storage.local.set({ [STORAGE_KEY]: enriched });
  return enriched;
}

async function getStoredSession() {
  const data = await chrome.storage.local.get(STORAGE_KEY);
  return data[STORAGE_KEY] ?? null;
}

async function clearSession() {
  await chrome.storage.local.remove(STORAGE_KEY);
}

async function refreshSupabaseSession(refreshToken) {
  const url = `${CONFIG.SUPABASE_URL.replace(/\/$/, "")}/auth/v1/token?grant_type=refresh_token`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: CONFIG.SUPABASE_ANON_KEY,
    },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    throw new Error(`Refresh falhou: ${r.status} ${txt}`);
  }
  return r.json();
}

async function ensureValidSession() {
  let session = await getStoredSession();
  if (!session) return null;

  const now = Math.floor(Date.now() / 1000);
  if (session.expires_at && session.expires_at - now > 60) return session;

  if (!session.refresh_token) {
    await clearSession();
    return null;
  }

  try {
    const refreshed = await refreshSupabaseSession(session.refresh_token);
    return saveSession(refreshed);
  } catch {
    await clearSession();
    return null;
  }
}

async function supabaseSignUpWithEmail({ email, password }) {
  const url = `${CONFIG.SUPABASE_URL.replace(/\/$/, "")}/auth/v1/signup`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: CONFIG.SUPABASE_ANON_KEY,
    },
    body: JSON.stringify({ email, password }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = data?.msg || data?.error_description || data?.error || JSON.stringify(data);
    throw new Error(`Cadastro falhou: ${r.status} ${msg}`);
  }
  return data;
}

async function supabaseSignInWithPassword({ email, password }) {
  const url = `${CONFIG.SUPABASE_URL.replace(/\/$/, "")}/auth/v1/token?grant_type=password`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: CONFIG.SUPABASE_ANON_KEY,
    },
    body: JSON.stringify({ email, password }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = data?.msg || data?.error_description || data?.error || JSON.stringify(data);
    throw new Error(`Login falhou: ${r.status} ${msg}`);
  }
  return data;
}

async function signOutFlow() {
  const session = await getStoredSession();
  if (session?.access_token) {
    try {
      await fetch(`${CONFIG.SUPABASE_URL.replace(/\/$/, "")}/auth/v1/logout`, {
        method: "POST",
        headers: {
          apikey: CONFIG.SUPABASE_ANON_KEY,
          Authorization: `Bearer ${session.access_token}`,
        },
      });
    } catch {
      /* ignora */
    }
  }
  await clearSession();
  await new Promise((resolve) => {
    chrome.identity.clearAllCachedAuthTokens(() => resolve());
  });
}

// =============================================================
//  Gmail API (token via manifest oauth2 — Client ID tipo Chrome Extension)
// =============================================================

function requestChromeIdentityToken(interactive) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!token) reject(new Error("Token Gmail vazio"));
      else resolve(token);
    });
  });
}

async function getGmailAccessToken() {
  try {
    return await requestChromeIdentityToken(false);
  } catch {
    return await requestChromeIdentityToken(true);
  }
}

async function gmailGetMessageFull(token, id) {
  const url = `https://www.googleapis.com/gmail/v1/users/me/messages/${id}?format=full`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`gmail full failed: ${r.status}`);
  return r.json();
}

async function gmailGetThread(token, threadId) {
  const url = `https://www.googleapis.com/gmail/v1/users/me/threads/${threadId}?format=metadata&metadataHeaders=From&metadataHeaders=Subject`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`threads.get failed: ${r.status}`);
  return r.json();
}

function pickLikelyMessageIdFromThread(threadJson) {
  const msgs = threadJson?.messages || [];
  if (!msgs.length) return null;
  return msgs[msgs.length - 1].id;
}

function b64urlDecode(str = "") {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 === 2 ? "==" : s.length % 4 === 3 ? "=" : "";
  const decoded = atob(s + pad);
  try {
    return decodeURIComponent(escape(decoded));
  } catch {
    return decoded;
  }
}

function collectParts(payload, out = []) {
  if (!payload) return out;
  if (payload.body?.data && payload.mimeType) {
    out.push({ mimeType: payload.mimeType, data: payload.body.data });
  }
  (payload.parts || []).forEach((p) => collectParts(p, out));
  return out;
}

function stripHtmlToText(html = "") {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractLinksFromText(text = "") {
  const re = /\bhttps?:\/\/[^\s<>"')]+/gi;
  return Array.from(new Set(text.match(re) || []));
}

function extractLinksFromHtml(html = "") {
  const links = [];
  const re = /href\s*=\s*"(.*?)"/gi;
  let m;
  while ((m = re.exec(html))) {
    const href = (m[1] || "").trim();
    if (!href || href.startsWith("#") || href.startsWith("mailto:")) continue;
    links.push(href);
  }
  return Array.from(new Set(links));
}

function parseAuthResults(val = "") {
  const lower = String(val || "").toLowerCase();
  const spf = (lower.match(/spf=(pass|fail|softfail|neutral|none)/) || [])[1] || "none";
  const dmarc = (lower.match(/dmarc=(pass|fail|quarantine|reject|none)/) || [])[1] || "none";
  const dkim = (lower.match(/dkim=(pass|fail|none)/) || [])[1] || "none";
  return { spf, dmarc, dkim };
}

function parseReceivedSpf(val = "") {
  const lower = String(val || "").toLowerCase();
  const m = lower.match(/\b(pass|fail|softfail|neutral|none)\b/);
  return m ? m[1] : "none";
}

function parseEmailAddresses(headerValue = "") {
  const emails = [];
  const re = /<\s*([^>]+@[^>]+)\s*>|(\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)/gi;
  let m;
  while ((m = re.exec(headerValue))) {
    const e = (m[1] || m[2] || "").trim().toLowerCase();
    if (e) emails.push(e);
  }
  return Array.from(new Set(emails));
}

function pickHeadersFromPayload(payload) {
  const headersArr = payload?.headers || [];
  const obj = {};
  for (const h of headersArr) obj[h.name] = h.value;
  return obj;
}

function buildAnalyzePayloadFromFullMessage(msgFull, threadId) {
  const allHeaders = pickHeadersFromPayload(msgFull.payload);

  const subject = allHeaders["Subject"] || "";
  const fromHeader = allHeaders["From"] || "";
  const toHeader = allHeaders["To"] || "";

  const fromEmails = parseEmailAddresses(fromHeader);
  const toEmails = parseEmailAddresses(toHeader);

  const parts = collectParts(msgFull.payload);
  const textPart = parts.find((p) => p.mimeType?.toLowerCase().includes("text/plain"));
  const htmlPart = parts.find((p) => p.mimeType?.toLowerCase().includes("text/html"));

  const body_text = textPart
    ? b64urlDecode(textPart.data)
    : htmlPart
      ? stripHtmlToText(b64urlDecode(htmlPart.data))
      : "";

  const linksHtml = htmlPart ? extractLinksFromHtml(b64urlDecode(htmlPart.data)) : [];
  const linksTxt = extractLinksFromText(body_text);
  const links = Array.from(new Set([...linksHtml, ...linksTxt])).slice(0, 100);

  const authRaw = allHeaders["Authentication-Results"] || allHeaders["ARC-Authentication-Results"] || "";
  const { spf: spfFromAuth, dmarc, dkim } = parseAuthResults(authRaw);
  const spfFromReceived = parseReceivedSpf(allHeaders["Received-SPF"] || "");
  const received_spf = spfFromReceived || spfFromAuth || "none";

  return {
    email: {
      subject: subject || undefined,
      from: fromEmails[0] || undefined,
      to: toEmails.length ? toEmails : undefined,
      body_text: body_text ? body_text.slice(0, 20000) : undefined,
      headers: { received_spf, dmarc, dkim },
      links: links.length ? links : undefined,
    },
    context: {
      source: "gmail_extension",
      gmail_message_id: msgFull.id,
      gmail_thread_id: threadId || msgFull.threadId,
    },
  };
}

function normalizeScanLabel(lb) {
  const m = {
    suspicious: "suspeito",
    suspeito: "suspeito",
    benign: "legitimo",
    legitimo: "legitimo",
    phishing: "phishing",
  };
  return m[lb] || (lb && String(lb)) || "other";
}

function summarizeScans(rows) {
  const byLabel = { phishing: 0, suspeito: 0, legitimo: 0, other: 0 };
  const bySource = {};
  let disagreementCount = 0;
  for (const row of rows) {
    const lb = normalizeScanLabel(row.label);
    if (lb && lb in byLabel) byLabel[lb]++;
    else byLabel.other++;
    if (row.disagreement) disagreementCount++;
    const rawSrc = row.analyzed_by || row.source || "desconhecido";
    const src = rawSrc === "fallback" ? "reserva" : rawSrc === "gpt" ? "gpt" : String(rawSrc);
    bySource[src] = (bySource[src] || 0) + 1;
  }
  return {
    total: rows.length,
    byLabel,
    disagreementCount,
    bySource,
  };
}

async function fetchUserScansFromSupabase(accessToken) {
  const base = CONFIG.SUPABASE_URL.replace(/\/$/, "");
  const fields =
    "id,label,score,confidence,subject,from_address,created_at,analyzed_by,disagreement,source,gmail_message_id";
  const url = `${base}/rest/v1/scans?select=${encodeURIComponent(fields)}&order=created_at.desc&limit=200`;
  const r = await fetch(url, {
    headers: {
      apikey: CONFIG.SUPABASE_ANON_KEY,
      Authorization: `Bearer ${accessToken}`,
    },
  });
  if (r.status === 401) {
    const err = new Error("not_authenticated");
    err.status = 401;
    throw err;
  }
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`Supabase scans: ${r.status} ${t}`);
  }
  return r.json();
}

async function callAnalyzeApi(payload) {
  const session = await ensureValidSession();
  if (!session) throw new Error("Nao autenticado");

  const r = await fetch(CONFIG.ANALYZE_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${session.access_token}`,
    },
    body: JSON.stringify(payload),
  });

  if (r.status === 401) {
    await clearSession();
    throw new Error("Sessao expirada, faca login novamente");
  }
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`analyze failed: ${r.status} ${text}`);
  }
  return r.json();
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      switch (msg?.type) {
        case "AUTH_GET_SESSION": {
          const session = await ensureValidSession();
          sendResponse({ ok: true, session });
          return;
        }
        case "AUTH_SIGN_IN_EMAIL": {
          const { email, password } = msg.payload || {};
          if (!email || !password) {
            sendResponse({ ok: false, error: "Informe e-mail e senha." });
            return;
          }
          const supaSession = await supabaseSignInWithPassword({
            email: String(email).trim(),
            password: String(password),
          });
          const session = await saveSession(supaSession);
          sendResponse({ ok: true, session });
          return;
        }
        case "AUTH_SIGN_UP_EMAIL": {
          const { email, password } = msg.payload || {};
          if (!email || !password) {
            sendResponse({ ok: false, error: "Informe e-mail e senha." });
            return;
          }
          const data = await supabaseSignUpWithEmail({
            email: String(email).trim(),
            password: String(password),
          });
          if (data.access_token) {
            const session = await saveSession(data);
            sendResponse({ ok: true, session, needsEmailConfirmation: false });
            return;
          }
          sendResponse({
            ok: true,
            session: null,
            needsEmailConfirmation: true,
            message:
              "Conta criada. Confirme o e-mail (se o Supabase exigir) e depois entre com e-mail e senha.",
          });
          return;
        }
        case "AUTH_SIGN_OUT": {
          await signOutFlow();
          sendResponse({ ok: true });
          return;
        }
        case "METRICS_FETCH": {
          const session = await ensureValidSession();
          if (!session?.access_token) {
            sendResponse({ ok: false, error: "not_authenticated" });
            return;
          }
          const scans = await fetchUserScansFromSupabase(session.access_token);
          const summary = summarizeScans(Array.isArray(scans) ? scans : []);
          sendResponse({ ok: true, scans, summary });
          return;
        }
        case "ANALYZE_CURRENT_MESSAGE": {
          const session = await ensureValidSession();
          if (!session) {
            sendResponse({ ok: false, error: "not_authenticated" });
            return;
          }

          let { messageId, threadId } = msg.payload || {};
          let token;
          try {
            token = await getGmailAccessToken();
          } catch (e) {
            sendResponse({
              ok: false,
              error: "gmail_oauth_failed",
              detail: String(e?.message || e),
            });
            return;
          }

          if (!messageId && threadId) {
            const thread = await gmailGetThread(token, threadId);
            messageId = pickLikelyMessageIdFromThread(thread);
          }
          if (!messageId) throw new Error("Nao foi possivel identificar a mensagem aberta");

          const msgFull = await gmailGetMessageFull(token, messageId);
          const payload = buildAnalyzePayloadFromFullMessage(msgFull, threadId);
          const result = await callAnalyzeApi(payload);

          sendResponse({ ok: true, payload, result });
          return;
        }
        default:
          sendResponse({ ok: false, error: "unknown_message_type" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();
  return true;
});
