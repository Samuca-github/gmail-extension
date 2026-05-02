import { CONFIG } from "./config.js";

// =============================================================
//  AUTH (Google OAuth + Supabase signInWithIdToken)
// =============================================================

const STORAGE_KEY = "supabase_session";
const STORAGE_KEY_USER_GOOGLE_CLIENT = "user_google_web_client_id";

function isPlausibleGoogleWebClientId(id) {
  return /^[\w.-]+\.apps\.googleusercontent\.com$/i.test(String(id || "").trim());
}

async function resolveGoogleWebClientId() {
  const data = await chrome.storage.local.get(STORAGE_KEY_USER_GOOGLE_CLIENT);
  const stored = String(data[STORAGE_KEY_USER_GOOGLE_CLIENT] ?? "").trim();
  const fallback = String(CONFIG.GOOGLE_WEB_CLIENT_ID ?? "").trim();
  const clientId = stored || fallback;
  if (!clientId || clientId.startsWith("COLE_AQUI")) {
    throw new Error(
      "GOOGLE_WEB_CLIENT_ID nao configurado. " +
        "Defina em config.js ou salve o OAuth Client ID (Web) nas opcoes da extensao."
    );
  }
  return clientId;
}

function generateNonce() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Supabase espera o nonce hasheado em SHA-256 HEXADECIMAL.
 * Quem envia para o Google e o Supabase deve combinar exatamente.
 */
async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

function getRedirectUri() {
  return chrome.identity.getRedirectURL("oauth2");
}

/**
 * Faz o fluxo OAuth implicit do Google via launchWebAuthFlow.
 *  - interactive=true + prompt='select_account' -> tela de login (primeira vez)
 *  - interactive=false + prompt='none' -> refresh silencioso (sem UI), falha se sessao Google expirou
 *
 * Retorna { idToken, accessToken, expiresIn, nonce } onde:
 *   - idToken: vai pro Supabase signInWithIdToken
 *   - accessToken: usado para Gmail API
 *   - expiresIn: segundos de validade do accessToken (~3600)
 */
async function googleAuthFlow({ interactive }) {
  const clientId = await resolveGoogleWebClientId();
  const scopes = CONFIG.GOOGLE_OAUTH_SCOPES.join(" ");
  const redirectUri = getRedirectUri();

  // Supabase exige nonce com hash SHA-256 (hex) no Google e o nonce raw no
  // signInWithIdToken. Esse e o pareamento documentado oficialmente.
  // Ref: https://supabase.com/docs/guides/auth/social-login/auth-google
  const nonce = generateNonce();
  const hashedNonce = await sha256Hex(nonce);
  const state = generateNonce();

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "id_token token",
    redirect_uri: redirectUri,
    scope: scopes,
    nonce: hashedNonce,
    state,
    // 'select_account' so quando interativo. No silencioso usamos 'none' para
    // o Google falhar rapido caso a sessao precise de UI.
    prompt: interactive ? "select_account" : "none",
  });

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  console.info("[phishing-ext] OAuth Google", { interactive, redirectUri });

  let responseUrl;
  try {
    responseUrl = await chrome.identity.launchWebAuthFlow({
      url: authUrl,
      interactive,
    });
  } catch (e) {
    if (!interactive) {
      const err = new Error("google_reauth_required");
      err.cause = e?.message || String(e);
      throw err;
    }
    throw new Error(
      `OAuth falhou (${e?.message || e}). Confira se o redirect URI '${redirectUri}' ` +
        `esta autorizado no OAuth Web Client do Google Cloud Console.`
    );
  }

  if (!responseUrl) {
    if (!interactive) throw new Error("google_reauth_required");
    throw new Error("OAuth cancelado");
  }

  const fragment = responseUrl.split("#")[1] || "";
  const fragParams = new URLSearchParams(fragment);
  const idToken = fragParams.get("id_token");
  const accessToken = fragParams.get("access_token");
  const expiresIn = Number(fragParams.get("expires_in") || 3600);
  const returnedState = fragParams.get("state");
  const error = fragParams.get("error");

  if (error) {
    // 'login_required', 'interaction_required', 'consent_required' = precisa UI
    const reauthErrors = ["login_required", "interaction_required", "consent_required"];
    if (!interactive && reauthErrors.includes(error)) {
      throw new Error("google_reauth_required");
    }
    throw new Error(`Google OAuth error: ${error}`);
  }
  if (returnedState !== state) throw new Error("OAuth state mismatch");
  if (!idToken) throw new Error("Sem id_token do Google");

  return { idToken, accessToken, expiresIn, nonce };
}

async function googleSignIn() {
  return googleAuthFlow({ interactive: true });
}

async function googleSilentRefresh() {
  return googleAuthFlow({ interactive: false });
}

/**
 * Troca o id_token Google por uma sessao Supabase (signInWithIdToken via REST).
 */
async function supabaseSignInWithGoogle({ idToken, nonce }) {
  const url = `${CONFIG.SUPABASE_URL}/auth/v1/token?grant_type=id_token`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: CONFIG.SUPABASE_ANON_KEY,
    },
    body: JSON.stringify({
      provider: "google",
      id_token: idToken,
      nonce,
    }),
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    throw new Error(`Supabase signin falhou: ${r.status} ${txt}`);
  }

  return r.json(); // { access_token, refresh_token, expires_in, user, ... }
}

/**
 * Salva (ou atualiza) a sessao no storage.
 *  - googleToken: { accessToken, expiresIn } | null  (passa null para preservar o que ja estava)
 */
async function saveSession(session, googleToken) {
  const now = Math.floor(Date.now() / 1000);
  const prev = await getStoredSession();
  const enriched = {
    ...session,
    expires_at: Math.floor(Date.now() / 1000) + (session.expires_in ?? 3600),
    google_access_token: googleToken?.accessToken ?? prev?.google_access_token ?? null,
    google_token_expires_at: googleToken
      ? now + (googleToken.expiresIn ?? 3600)
      : prev?.google_token_expires_at ?? null,
  };
  await chrome.storage.local.set({ [STORAGE_KEY]: enriched });
  return enriched;
}

async function updateGoogleToken({ accessToken, expiresIn }) {
  const session = await getStoredSession();
  if (!session) return null;
  const now = Math.floor(Date.now() / 1000);
  const updated = {
    ...session,
    google_access_token: accessToken,
    google_token_expires_at: now + (expiresIn ?? 3600),
  };
  await chrome.storage.local.set({ [STORAGE_KEY]: updated });
  return updated;
}

async function getStoredSession() {
  const data = await chrome.storage.local.get(STORAGE_KEY);
  return data[STORAGE_KEY] ?? null;
}

async function clearSession() {
  await chrome.storage.local.remove(STORAGE_KEY);
}

async function refreshSupabaseSession(refreshToken) {
  const url = `${CONFIG.SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`;
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

/**
 * Garante uma sessao Supabase valida. Faz refresh se faltam < 60s para expirar.
 */
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
    session = await saveSession(refreshed, session.google_access_token);
    return session;
  } catch {
    await clearSession();
    return null;
  }
}

async function signInFlow() {
  const google = await googleSignIn();
  const supaSession = await supabaseSignInWithGoogle({
    idToken: google.idToken,
    nonce: google.nonce,
  });
  return saveSession(supaSession, {
    accessToken: google.accessToken,
    expiresIn: google.expiresIn,
  });
}

async function signOutFlow() {
  const session = await getStoredSession();
  if (session?.access_token) {
    try {
      await fetch(`${CONFIG.SUPABASE_URL}/auth/v1/logout`, {
        method: "POST",
        headers: {
          apikey: CONFIG.SUPABASE_ANON_KEY,
          Authorization: `Bearer ${session.access_token}`,
        },
      });
    } catch {
      // ignora erro de logout remoto
    }
  }
  await clearSession();
}

// =============================================================
//  GMAIL API helpers
// =============================================================

/**
 * Retorna um access_token Google valido para a Gmail API.
 *  1. Se o token salvo ainda tem >60s ate expirar, usa.
 *  2. Caso contrario, faz um refresh silencioso via launchWebAuthFlow.
 *  3. Se o refresh silencioso falhar (sessao Google expirou ou foi revogada),
 *     lanca 'google_reauth_required' para o popup levar o usuario ao login.
 */
async function getGmailAccessToken() {
  const session = await ensureValidSession();
  if (!session) throw new Error("not_authenticated");

  const now = Math.floor(Date.now() / 1000);
  const exp = session.google_token_expires_at ?? 0;

  if (session.google_access_token && exp - now > 60) {
    return session.google_access_token;
  }

  console.info("[phishing-ext] google access_token expirado/ausente, tentando refresh silencioso");
  try {
    const fresh = await googleSilentRefresh();
    await updateGoogleToken({
      accessToken: fresh.accessToken,
      expiresIn: fresh.expiresIn,
    });
    return fresh.accessToken;
  } catch (err) {
    if (err?.message === "google_reauth_required") {
      throw err;
    }
    throw new Error(`Falha ao renovar token Google: ${err?.message || err}`);
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

// =============================================================
//  Email parsing
// =============================================================

function b64urlDecode(str = "") {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 === 2 ? "==" : s.length % 4 === 3 ? "=" : "";
  const decoded = atob(s + pad);
  try { return decodeURIComponent(escape(decoded)); } catch { return decoded; }
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

// =============================================================
//  Analyze API call
// =============================================================

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

// =============================================================
//  Listener
// =============================================================

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      switch (msg?.type) {
        case "AUTH_GET_REDIRECT_URI": {
          sendResponse({ ok: true, redirectUri: getRedirectUri() });
          return;
        }
        case "AUTH_GET_GOOGLE_CLIENT_ID_SETTINGS": {
          const data = await chrome.storage.local.get(STORAGE_KEY_USER_GOOGLE_CLIENT);
          const raw = data[STORAGE_KEY_USER_GOOGLE_CLIENT];
          const override = typeof raw === "string" ? raw.trim() : "";
          const defaultId = String(CONFIG.GOOGLE_WEB_CLIENT_ID ?? "").trim();
          const effective = override || defaultId;
          sendResponse({
            ok: true,
            override: override || "",
            defaultId,
            effective,
            hasOverride: override.length > 0,
          });
          return;
        }
        case "AUTH_SAVE_GOOGLE_CLIENT_ID": {
          const id = String(msg.clientId ?? "").trim();
          if (id && !isPlausibleGoogleWebClientId(id)) {
            sendResponse({
              ok: false,
              error:
                "Client ID invalido. Formato esperado: xxx.apps.googleusercontent.com",
            });
            return;
          }
          if (!id) {
            await chrome.storage.local.remove(STORAGE_KEY_USER_GOOGLE_CLIENT);
          } else {
            await chrome.storage.local.set({
              [STORAGE_KEY_USER_GOOGLE_CLIENT]: id,
            });
          }
          sendResponse({ ok: true });
          return;
        }
        case "AUTH_GET_SESSION": {
          const session = await ensureValidSession();
          sendResponse({ ok: true, session });
          return;
        }
        case "AUTH_SIGN_IN": {
          const session = await signInFlow();
          sendResponse({ ok: true, session });
          return;
        }
        case "AUTH_SIGN_OUT": {
          await signOutFlow();
          sendResponse({ ok: true });
          return;
        }
        case "ANALYZE_CURRENT_MESSAGE": {
          const session = await ensureValidSession();
          if (!session) {
            sendResponse({ ok: false, error: "not_authenticated" });
            return;
          }

          let { messageId, threadId } = msg.payload || {};
          const token = await getGmailAccessToken();

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
