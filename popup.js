const els = {
  loading: document.getElementById("loadingView"),
  login: document.getElementById("loginView"),
  app: document.getElementById("appView"),
  loginStatus: document.getElementById("loginStatus"),
  logoutBtn: document.getElementById("logoutBtn"),
  analyzeBtn: document.getElementById("analyzeBtn"),
  status: document.getElementById("status"),
  out: document.getElementById("out"),
  userAvatar: document.getElementById("userAvatar"),
  userName: document.getElementById("userName"),
  userEmail: document.getElementById("userEmail"),
  authEmail: document.getElementById("authEmail"),
  authPassword: document.getElementById("authPassword"),
  emailLoginBtn: document.getElementById("emailLoginBtn"),
  emailSignupBtn: document.getElementById("emailSignupBtn"),
};

function show(view) {
  els.loading.classList.add("hidden");
  els.login.classList.add("hidden");
  els.app.classList.add("hidden");
  view.classList.remove("hidden");
}

function setLoginStatus(text, isError = false) {
  els.loginStatus.textContent = text || "";
  els.loginStatus.classList.toggle("error", isError);
}

function setStatus(text, isError = false) {
  els.status.textContent = text || "";
  els.status.classList.toggle("error", isError);
}

async function sendBg(msg) {
  return chrome.runtime.sendMessage(msg);
}

function renderUser(session) {
  const meta = session.user?.user_metadata || {};
  els.userAvatar.src = meta.avatar_url || "";
  els.userAvatar.alt = meta.full_name || session.user?.email || "";
  els.userName.textContent = meta.full_name || meta.name || session.user?.email || "";
  els.userEmail.textContent = session.user?.email || "";
  els.logoutBtn.classList.remove("hidden");
}

function renderResult(payload, response) {
  const r = response?.result || {};
  const b = response?.breakdown || {};
  const sourceLabels = {
    gpt: "GPT",
    short_circuit: "regras rapidas",
    fallback: "fallback (GPT off)",
    rules_only: "so regras",
  };
  const sourceLabel = sourceLabels[b.analyzed_by] || b.analyzed_by || "?";

  const meterClass = (r.label === "phishing") ? "high" : (r.label === "suspicious") ? "med" : "low";
  const scorePct = Math.round((r.score ?? 0) * 100);

  const phishingAlert = r.label === "phishing"
    ? `<div class="alert-danger">ALERTA: este e-mail foi classificado como phishing. Nao clique em links nem responda dados pessoais.</div>`
    : "";

  const disagreementAlert = r.disagreement
    ? `<div class="alert-warning">As regras heuristicas e o GPT discordaram. A confianca foi reduzida; avalie com cuidado.</div>`
    : "";

  const categoriesHtml = (r.categories || []).length
    ? `<div style="margin-top:8px">
         <span style="font-size:11px; color:#6b7280">Categorias:</span><br/>
         ${r.categories.map((c) => `<span class="badge tag">${escapeHtml(c)}</span>`).join("")}
       </div>`
    : "";

  const explanationsHtml = (r.explanations || []).length
    ? `<div style="margin-top:10px">
         <strong style="font-size:12px">Por que:</strong>
         <ul class="explanations">
           ${r.explanations.map((e) => `<li>${escapeHtml(e)}</li>`).join("")}
         </ul>
       </div>`
    : "";

  const breakdownHtml = `
    <details style="margin-top:10px">
      <summary style="cursor:pointer; font-size:12px; color:#4b5563">Detalhamento da decisao</summary>
      <div style="margin-top:8px">
        <div class="breakdown-row"><span class="k">Origem</span><span>${escapeHtml(sourceLabel)}</span></div>
        <div class="breakdown-row"><span class="k">Score regras</span><span>${(b.rules_score ?? 0).toFixed(2)} (${b.rules_label ?? "-"})</span></div>
        <div class="breakdown-row"><span class="k">Score ML</span><span>${(b.ml_score ?? 0).toFixed(2)} (${b.ml_label ?? "-"})</span></div>
        <div class="breakdown-row"><span class="k">Confianca ML</span><span>${b.ml_confidence ?? "-"}</span></div>
        <div class="breakdown-row"><span class="k">Concordam?</span><span>${r.disagreement ? "nao" : "sim"}</span></div>
        <div style="margin-top:8px">
          <span style="font-size:11px; color:#6b7280">Headers SPF/DKIM/DMARC:</span>
          <pre>${escapeHtml(JSON.stringify(payload?.email?.headers ?? {}, null, 2))}</pre>
        </div>
      </div>
    </details>
  `;

  els.out.innerHTML = `
    <div class="result-card">
      <div style="display:flex; align-items:center; flex-wrap:wrap; gap:6px">
        <strong>Veredito:</strong>
        <span class="badge ${r.label || ""}">${r.label || "?"}</span>
        <span class="badge source">via ${escapeHtml(sourceLabel)}</span>
      </div>
      <div style="margin-top:6px; font-size:11px; color:#6b7280">
        Score combinado <strong>${scorePct}%</strong> &middot; confianca <strong>${r.confidence || "-"}</strong>
      </div>
      <div class="meter"><div class="meter-fill ${meterClass}" style="width:${scorePct}%"></div></div>
      ${phishingAlert}
      ${disagreementAlert}
      ${categoriesHtml}
      ${explanationsHtml}
      ${breakdownHtml}
    </div>
  `;
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function sendMsgToContent(tabId, msg) {
  try {
    return await chrome.tabs.sendMessage(tabId, msg);
  } catch (e) {
    if (String(e).includes("Receiving end does not exist")) {
      await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
      await new Promise((r) => setTimeout(r, 200));
      return await chrome.tabs.sendMessage(tabId, msg);
    }
    throw e;
  }
}

async function bootstrap() {
  show(els.loading);
  const sessionResp = await sendBg({ type: "AUTH_GET_SESSION" });

  if (sessionResp?.ok && sessionResp.session) {
    renderUser(sessionResp.session);
    show(els.app);
  } else {
    show(els.login);
  }
}

function readEmailPassword() {
  const email = (els.authEmail?.value ?? "").trim();
  const password = els.authPassword?.value ?? "";
  return { email, password };
}

function setEmailAuthBusy(busy) {
  if (els.emailLoginBtn) els.emailLoginBtn.disabled = busy;
  if (els.emailSignupBtn) els.emailSignupBtn.disabled = busy;
}

els.emailLoginBtn?.addEventListener("click", async () => {
  const { email, password } = readEmailPassword();
  if (!email || !password) {
    setLoginStatus("Preencha e-mail e senha.", true);
    return;
  }
  setLoginStatus("Entrando...");
  setEmailAuthBusy(true);
  try {
    const resp = await sendBg({
      type: "AUTH_SIGN_IN_EMAIL",
      payload: { email, password },
    });
    if (!resp?.ok) throw new Error(resp?.error || "Falha no login");
    renderUser(resp.session);
    setLoginStatus("");
    if (els.authPassword) els.authPassword.value = "";
    show(els.app);
  } catch (e) {
    setLoginStatus(`Erro: ${e.message || e}`, true);
  } finally {
    setEmailAuthBusy(false);
  }
});

els.emailSignupBtn?.addEventListener("click", async () => {
  const { email, password } = readEmailPassword();
  if (!email || !password) {
    setLoginStatus("Preencha e-mail e senha para criar a conta.", true);
    return;
  }
  if (password.length < 6) {
    setLoginStatus("A senha deve ter pelo menos 6 caracteres.", true);
    return;
  }
  setLoginStatus("Criando conta...");
  setEmailAuthBusy(true);
  try {
    const resp = await sendBg({
      type: "AUTH_SIGN_UP_EMAIL",
      payload: { email, password },
    });
    if (!resp?.ok) throw new Error(resp?.error || "Falha no cadastro");
    if (resp.needsEmailConfirmation && !resp.session) {
      setLoginStatus(resp.message || "Verifique seu e-mail para confirmar a conta.", false);
      return;
    }
    if (resp.session) {
      renderUser(resp.session);
      setLoginStatus("");
      if (els.authPassword) els.authPassword.value = "";
      show(els.app);
      return;
    }
    setLoginStatus("Conta criada. Agora use Entrar.", false);
  } catch (e) {
    setLoginStatus(`Erro: ${e.message || e}`, true);
  } finally {
    setEmailAuthBusy(false);
  }
});

els.logoutBtn.addEventListener("click", async () => {
  await sendBg({ type: "AUTH_SIGN_OUT" });
  els.logoutBtn.classList.add("hidden");
  els.out.innerHTML = "";
  setStatus("");
  show(els.login);
});

els.analyzeBtn.addEventListener("click", async () => {
  els.out.innerHTML = "";
  setStatus("Coletando identificadores...");
  els.analyzeBtn.disabled = true;
  try {
    const tab = await getCurrentTab();
    if (!tab?.id || !/^https:\/\/mail\.google\.com\//.test(tab.url || "")) {
      throw new Error("Abra um e-mail no Gmail e tente novamente.");
    }

    const ids = await sendMsgToContent(tab.id, { type: "REQUEST_MESSAGE_ID" });
    const { messageId, threadId } = ids || {};
    if (!messageId && !threadId) {
      throw new Error("Nao encontrei messageId/threadId. Abra o e-mail (nao so a lista).");
    }

    setStatus("Pedindo acesso ao Gmail (se for a primeira vez, aceite na janela do Chrome)...");
    const resp = await sendBg({
      type: "ANALYZE_CURRENT_MESSAGE",
      payload: { messageId, threadId },
    });
    if (!resp?.ok) {
      if (resp?.error === "not_authenticated") {
        show(els.login);
        setLoginStatus("Sessao expirada, entre novamente.", true);
        return;
      }
      if (resp?.error === "gmail_oauth_failed") {
        setStatus(
          `Nao foi possivel autorizar o Gmail: ${resp.detail || "verifique o Client ID (Chrome Extension) e o ID da extensao no Google Cloud."}`,
          true
        );
        return;
      }
      throw new Error(resp?.error || "Falha na analise");
    }

    setStatus("Analise concluida.");
    renderResult(resp.payload, resp.result);
  } catch (e) {
    setStatus(`Erro: ${e.message || e}`, true);
  } finally {
    els.analyzeBtn.disabled = false;
  }
});

bootstrap();
