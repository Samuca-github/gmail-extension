const els = {
  loading: document.getElementById("loadingView"),
  login: document.getElementById("loginView"),
  app: document.getElementById("appView"),
  metrics: document.getElementById("metricsView"),
  loginStatus: document.getElementById("loginStatus"),
  logoutBtn: document.getElementById("logoutBtn"),
  openMetricsBtn: document.getElementById("openMetricsBtn"),
  metricsBackBtn: document.getElementById("metricsBackBtn"),
  metricsRefreshBtn: document.getElementById("metricsRefreshBtn"),
  metricsSummary: document.getElementById("metricsSummary"),
  metricsTableWrap: document.getElementById("metricsTableWrap"),
  metricsStatus: document.getElementById("metricsStatus"),
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
  els.metrics.classList.add("hidden");
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

function badgeClassForLabel(lb) {
  if (lb === "phishing") return "phishing";
  if (lb === "suspeito" || lb === "suspicious") return "suspeito";
  if (lb === "legitimo" || lb === "benign") return "legitimo";
  return "";
}

function labelTextPt(lb) {
  if (lb == null || lb === "") return "-";
  const m = {
    phishing: "phishing",
    suspeito: "suspeito",
    suspicious: "suspeito",
    legitimo: "legitimo",
    benign: "legitimo",
  };
  return m[lb] || lb || "?";
}

function confidenceTextPt(c) {
  if (c == null || c === "") return "-";
  const m = { baixa: "baixa", media: "media", alta: "alta", low: "baixa", medium: "media", high: "alta" };
  return m[c] || c || "-";
}

function categoryTextPt(c) {
  const m = {
    personificacao_marca: "personificacao de marca",
    coleta_credenciais: "coleta de credenciais",
    falsificacao_remetente: "falsificacao de remetente",
    extorsao: "extorsao",
    malware: "malware",
    golpe_fatura: "golpe de fatura",
    premio_falso: "premio falso",
    pagamento_falso: "pagamento falso",
    nenhum_sinal_critico: "nenhum sinal critico",
  };
  return m[c] || String(c).replace(/_/g, " ");
}

function renderResult(payload, response) {
  const r = response?.result || {};
  const b = response?.breakdown || {};
  const sourceLabels = {
    gpt: "GPT",
    reserva: "modo reserva (sem modelo)",
    fallback: "modo reserva (sem modelo)",
  };
  const sourceLabel = sourceLabels[b.analyzed_by] || b.analyzed_by || "?";

  const lb = r.label;
  const meterClass = (lb === "phishing") ? "high" : (lb === "suspeito" || lb === "suspicious") ? "med" : "low";
  const scorePct = Math.round((r.score ?? 0) * 100);

  const phishingAlert = lb === "phishing"
    ? `<div class="alert-danger">ALERTA: este e-mail foi classificado como phishing. Nao clique em links nem responda dados pessoais.</div>`
    : "";

  const categoriesHtml = (r.categories || []).length
    ? `<div style="margin-top:8px">
         <span style="font-size:11px; color:#6b7280">Categorias:</span><br/>
         ${r.categories.map((c) => `<span class="badge tag">${escapeHtml(categoryTextPt(c))}</span>`).join("")}
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
        <div class="breakdown-row"><span class="k">Score</span><span>${(b.ml_score ?? 0).toFixed(2)} (${labelTextPt(b.ml_label)})</span></div>
        <div class="breakdown-row"><span class="k">Confianca</span><span>${confidenceTextPt(b.ml_confidence)}</span></div>
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
        <span class="badge ${badgeClassForLabel(lb)}">${escapeHtml(labelTextPt(lb))}</span>
        <span class="badge source">via ${escapeHtml(sourceLabel)}</span>
      </div>
      <div style="margin-top:6px; font-size:11px; color:#6b7280">
        Score <strong>${scorePct}%</strong> &middot; confianca <strong>${escapeHtml(confidenceTextPt(r.confidence))}</strong>
      </div>
      <div class="meter"><div class="meter-fill ${meterClass}" style="width:${scorePct}%"></div></div>
      ${phishingAlert}
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

const SOURCE_LABELS = {
  gpt: "GPT",
  reserva: "modo reserva",
  fallback: "modo reserva",
};

const LABEL_PT = {
  phishing: "Phishing",
  suspeito: "Suspeito",
  legitimo: "Legitimo",
  suspicious: "Suspeito",
  benign: "Legitimo",
  other: "Outro",
};

function formatShortDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return String(iso);
  }
}

function sourceDisplay(key) {
  const k = key == null ? "" : String(key);
  if (k === "short_circuit" || k === "rules_only" || k === "regras_rapidas") return "GPT";
  return SOURCE_LABELS[k] || k;
}

function renderMetrics(scans, summary) {
  const s = summary || {};
  const bl = s.byLabel || {};
  const total = s.total ?? (Array.isArray(scans) ? scans.length : 0);
  const disc = s.disagreementCount ?? 0;

  const labelBoxes = ["phishing", "suspeito", "legitimo", "other"].map((key) => `
    <div class="metric-box">
      <div class="k">${LABEL_PT[key] || key}</div>
      <div class="v">${bl[key] ?? 0}</div>
    </div>
  `).join("");

  const bySrc = s.bySource || {};
  const srcRows = Object.entries(bySrc)
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `<li><strong>${escapeHtml(sourceDisplay(k))}</strong>: ${n}</li>`)
    .join("");

  els.metricsSummary.innerHTML = `
    <div class="metrics-stats">
      <div class="metric-box" style="grid-column:1/-1">
        <div class="k">Total de analises (nesta amostra)</div>
        <div class="v">${total}</div>
      </div>
      ${labelBoxes}     
    </div>
    <div class="metrics-sources">
      <strong>Por origem da decisao</strong> (<code>analyzed_by</code> / <code>source</code>):
      <ul>${srcRows || "<li>Nenhum dado</li>"}</ul>
    </div>
  `;

  const rows = Array.isArray(scans) ? scans.slice(0, 80) : [];
  if (!rows.length) {
    els.metricsTableWrap.innerHTML = "<p style=\"margin:12px; font-size:12px; color:var(--muted)\">Nenhuma linha ainda. Analise um e-mail para gravar em scans.</p>";
    return;
  }

  const thead = `
    <thead><tr>
      <th class="col-date">Data</th>
      <th class="col-label">Rotulo</th>
      <th class="col-score">Score</th>
      <th class="col-subj">Assunto</th>
      <th class="col-from">De</th>
    </tr></thead>`;
  const tbody = rows.map((row) => {
    const lb = row.label || "?";
    const badgeClass = badgeClassForLabel(lb);
    const disc = row.disagreement ? " *" : "";
    return `<tr>
      <td class="col-date">${escapeHtml(formatShortDate(row.created_at))}</td>
      <td class="col-label"><span class="badge ${badgeClass}">${escapeHtml(lb)}</span>${disc}</td>
      <td class="col-score">${row.score != null ? Math.round(Number(row.score) * 100) + "%" : "—"}</td>
      <td class="col-subj">${escapeHtml((row.subject || "").slice(0, 160))}</td>
      <td class="col-from">${escapeHtml((row.from_address || "").slice(0, 56))}</td>
    </tr>`;
  }).join("");

  els.metricsTableWrap.innerHTML = `<table class="metrics-table">${thead}<tbody>${tbody}</tbody></table>`;
}

async function loadMetrics() {
  els.metricsStatus.textContent = "Carregando...";
  els.metricsStatus.classList.remove("error");
  els.metricsSummary.innerHTML = "";
  els.metricsTableWrap.innerHTML = "";
  try {
    const resp = await sendBg({ type: "METRICS_FETCH" });
    if (!resp?.ok) {
      if (resp?.error === "not_authenticated") {
        show(els.login);
        setLoginStatus("Sessao expirada, entre novamente.", true);
        return;
      }
      throw new Error(resp?.error || "Falha ao carregar metricas");
    }
    renderMetrics(resp.scans, resp.summary);
    els.metricsStatus.textContent = "";
  } catch (e) {
    els.metricsStatus.textContent = `Erro: ${e.message || e}`;
    els.metricsStatus.classList.add("error");
  }
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
  if (els.metricsSummary) els.metricsSummary.innerHTML = "";
  if (els.metricsTableWrap) els.metricsTableWrap.innerHTML = "";
  if (els.metricsStatus) {
    els.metricsStatus.textContent = "";
    els.metricsStatus.classList.remove("error");
  }
  show(els.login);
});

els.openMetricsBtn?.addEventListener("click", () => {
  show(els.metrics);
  loadMetrics();
});

els.metricsBackBtn?.addEventListener("click", () => {
  els.metricsStatus.textContent = "";
  els.metricsStatus.classList.remove("error");
  show(els.app);
});

els.metricsRefreshBtn?.addEventListener("click", () => {
  loadMetrics();
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
