// content.js
console.log("[phishing-ext] content.js carregado:", location.href);

function getMessageIdFromDom() {
  // 1) Pega o último elemento visível com data-legacy-message-id
  const all = Array.from(document.querySelectorAll('[data-legacy-message-id]'));
  const visible = all.reverse().find(el => {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  });
  const id = visible?.getAttribute('data-legacy-message-id');
  if (id) return id;

  // 2) Procura containers típicos da mensagem aberta
  const opened = document.querySelectorAll('.adn, .a3s'); // áreas comuns do corpo
  for (const el of opened) {
    const host = el.closest('[data-legacy-message-id]');
    const v = host?.getAttribute('data-legacy-message-id');
    if (v) return v;
  }
  return null;
}

function getThreadIdFromUrl() {
  // Exemplos de URL ao abrir um e-mail:
  // https://mail.google.com/mail/u/0/#inbox/FMfcgzGrcp... (o token depois de /#inbox/ é o threadId)
  // https://mail.google.com/mail/u/0/?tab=rm&ogbl#inbox/FMfcgzQcpdpdXRRxbBcsCWrBmkrQPLSG
  const m = location.href.match(/#(?:inbox|all|spam|starred|trash|sent|drafts)\/([A-Za-z0-9_\-]+)/);
  return m ? m[1] : null;
}

// Observa mudanças para quando o usuário abre/fecha mensagens numa SPA
const ready = { hasSentReady: false };
const observer = new MutationObserver(() => {
  const mid = getMessageIdFromDom();
  if (mid && !ready.hasSentReady) {
    console.log("[phishing-ext] messageId observado:", mid);
    ready.hasSentReady = true;
  }
});
observer.observe(document.documentElement, { subtree: true, childList: true });

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "REQUEST_MESSAGE_ID") {
    const messageId = getMessageIdFromDom();
    const threadId = getThreadIdFromUrl();
    console.log("[phishing-ext] REQUEST_MESSAGE_ID →", { messageId, threadId });
    sendResponse({ messageId, threadId });
  }
});
