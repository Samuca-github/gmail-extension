## Phishing Scanner (Gmail)

### Autenticacao

1. **Supabase (e-mail + senha)** — login da Analyze API; ative o provider **Email** no projeto.
2. **Gmail API** — separado: usa `chrome.identity.getAuthToken` com **OAuth Client ID tipo Chrome Extension** no `manifest.json` (`oauth2.client_id`).

O Client ID no Google Cloud deve listar o **ID da extensao** correto:

- Extensao publicada na Chrome Web Store: use o ID da loja (ex.: o que voce cadastrou no console).
- Desenvolvimento **Load unpacked**: o ID e outro (veja em `chrome://extensions` → Detalhes). Nesse caso crie/edite o cliente OAuth com **esse** ID ou use um `.pem` fixo para manter o mesmo ID entre cargas.

### Gmail API no Google Cloud

- Ative a **Gmail API** no projeto.
- Credenciais → **ID do cliente OAuth** → tipo **Extensao do Chrome** → cole o ID da extensao e o `client_id` gerado no `manifest.json` em `oauth2`.

### Uso

1. Carregue a extensao em `chrome://extensions`.
2. Abra o Gmail, visualize um e-mail.
3. Popup → entre com e-mail/senha → **Analisar e-mail aberto** (na primeira vez aceite o acesso ao Gmail).
