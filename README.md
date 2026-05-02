1. Criar OAuth no Google Cloud

    Ative Gmail API
    https://console.cloud.google.com/auth/branding?hl=pt-br

    Configure a OAuth consent screen (adicionar “User type: External” e seus e-mails de teste)

    Crie OAuth Client ID e copie o client_id

    Coloque no manifest.json em oauth2.client_id

2. Carregar a extensão

    Chrome → chrome://extensions

    Ative Developer mode

    Load unpacked → selecione a pasta gmail-phishing-ext/

3. Abrir o Gmail em uma aba, abrir um e-mail (visualizar mensagem).

4. Clicar no ícone da extensão → “Analisar e-mail aberto”

    O Chrome pedirá login/consent (primeira vez)

    O popup mostra o veredito e os headers SPF/DMARC/DKIM usados.
