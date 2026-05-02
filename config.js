export const CONFIG = {
  ANALYZE_API_URL: "https://api-analize.onrender.com/analyze",
  SUPABASE_URL: "https://fmpsqygpdujikcqsuvke.supabase.co",
  SUPABASE_ANON_KEY:
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZtcHNxeWdwZHVqaWtjcXN1dmtlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzc0MDY1NDksImV4cCI6MjA5Mjk4MjU0OX0.Cep5oVgyc5-OY2IY48ntnyve5GQnTfYg3KRhDEHFIEM",

  // ATENCAO: este e um OAuth Client do tipo "Web application" (NAO "Chrome Extension").
  // Use-o com launchWebAuthFlow (necessario para obter id_token e fazer SSO no Supabase).
  // O redirect URI registrado no Google Cloud Console deve ser exatamente o valor de
  // chrome.identity.getRedirectURL("oauth2"), tipicamente:
  //   https://<EXTENSION_ID>.chromiumapp.org/oauth2
  GOOGLE_WEB_CLIENT_ID: "",

  GOOGLE_OAUTH_SCOPES: [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.readonly",
  ],
};
