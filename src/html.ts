/** HTML Page templates for dsh-web-auth. */

export interface RenderLoginOptions {
  readonly error?: string
}

export interface RenderChangePasswordOptions {
  readonly error?: string
  readonly success?: string
}

/** Escapar entidades HTML básicas para evitar XSS. */
function escapeHtml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

/** Renderizar página de login HTML moderna (Dark Theme alinhada ao DSH). */
export function renderLoginPage(options: RenderLoginOptions = {}): string {
  const errorMsg = options.error !== undefined ? escapeHtml(options.error) : undefined
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login - DeepSeek Harness</title>
  <style>
    :root {
      --bg-color: #111418;
      --card-bg: #1b1f24;
      --border-color: #2b3036;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --accent-color: #4f46e5;
      --accent-hover: #4338ca;
      --error-bg: #3c1e1e;
      --error-border: #7f1d1d;
      --error-text: #f87171;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-color);
      color: var(--text-primary);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 16px;
    }
    .login-card {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 32px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 24px;
    }
    .brand-logo {
      width: 36px;
      height: 36px;
      background: var(--accent-color);
      border-radius: 8px;
      display: grid;
      place-items: center;
      font-weight: 700;
      font-size: 14px;
      color: #ffffff;
      letter-spacing: 0.5px;
    }
    .brand-title {
      font-size: 18px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .subtitle {
      font-size: 13px;
      color: var(--text-secondary);
      margin-bottom: 20px;
      line-height: 1.4;
    }
    .alert-error {
      background: var(--error-bg);
      border: 1px solid var(--error-border);
      color: var(--error-text);
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      margin-bottom: 16px;
    }
    .form-group {
      margin-bottom: 20px;
    }
    label {
      display: block;
      font-size: 12px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    input[type="password"] {
      width: 100%;
      padding: 10px 14px;
      background: var(--bg-color);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      color: var(--text-primary);
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s;
    }
    input[type="password"]:focus {
      border-color: var(--accent-color);
    }
    button[type="submit"] {
      width: 100%;
      padding: 12px;
      background: var(--accent-color);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.2s;
    }
    button[type="submit"]:hover {
      background: var(--accent-hover);
    }
    .footer-note {
      text-align: center;
      font-size: 11px;
      color: var(--text-secondary);
      margin-top: 24px;
    }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="brand">
      <div class="brand-logo">DSH</div>
      <div class="brand-title">DeepSeek Harness</div>
    </div>
    <div class="subtitle">Insira sua senha de acesso para continuar</div>
    ${errorMsg !== undefined ? `<div class="alert-error">${errorMsg}</div>` : ''}
    <form method="POST" action="/login">
      <div class="form-group">
        <label for="password">Senha de Acesso</label>
        <input type="password" id="password" name="password" autofocus required placeholder="Sua senha">
      </div>
      <button type="submit">Entrar</button>
    </form>
    <div class="footer-note">Acesso seguro com autenticação persistente</div>
  </div>
</body>
</html>`
}

/** Renderizar página de alteração de senha (Dark Theme alinhada ao DSH). */
export function renderChangePasswordPage(options: RenderChangePasswordOptions = {}): string {
  const errorMsg = options.error !== undefined ? escapeHtml(options.error) : undefined
  const successMsg = options.success !== undefined ? escapeHtml(options.success) : undefined
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Alterar Senha - DeepSeek Harness</title>
  <style>
    :root {
      --bg-color: #111418;
      --card-bg: #1b1f24;
      --border-color: #2b3036;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --accent-color: #4f46e5;
      --accent-hover: #4338ca;
      --error-bg: #3c1e1e;
      --error-border: #7f1d1d;
      --error-text: #f87171;
      --success-bg: #1e3a2b;
      --success-border: #15803d;
      --success-text: #4ade80;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-color);
      color: var(--text-primary);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 16px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 32px;
      width: 100%;
      max-width: 440px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 20px;
    }
    .brand-logo {
      width: 36px;
      height: 36px;
      background: var(--accent-color);
      border-radius: 8px;
      display: grid;
      place-items: center;
      font-weight: 700;
      font-size: 14px;
      color: #ffffff;
    }
    .brand-title {
      font-size: 18px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .subtitle {
      font-size: 13px;
      color: var(--text-secondary);
      margin-bottom: 20px;
    }
    .alert-error {
      background: var(--error-bg);
      border: 1px solid var(--error-border);
      color: var(--error-text);
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      margin-bottom: 16px;
    }
    .alert-success {
      background: var(--success-bg);
      border: 1px solid var(--success-border);
      color: var(--success-text);
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      margin-bottom: 16px;
    }
    .form-group {
      margin-bottom: 16px;
    }
    label {
      display: block;
      font-size: 12px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    input[type="password"] {
      width: 100%;
      padding: 10px 14px;
      background: var(--bg-color);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      color: var(--text-primary);
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s;
    }
    input[type="password"]:focus {
      border-color: var(--accent-color);
    }
    .actions {
      display: flex;
      gap: 12px;
      margin-top: 24px;
    }
    button[type="submit"] {
      flex: 1;
      padding: 12px;
      background: var(--accent-color);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.2s;
    }
    button[type="submit"]:hover {
      background: var(--accent-hover);
    }
    .btn-secondary {
      padding: 12px 16px;
      background: transparent;
      border: 1px solid var(--border-color);
      color: var(--text-primary);
      border-radius: 8px;
      font-size: 14px;
      font-weight: 500;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .btn-secondary:hover {
      background: var(--border-color);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">
      <div class="brand-logo">DSH</div>
      <div class="brand-title">Perfil e Segurança</div>
    </div>
    <div class="subtitle">Atualize sua senha de acesso ao DeepSeek Harness</div>
    ${errorMsg !== undefined ? `<div class="alert-error">${errorMsg}</div>` : ''}
    ${successMsg !== undefined ? `<div class="alert-success">${successMsg}</div>` : ''}
    <form method="POST" action="/change-password">
      <div class="form-group">
        <label for="currentPassword">Senha Atual</label>
        <input type="password" id="currentPassword" name="currentPassword" autofocus required placeholder="Sua senha atual">
      </div>
      <div class="form-group">
        <label for="newPassword">Nova Senha</label>
        <input type="password" id="newPassword" name="newPassword" required placeholder="Nova senha (mínimo 6 caracteres)">
      </div>
      <div class="form-group">
        <label for="confirmPassword">Confirmar Nova Senha</label>
        <input type="password" id="confirmPassword" name="confirmPassword" required placeholder="Digite novamente a nova senha">
      </div>
      <div class="actions">
        <a href="/" class="btn-secondary">Voltar</a>
        <button type="submit">Salvar Senha</button>
      </div>
    </form>
  </div>
</body>
</html>`
}
