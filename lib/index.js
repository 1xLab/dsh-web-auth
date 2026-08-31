import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { credentialRef } from "@deepseek-ai/dsh-credentials";
//#region src/auth-crypto.ts
/** Authentication crypto utilities for dsh-web-auth. */
const DSH_WEB_PASSWORD_REF = credentialRef("DSH_WEB_PASSWORD");
const AUTH_RECORD_KEY = "client-connection/browser-session";
const STORED_SECRET_VERSION = 1;
const COOKIE_PAYLOAD_VERSION = 1;
const DAY_MILLISECONDS = 864e5;
const SECRET_BYTES = 32;
const COOKIE_PREFIX = "dsh-auth-";
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;
function encodeBase64Url(value) {
	return Buffer.from(value).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
function decodeBase64Url(value) {
	if (!BASE64URL_PATTERN.test(value) || value.length % 4 === 1) return void 0;
	const padding = "=".repeat((4 - value.length % 4) % 4);
	const decoded = Buffer.from(value.replaceAll("-", "+").replaceAll("_", "/") + padding, "base64");
	return encodeBase64Url(decoded) === value ? decoded : void 0;
}
/** Extract canonical authority (host:port) from incoming request headers. */
function requestAuthority(headers) {
	let host;
	if (headers instanceof Headers) host = headers.get("host") ?? void 0;
	else {
		const raw = headers["host"] ?? headers["Host"];
		host = typeof raw === "string" ? raw : Array.isArray(raw) ? raw[0] : void 0;
	}
	if (host === void 0 || host === "") return void 0;
	try {
		return new URL(`http://${host}`).host;
	} catch {
		return;
	}
}
/** Generate authority-bound cookie name. */
function cookieName(authority) {
	return COOKIE_PREFIX + encodeBase64Url(createHash("sha256").update(authority).digest());
}
function storedSecret(record) {
	if (record === void 0) return void 0;
	if (record.kind !== "grant" || typeof record.payload !== "object" || record.payload === null || record.payload.version !== STORED_SECRET_VERSION) return;
	const raw = record.payload.secret;
	if (typeof raw !== "string") return void 0;
	const decoded = decodeBase64Url(raw);
	if (decoded === void 0 || decoded.byteLength !== SECRET_BYTES) return void 0;
	return decoded;
}
/** Retrieve custom password stored via credentials seam, if configured. */
async function readStoredPassword(credentials) {
	try {
		const res = await credentials.resolve(DSH_WEB_PASSWORD_REF);
		if (res !== void 0 && res.value !== "") return res.value;
	} catch {}
}
/** Store a updated custom access password in credentials. */
async function storeNewPassword(credentials, newPassword) {
	await credentials.set(DSH_WEB_PASSWORD_REF, newPassword);
}
/** Retrieve existing signing secret or initialize the shared 32-byte secret in credentials. */
async function getOrCreateSigningSecret(credentials) {
	const service = credentials;
	const existing = storedSecret(await service.readRecord(AUTH_RECORD_KEY));
	if (existing !== void 0) return existing;
	const generated = {
		version: STORED_SECRET_VERSION,
		secret: encodeBase64Url(randomBytes(SECRET_BYTES))
	};
	const secret = storedSecret(await service.modifyRecord(AUTH_RECORD_KEY, (current) => {
		if (current !== void 0 && storedSecret(current) !== void 0) return Promise.resolve(void 0);
		return Promise.resolve({
			kind: "grant",
			payload: generated
		});
	}));
	if (secret === void 0) throw new Error("dsh-web-auth: failed to initialize browser authentication secret");
	return secret;
}
function signature(secret, body) {
	return createHmac("sha256", secret).update(body).digest();
}
/** Mint a signed dsh-auth-* cookie header valid for maxAgeDays. */
function mintAuthCookie(authority, secret, maxAgeDays = 30) {
	const issuedAt = Date.now();
	const maxAgeMilliseconds = maxAgeDays * DAY_MILLISECONDS;
	const expiresAt = issuedAt + maxAgeMilliseconds;
	const payload = {
		version: COOKIE_PAYLOAD_VERSION,
		authority,
		issuedAt,
		expiresAt
	};
	const body = encodeBase64Url(Buffer.from(JSON.stringify(payload), "utf8"));
	const cookieValue = `v1.${body}.${encodeBase64Url(signature(secret, body))}`;
	const name = cookieName(authority);
	const maxAgeSeconds = Math.floor(maxAgeMilliseconds / 1e3);
	return {
		cookieHeader: `${name}=${cookieValue}; Max-Age=${String(maxAgeSeconds)}; Path=/; Expires=${new Date(expiresAt).toUTCString()}; HttpOnly; SameSite=Strict`,
		name
	};
}
/** Verify incoming request headers against the signing secret. */
function verifyAuthCookie(headers, secret) {
	const authority = requestAuthority(headers);
	if (authority === void 0) return false;
	const name = cookieName(authority);
	let rawCookie;
	if (headers instanceof Headers) rawCookie = headers.get("cookie") ?? void 0;
	else {
		const raw = headers["cookie"];
		rawCookie = typeof raw === "string" ? raw : Array.isArray(raw) ? raw[0] : void 0;
	}
	if (rawCookie === void 0 || rawCookie === "") return false;
	let val;
	for (const segment of rawCookie.split(";")) {
		const at = segment.indexOf("=");
		if (at === -1 || segment.slice(0, at).trim() !== name) continue;
		val = segment.slice(at + 1).trim();
		break;
	}
	if (val === void 0) return false;
	const parts = val.split(".");
	const [version, body, encodedSignature] = parts;
	if (parts.length !== 3 || version !== "v1" || body === void 0 || encodedSignature === void 0) return false;
	const actualSignature = decodeBase64Url(encodedSignature);
	if (actualSignature === void 0) return false;
	const expectedSignature = signature(secret, body);
	if (actualSignature.byteLength !== expectedSignature.byteLength || !timingSafeEqual(actualSignature, expectedSignature)) return false;
	let decoded;
	try {
		const bodyBytes = decodeBase64Url(body);
		if (bodyBytes === void 0) return false;
		decoded = JSON.parse(bodyBytes.toString("utf8"));
	} catch {
		return false;
	}
	if (typeof decoded !== "object" || decoded === null || decoded.version !== COOKIE_PAYLOAD_VERSION) return false;
	if (decoded.authority !== authority) return false;
	const issuedAt = Number(decoded.issuedAt);
	const expiresAt = Number(decoded.expiresAt);
	const now = Date.now();
	return Number.isSafeInteger(issuedAt) && Number.isSafeInteger(expiresAt) && issuedAt <= now && expiresAt > now && expiresAt > issuedAt;
}
//#endregion
//#region src/html.ts
/** Escapar entidades HTML básicas para evitar XSS. */
function escapeHtml(text) {
	return text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll("\"", "&quot;").replaceAll("'", "&#39;");
}
/** Renderizar página de login HTML moderna (Dark Theme alinhada ao DSH). */
function renderLoginPage(options = {}) {
	const errorMsg = options.error !== void 0 ? escapeHtml(options.error) : void 0;
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
    ${errorMsg !== void 0 ? `<div class="alert-error">${errorMsg}</div>` : ""}
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
</html>`;
}
/** Renderizar página de alteração de senha (Dark Theme alinhada ao DSH). */
function renderChangePasswordPage(options = {}) {
	const errorMsg = options.error !== void 0 ? escapeHtml(options.error) : void 0;
	const successMsg = options.success !== void 0 ? escapeHtml(options.success) : void 0;
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
    ${errorMsg !== void 0 ? `<div class="alert-error">${errorMsg}</div>` : ""}
    ${successMsg !== void 0 ? `<div class="alert-success">${successMsg}</div>` : ""}
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
</html>`;
}
//#endregion
//#region src/index.ts
/** 宿主插件依赖 Web 路由与凭据存储。 */
const inject = ["webServer", "credentials"];
/**
* 注册 /login、/logout、/change-password 路由与 / 根路由拦截。
*
* @param ctx - 提供 WebServer 和 Credentials 的 Context。
* @param config - 插件配置项。
*/
function apply(ctx, config = {}) {
	let signingSecret;
	const getSecret = async () => {
		if (signingSecret !== void 0) return signingSecret;
		signingSecret = await getOrCreateSigningSecret(ctx.credentials);
		return signingSecret;
	};
	const getExpectedPassword = async () => {
		const stored = await readStoredPassword(ctx.credentials);
		if (stored !== void 0 && stored !== "") return stored;
		return process.env.DSH_WEB_PASSWORD ?? config.password ?? "coder2026";
	};
	const parseRequestBody = async (req) => {
		const chunks = [];
		for await (const chunk of req) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
		const bodyStr = Buffer.concat(chunks).toString("utf8");
		if ((req.headers["content-type"] ?? "").includes("application/json")) try {
			const parsed = JSON.parse(bodyStr);
			return typeof parsed === "object" && parsed !== null ? parsed : {};
		} catch {
			return {};
		}
		const params = new URLSearchParams(bodyStr);
		const result = {};
		for (const [key, value] of params.entries()) result[key] = value;
		return result;
	};
	const handleLoginSubmit = async (req, res) => {
		const password = (await parseRequestBody(req)).password ?? "";
		if (password === await getExpectedPassword() && password !== "") {
			const secret = await getSecret();
			const { cookieHeader } = mintAuthCookie(requestAuthority(req.headers) ?? "localhost", secret, config.cookieMaxAgeDays ?? 30);
			res.writeHead(303, {
				"location": "/",
				"cache-control": "no-store",
				"set-cookie": cookieHeader
			});
			res.end();
			return;
		}
		res.writeHead(401, {
			"content-type": "text/html; charset=utf-8",
			"cache-control": "no-store"
		});
		res.end(renderLoginPage({ error: "Senha incorreta. Tente novamente." }));
	};
	ctx.effect(() => ctx.webServer.register({
		kind: "exact",
		path: "/login",
		handler: async (req, res) => {
			if (req.method === "POST") {
				await handleLoginSubmit(req, res);
				return;
			}
			if (req.method !== "GET" && req.method !== "HEAD") {
				res.writeHead(405, { allow: "GET, POST" });
				res.end();
				return;
			}
			const secret = await getSecret();
			if (verifyAuthCookie(req.headers, secret)) {
				res.writeHead(303, { location: "/" });
				res.end();
				return;
			}
			res.writeHead(200, {
				"content-type": "text/html; charset=utf-8",
				"cache-control": "no-store"
			});
			res.end(req.method === "HEAD" ? void 0 : renderLoginPage());
		}
	}), "dsh-web-auth: /login route");
	ctx.effect(() => ctx.webServer.register({
		kind: "exact",
		path: "/change-password",
		handler: async (req, res) => {
			const secret = await getSecret();
			if (!verifyAuthCookie(req.headers, secret)) {
				res.writeHead(303, { location: "/login" });
				res.end();
				return;
			}
			if (req.method === "POST") {
				const body = await parseRequestBody(req);
				const currentPassword = body.currentPassword ?? "";
				const newPassword = body.newPassword ?? "";
				const confirmPassword = body.confirmPassword ?? "";
				if (currentPassword !== await getExpectedPassword()) {
					res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
					res.end(renderChangePasswordPage({ error: "Senha atual incorreta." }));
					return;
				}
				if (newPassword.length < 6) {
					res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
					res.end(renderChangePasswordPage({ error: "A nova senha deve ter no mínimo 6 caracteres." }));
					return;
				}
				if (newPassword !== confirmPassword) {
					res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
					res.end(renderChangePasswordPage({ error: "As senhas digitadas não coincidem." }));
					return;
				}
				await storeNewPassword(ctx.credentials, newPassword);
				res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
				res.end(renderChangePasswordPage({ success: "Senha atualizada com sucesso!" }));
				return;
			}
			if (req.method !== "GET" && req.method !== "HEAD") {
				res.writeHead(405, { allow: "GET, POST" });
				res.end();
				return;
			}
			res.writeHead(200, {
				"content-type": "text/html; charset=utf-8",
				"cache-control": "no-store"
			});
			res.end(req.method === "HEAD" ? void 0 : renderChangePasswordPage());
		}
	}), "dsh-web-auth: /change-password route");
	ctx.effect(() => ctx.webServer.register({
		kind: "exact",
		path: "/api/web-auth.change-password",
		handler: async (req, res) => {
			if (req.method !== "POST") {
				res.writeHead(405, { allow: "POST" });
				res.end();
				return;
			}
			const secret = await getSecret();
			if (!verifyAuthCookie(req.headers, secret)) {
				res.writeHead(401, { "content-type": "application/json" });
				res.end(JSON.stringify({ error: "unauthorized" }));
				return;
			}
			const body = await parseRequestBody(req);
			const currentPassword = body.currentPassword ?? "";
			const newPassword = body.newPassword ?? "";
			if (currentPassword !== await getExpectedPassword()) {
				res.writeHead(400, { "content-type": "application/json" });
				res.end(JSON.stringify({ error: "Senha atual incorreta." }));
				return;
			}
			if (newPassword.length < 6) {
				res.writeHead(400, { "content-type": "application/json" });
				res.end(JSON.stringify({ error: "A nova senha deve ter no mínimo 6 caracteres." }));
				return;
			}
			await storeNewPassword(ctx.credentials, newPassword);
			res.writeHead(200, { "content-type": "application/json" });
			res.end(JSON.stringify({ ok: true }));
		}
	}), "dsh-web-auth: /api/web-auth.change-password route");
	ctx.effect(() => ctx.webServer.register({
		kind: "exact",
		path: "/logout",
		handler: (req, res) => {
			const name = cookieName(requestAuthority(req.headers) ?? "localhost");
			res.writeHead(303, {
				"location": "/login",
				"cache-control": "no-store",
				"set-cookie": `${name}=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict`
			});
			res.end();
		}
	}), "dsh-web-auth: /logout route");
	ctx.effect(() => ctx.webServer.register({
		kind: "exact",
		path: "/",
		handler: async (req, res) => {
			const url = new URL(req.url ?? "/", "http://dsh.local");
			const fallback = ctx.webServer.fallback;
			if (url.searchParams.has("token")) {
				if (fallback !== void 0) {
					await fallback(req, res);
					return;
				}
			}
			const secret = await getSecret();
			if (verifyAuthCookie(req.headers, secret)) {
				if (fallback !== void 0) {
					await fallback(req, res);
					return;
				}
				res.writeHead(404);
				res.end();
				return;
			}
			res.writeHead(303, {
				"location": "/login",
				"cache-control": "no-store"
			});
			res.end();
		}
	}), "dsh-web-auth: root unauthenticated redirect route");
}
//#endregion
export { apply, inject };
