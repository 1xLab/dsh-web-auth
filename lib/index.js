import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { credentialRef } from "@deepseek-ai/dsh-credentials";
//#region src/auth-crypto.ts
/** Authentication crypto utilities for dsh-web-auth. */
const AUTH_SECRET_REF = credentialRef("DSH_WEB_SESSION_SECRET");
const DAY_MILLISECONDS = 864e5;
const COOKIE_PREFIX = "dsh-auth-";
const COOKIE_PAYLOAD_VERSION = 1;
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
/** Retrieve existing signing secret or initialize a durable 32-byte secret in credentials. */
async function getOrCreateSigningSecret(credentials) {
	const existing = await credentials.resolve(AUTH_SECRET_REF);
	if (existing !== void 0 && existing.value !== "") return Buffer.from(existing.value, "utf8");
	const generated = randomBytes(32).toString("hex");
	await credentials.set(AUTH_SECRET_REF, generated);
	return Buffer.from(generated, "utf8");
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
//#endregion
//#region src/index.ts
/** 宿主插件依赖 Web 路由与凭据存储。 */
const inject = ["webServer", "credentials"];
/**
* 注册 /login、/logout 路由与 / 根路由拦截。
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
	const getExpectedPassword = () => {
		return process.env.DSH_WEB_PASSWORD ?? config.password ?? "coder2026";
	};
	const handleLoginSubmit = async (req, res) => {
		const chunks = [];
		for await (const chunk of req) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
		const bodyStr = Buffer.concat(chunks).toString("utf8");
		let password = "";
		if ((req.headers["content-type"] ?? "").includes("application/json")) try {
			password = JSON.parse(bodyStr).password ?? "";
		} catch {
			password = "";
		}
		else password = new URLSearchParams(bodyStr).get("password") ?? "";
		const expected = getExpectedPassword();
		if (password === expected && password !== "") {
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
