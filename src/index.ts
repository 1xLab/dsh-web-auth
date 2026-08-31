/**
 * DSH Web Auth 宿主端。
 *
 * 插件提供 password 登录界面 (/login)、密码修改界面 (/change-password)
 * 以及 GET / 未登录自动重定向。
 * 验证成功后使用 credentials 秘钥签署 DSH 原生的 dsh-auth-* cookie。
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-credentials'
import type {} from '@deepseek-ai/dsh-host-webserver'
import {
  cookieName,
  getOrCreateSigningSecret,
  mintAuthCookie,
  readStoredPassword,
  requestAuthority,
  storeNewPassword,
  verifyAuthCookie,
} from './auth-crypto.ts'
import { renderChangePasswordPage, renderLoginPage } from './html.ts'
import type { Config } from './types.ts'

export type * from './types.ts'

/** 宿主插件依赖 Web 路由与凭据存储。 */
export const inject = ['webServer', 'credentials']

interface WebServerWithFallback {
  fallback?: (req: IncomingMessage, res: ServerResponse) => Promise<void>
}

/**
 * 注册 /login、/logout、/change-password 路由与 / 根路由拦截。
 *
 * @param ctx - 提供 WebServer 和 Credentials 的 Context。
 * @param config - 插件配置项。
 */
export function apply(ctx: Context, config: Config = {}): void {
  let signingSecret: Buffer | undefined

  const getSecret = async (): Promise<Buffer> => {
    if (signingSecret !== undefined) return signingSecret
    signingSecret = await getOrCreateSigningSecret(ctx.credentials)
    return signingSecret
  }

  const getExpectedPassword = async (): Promise<string> => {
    const stored = await readStoredPassword(ctx.credentials)
    if (stored !== undefined && stored !== '') return stored
    return process.env.DSH_WEB_PASSWORD ?? config.password ?? 'coder2026'
  }

  const parseRequestBody = async (req: IncomingMessage): Promise<Record<string, string>> => {
    const chunks: Buffer[] = []
    for await (const chunk of req) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer))
    }
    const bodyStr = Buffer.concat(chunks).toString('utf8')
    const contentType = req.headers['content-type'] ?? ''

    if (contentType.includes('application/json')) {
      try {
        const parsed = JSON.parse(bodyStr) as Record<string, string>
        return typeof parsed === 'object' && parsed !== null ? parsed : {}
      } catch {
        return {}
      }
    }
    const params = new URLSearchParams(bodyStr)
    const result: Record<string, string> = {}
    for (const [key, value] of params.entries()) {
      result[key] = value
    }
    return result
  }

  const handleLoginSubmit = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const body = await parseRequestBody(req)
    const password = body.password ?? ''

    const expected = await getExpectedPassword()
    if (password === expected && password !== '') {
      const secret = await getSecret()
      const authority = requestAuthority(req.headers) ?? 'localhost'
      const { cookieHeader } = mintAuthCookie(authority, secret, config.cookieMaxAgeDays ?? 30)
      res.writeHead(303, {
        'location': '/',
        'cache-control': 'no-store',
        'set-cookie': cookieHeader,
      })
      res.end()
      return
    }

    res.writeHead(401, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    })
    res.end(renderLoginPage({ error: 'Senha incorreta. Tente novamente.' }))
  }

  // Rota /login (GET exibe formulário, POST autentica)
  ctx.effect(
    () => ctx.webServer.register({
      kind: 'exact',
      path: '/login',
      handler: async (req: IncomingMessage, res: ServerResponse) => {
        if (req.method === 'POST') {
          await handleLoginSubmit(req, res)
          return
        }
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          res.writeHead(405, { allow: 'GET, POST' })
          res.end()
          return
        }
        const secret = await getSecret()
        if (verifyAuthCookie(req.headers, secret)) {
          res.writeHead(303, { location: '/' })
          res.end()
          return
        }
        res.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
        })
        res.end(req.method === 'HEAD' ? undefined : renderLoginPage())
      },
    }),
    'dsh-web-auth: /login route',
  )

  // Rota /change-password (GET exibe formulário de perfil, POST atualiza a senha)
  ctx.effect(
    () => ctx.webServer.register({
      kind: 'exact',
      path: '/change-password',
      handler: async (req: IncomingMessage, res: ServerResponse) => {
        const secret = await getSecret()
        if (!verifyAuthCookie(req.headers, secret)) {
          res.writeHead(303, { location: '/login' })
          res.end()
          return
        }

        if (req.method === 'POST') {
          const body = await parseRequestBody(req)
          const currentPassword = body.currentPassword ?? ''
          const newPassword = body.newPassword ?? ''
          const confirmPassword = body.confirmPassword ?? ''

          const expected = await getExpectedPassword()
          if (currentPassword !== expected) {
            res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' })
            res.end(renderChangePasswordPage({ error: 'Senha atual incorreta.' }))
            return
          }

          if (newPassword.length < 6) {
            res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' })
            res.end(renderChangePasswordPage({ error: 'A nova senha deve ter no mínimo 6 caracteres.' }))
            return
          }

          if (newPassword !== confirmPassword) {
            res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' })
            res.end(renderChangePasswordPage({ error: 'As senhas digitadas não coincidem.' }))
            return
          }

          await storeNewPassword(ctx.credentials, newPassword)
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
          res.end(renderChangePasswordPage({ success: 'Senha atualizada com sucesso!' }))
          return
        }

        if (req.method !== 'GET' && req.method !== 'HEAD') {
          res.writeHead(405, { allow: 'GET, POST' })
          res.end()
          return
        }

        res.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
        })
        res.end(req.method === 'HEAD' ? undefined : renderChangePasswordPage())
      },
    }),
    'dsh-web-auth: /change-password route',
  )

  // API Rota /api/web-auth.change-password (JSON API)
  ctx.effect(
    () => ctx.webServer.register({
      kind: 'exact',
      path: '/api/web-auth.change-password',
      handler: async (req: IncomingMessage, res: ServerResponse) => {
        if (req.method !== 'POST') {
          res.writeHead(405, { allow: 'POST' })
          res.end()
          return
        }
        const secret = await getSecret()
        if (!verifyAuthCookie(req.headers, secret)) {
          res.writeHead(401, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'unauthorized' }))
          return
        }

        const body = await parseRequestBody(req)
        const currentPassword = body.currentPassword ?? ''
        const newPassword = body.newPassword ?? ''

        const expected = await getExpectedPassword()
        if (currentPassword !== expected) {
          res.writeHead(400, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'Senha atual incorreta.' }))
          return
        }

        if (newPassword.length < 6) {
          res.writeHead(400, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'A nova senha deve ter no mínimo 6 caracteres.' }))
          return
        }

        await storeNewPassword(ctx.credentials, newPassword)
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: true }))
      },
    }),
    'dsh-web-auth: /api/web-auth.change-password route',
  )

  // Rota /logout (Limpa o cookie e redireciona para /login)
  ctx.effect(
    () => ctx.webServer.register({
      kind: 'exact',
      path: '/logout',
      handler: (req: IncomingMessage, res: ServerResponse) => {
        const authority = requestAuthority(req.headers) ?? 'localhost'
        const name = cookieName(authority)
        res.writeHead(303, {
          'location': '/login',
          'cache-control': 'no-store',
          'set-cookie': `${name}=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict`,
        })
        res.end()
      },
    }),
    'dsh-web-auth: /logout route',
  )

  // Interceptador para a raiz /
  ctx.effect(
    () => ctx.webServer.register({
      kind: 'exact',
      path: '/',
      handler: async (req: IncomingMessage, res: ServerResponse) => {
        const url = new URL(req.url ?? '/', 'http://dsh.local')
        const fallback = (ctx.webServer as unknown as WebServerWithFallback).fallback

        // Se contiver ?token= (link de inicialização do DSH), passa para o fallback/DSH
        if (url.searchParams.has('token')) {
          if (fallback !== undefined) {
            await fallback(req, res)
            return
          }
        }

        const secret = await getSecret()
        if (verifyAuthCookie(req.headers, secret)) {
          // Autenticado: repassa para o fallback (frontend-static serve index.html)
          if (fallback !== undefined) {
            await fallback(req, res)
            return
          }
          res.writeHead(404)
          res.end()
          return
        }

        // Não autenticado em / -> redireciona para /login
        res.writeHead(303, { 'location': '/login', 'cache-control': 'no-store' })
        res.end()
      },
    }),
    'dsh-web-auth: root unauthenticated redirect route',
  )
}
