/**
 * DSH Web Auth 宿主端。
 *
 * 插件提供 password 登录界面 (/login) 和 GET / 未登录自动重定向。
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
  requestAuthority,
  verifyAuthCookie,
} from './auth-crypto.ts'
import { renderLoginPage } from './html.ts'
import type { Config } from './types.ts'

export type * from './types.ts'

/** 宿主插件依赖 Web 路由与凭据存储。 */
export const inject = ['webServer', 'credentials']

interface WebServerWithFallback {
  fallback?: (req: IncomingMessage, res: ServerResponse) => Promise<void>
}

/**
 * 注册 /login、/logout 路由与 / 根路由拦截。
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

  const getExpectedPassword = (): string => {
    return process.env.DSH_WEB_PASSWORD ?? config.password ?? 'coder2026'
  }

  const handleLoginSubmit = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const chunks: Buffer[] = []
    for await (const chunk of req) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer))
    }
    const bodyStr = Buffer.concat(chunks).toString('utf8')
    let password = ''
    const contentType = req.headers['content-type'] ?? ''

    if (contentType.includes('application/json')) {
      try {
        const parsed = JSON.parse(bodyStr) as { password?: string }
        password = parsed.password ?? ''
      } catch {
        password = ''
      }
    } else {
      const params = new URLSearchParams(bodyStr)
      password = params.get('password') ?? ''
    }

    const expected = getExpectedPassword()
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
