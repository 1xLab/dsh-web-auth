import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { describe, expect, it, vi } from 'vitest'
import { cookieName, getOrCreateSigningSecret, mintAuthCookie, verifyAuthCookie, type CredentialRecord } from '../src/auth-crypto.ts'
import { renderLoginPage } from '../src/html.ts'
import { apply } from '../src/index.ts'

function createFakeCredentials(): {
  records: Map<string, CredentialRecord>
  credentials: {
    readRecord: (key: unknown) => Promise<CredentialRecord | undefined>
    modifyRecord: (key: unknown, mutate: (current: CredentialRecord | undefined) => Promise<CredentialRecord | undefined>) => Promise<CredentialRecord | undefined>
  }
} {
  const records = new Map<string, CredentialRecord>()
  return {
    records,
    credentials: {
      readRecord: async (key: unknown) => records.get(String(key)),
      modifyRecord: async (key: unknown, mutate) => {
        const strKey = String(key)
        const current = records.get(strKey)
        const next = await mutate(current)
        if (next !== undefined) records.set(strKey, next)
        return records.get(strKey)
      },
    },
  }
}

describe('auth-crypto', () => {
  it('cria e verifica um cookie de autenticação assinado por HMAC', async () => {
    const { credentials } = createFakeCredentials()
    const secret = await getOrCreateSigningSecret(credentials as never)

    const authority = 'example.com:443'
    const { cookieHeader, name } = mintAuthCookie(authority, secret, 30)

    expect(name).toBe(cookieName(authority))
    expect(cookieHeader).toContain(name)
    expect(cookieHeader).toContain('Max-Age=2592000')

    const cookieValue = cookieHeader.split(';', 1)[0]!
    const validRequest = { headers: { host: authority, cookie: cookieValue } }
    expect(verifyAuthCookie(validRequest.headers, secret)).toBe(true)

    const invalidRequest = { headers: { host: authority, cookie: `${name}=broken.cookie` } }
    expect(verifyAuthCookie(invalidRequest.headers, secret)).toBe(false)

    const wrongHostRequest = { headers: { host: 'other.com', cookie: cookieValue } }
    expect(verifyAuthCookie(wrongHostRequest.headers, secret)).toBe(false)
  })
})

describe('html renderer', () => {
  it('renderiza o formulário de login e escapa HTML de erro', () => {
    const html = renderLoginPage({ error: '<script>alert(1)</script>' })
    expect(html).toContain('DeepSeek Harness')
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
    expect(html).not.toContain('<script>alert(1)</script>')
  })
})

describe('apply / plugin routes', () => {
  it('registra as rotas /login, /logout e / na instância do webServer', async () => {
    const routes = new Map<string, (req: IncomingMessage, res: ServerResponse) => Promise<void>>()
    const fallback = vi.fn(async (_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(200)
      res.end('index.html')
    })

    const { credentials } = createFakeCredentials()
    const ctx = {
      credentials,
      webServer: {
        fallback,
        register: vi.fn((route: { path: string; handler: (req: IncomingMessage, res: ServerResponse) => Promise<void> }) => {
          routes.set(route.path, route.handler)
          return () => { routes.delete(route.path) }
        }),
      },
      effect: (fn: () => () => void) => fn(),
    } as unknown as Context

    apply(ctx, { password: 'test-password-123' })

    expect(routes.has('/login')).toBe(true)
    expect(routes.has('/logout')).toBe(true)
    expect(routes.has('/')).toBe(true)

    // Test GET / sem autenticação -> Redireciona para /login (303)
    const reqRootUnauth = { url: '/', headers: { host: 'localhost:3080' } } as unknown as IncomingMessage
    const resRootUnauth = {
      writeHead: vi.fn(),
      end: vi.fn(),
    } as unknown as ServerResponse
    await routes.get('/')!(reqRootUnauth, resRootUnauth)
    expect(resRootUnauth.writeHead).toHaveBeenCalledWith(303, expect.objectContaining({ location: '/login' }))

    // Test GET /login sem autenticação -> Exibe formulário (200)
    const reqLogin = { method: 'GET', url: '/login', headers: { host: 'localhost:3080' } } as unknown as IncomingMessage
    const resLogin = {
      writeHead: vi.fn(),
      end: vi.fn(),
    } as unknown as ServerResponse
    await routes.get('/login')!(reqLogin, resLogin)
    expect(resLogin.writeHead).toHaveBeenCalledWith(200, expect.anything())

    // Test POST /login com senha errada -> Retorna 401
    const reqSubmitWrong = {
      method: 'POST',
      url: '/login',
      headers: { host: 'localhost:3080', 'content-type': 'application/x-www-form-urlencoded' },
      [Symbol.asyncIterator]: async function* () {
        yield Buffer.from('password=wrong')
      },
    } as unknown as IncomingMessage
    const resSubmitWrong = {
      writeHead: vi.fn(),
      end: vi.fn(),
    } as unknown as ServerResponse
    await routes.get('/login')!(reqSubmitWrong, resSubmitWrong)
    expect(resSubmitWrong.writeHead).toHaveBeenCalledWith(401, expect.anything())

    // Test POST /login com senha correta -> Retorna 303 e grava Cookie
    const reqSubmitOk = {
      method: 'POST',
      url: '/login',
      headers: { host: 'localhost:3080', 'content-type': 'application/x-www-form-urlencoded' },
      [Symbol.asyncIterator]: async function* () {
        yield Buffer.from('password=test-password-123')
      },
    } as unknown as IncomingMessage
    let setCookieHeader: string | undefined
    const resSubmitOk = {
      writeHead: vi.fn((_status: number, headers: Record<string, string>) => {
        setCookieHeader = headers['set-cookie']
      }),
      end: vi.fn(),
    } as unknown as ServerResponse
    await routes.get('/login')!(reqSubmitOk, resSubmitOk)
    expect(resSubmitOk.writeHead).toHaveBeenCalledWith(303, expect.objectContaining({ location: '/' }))
    expect(setCookieHeader).toBeDefined()

    // Test GET / com Cookie autenticado -> Chama o fallback para servir index.html
    const reqRootAuth = {
      url: '/',
      headers: { host: 'localhost:3080', cookie: setCookieHeader!.split(';', 1)[0]! },
    } as unknown as IncomingMessage
    const resRootAuth = { writeHead: vi.fn(), end: vi.fn() } as unknown as ServerResponse
    await routes.get('/')!(reqRootAuth, resRootAuth)
    expect(fallback).toHaveBeenCalledWith(reqRootAuth, resRootAuth)

    // Test GET /logout -> Limpa cookie e redireciona para /login
    const reqLogout = { headers: { host: 'localhost:3080' } } as unknown as IncomingMessage
    let logoutCookie: string | undefined
    const resLogout = {
      writeHead: vi.fn((_status: number, headers: Record<string, string>) => {
        logoutCookie = headers['set-cookie']
      }),
      end: vi.fn(),
    } as unknown as ServerResponse
    await routes.get('/logout')!(reqLogout, resLogout)
    expect(resLogout.writeHead).toHaveBeenCalledWith(303, expect.objectContaining({ location: '/login' }))
    expect(logoutCookie).toContain('Max-Age=0')
  })
})
