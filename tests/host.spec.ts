import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { describe, expect, it, vi } from 'vitest'
import { cookieName, getOrCreateSigningSecret, mintAuthCookie, verifyAuthCookie, type CredentialRecord } from '../src/auth-crypto.ts'
import { renderChangePasswordPage, renderLoginPage } from '../src/html.ts'
import { apply } from '../src/index.ts'

function createFakeCredentials(): {
  records: Map<string, CredentialRecord | string>
  credentials: {
    resolve: (ref: unknown) => Promise<{ value: string; source: string } | undefined>
    set: (ref: unknown, value: string) => Promise<void>
    readRecord: (key: unknown) => Promise<CredentialRecord | undefined>
    modifyRecord: (key: unknown, mutate: (current: CredentialRecord | undefined) => Promise<CredentialRecord | undefined>) => Promise<CredentialRecord | undefined>
  }
} {
  const records = new Map<string, CredentialRecord | string>()
  return {
    records,
    credentials: {
      resolve: async (ref: unknown) => {
        const val = records.get(String(ref))
        return typeof val === 'string' ? { value: val, source: 'file' } : undefined
      },
      set: async (ref: unknown, value: string) => {
        records.set(String(ref), value)
      },
      readRecord: async (key: unknown) => {
        const val = records.get(String(key))
        return typeof val === 'object' ? val : undefined
      },
      modifyRecord: async (key: unknown, mutate) => {
        const strKey = String(key)
        const current = records.get(strKey)
        const next = await mutate(typeof current === 'object' ? current : undefined)
        if (next !== undefined) records.set(strKey, next)
        return records.get(strKey) as CredentialRecord | undefined
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

  it('renderiza o formulário de troca de senha', () => {
    const html = renderChangePasswordPage({ success: 'Senha alterada' })
    expect(html).toContain('Perfil e Segurança')
    expect(html).toContain('Senha alterada')
  })
})

describe('apply / plugin routes', () => {
  it('registra as rotas /login, /logout, /change-password e / na instância do webServer', async () => {
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
    expect(routes.has('/change-password')).toBe(true)
    expect(routes.has('/api/web-auth.change-password')).toBe(true)
    expect(routes.has('/')).toBe(true)

    // Test GET / sem autenticação -> Redireciona para /login (303)
    const reqRootUnauth = { url: '/', headers: { host: 'localhost:3080' } } as unknown as IncomingMessage
    const resRootUnauth = {
      writeHead: vi.fn(),
      end: vi.fn(),
    } as unknown as ServerResponse
    await routes.get('/')!(reqRootUnauth, resRootUnauth)
    expect(resRootUnauth.writeHead).toHaveBeenCalledWith(303, expect.objectContaining({ location: '/login' }))

    // Test GET /change-password sem autenticação -> Redireciona para /login (303)
    const reqChangeUnauth = { method: 'GET', url: '/change-password', headers: { host: 'localhost:3080' } } as unknown as IncomingMessage
    const resChangeUnauth = { writeHead: vi.fn(), end: vi.fn() } as unknown as ServerResponse
    await routes.get('/change-password')!(reqChangeUnauth, resChangeUnauth)
    expect(resChangeUnauth.writeHead).toHaveBeenCalledWith(303, expect.objectContaining({ location: '/login' }))

    // Test GET /login sem autenticação -> Exibe formulário (200)
    const reqLogin = { method: 'GET', url: '/login', headers: { host: 'localhost:3080' } } as unknown as IncomingMessage
    const resLogin = {
      writeHead: vi.fn(),
      end: vi.fn(),
    } as unknown as ServerResponse
    await routes.get('/login')!(reqLogin, resLogin)
    expect(resLogin.writeHead).toHaveBeenCalledWith(200, expect.anything())

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

    const authCookie = setCookieHeader!.split(';', 1)[0]!

    // Test POST /change-password autenticado alterando para nova senha 'new-secret-999'
    const reqChangeSubmit = {
      method: 'POST',
      url: '/change-password',
      headers: { host: 'localhost:3080', cookie: authCookie, 'content-type': 'application/x-www-form-urlencoded' },
      [Symbol.asyncIterator]: async function* () {
        yield Buffer.from('currentPassword=test-password-123&newPassword=new-secret-999&confirmPassword=new-secret-999')
      },
    } as unknown as IncomingMessage
    const resChangeSubmit = { writeHead: vi.fn(), end: vi.fn() } as unknown as ServerResponse
    await routes.get('/change-password')!(reqChangeSubmit, resChangeSubmit)
    expect(resChangeSubmit.writeHead).toHaveBeenCalledWith(200, expect.anything())

    // Test POST /login com a NOVA senha 'new-secret-999' -> Sucesso
    const reqLoginNew = {
      method: 'POST',
      url: '/login',
      headers: { host: 'localhost:3080', 'content-type': 'application/x-www-form-urlencoded' },
      [Symbol.asyncIterator]: async function* () {
        yield Buffer.from('password=new-secret-999')
      },
    } as unknown as IncomingMessage
    const resLoginNew = { writeHead: vi.fn(), end: vi.fn() } as unknown as ServerResponse
    await routes.get('/login')!(reqLoginNew, resLoginNew)
    expect(resLoginNew.writeHead).toHaveBeenCalledWith(303, expect.objectContaining({ location: '/' }))
  })
})
