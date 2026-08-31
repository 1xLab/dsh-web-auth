/** Authentication crypto utilities for dsh-web-auth. */
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { CredentialProvider } from '@deepseek-ai/dsh-credentials'

const AUTH_RECORD_KEY = 'client-connection/browser-session'
const STORED_SECRET_VERSION = 1
const COOKIE_PAYLOAD_VERSION = 1
const DAY_MILLISECONDS = 24 * 60 * 60 * 1000
const SECRET_BYTES = 32
const COOKIE_PREFIX = 'dsh-auth-'
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/

export interface CredentialRecord {
  readonly kind: string
  readonly payload: unknown
}

interface BrowserCookiePayload {
  readonly version: typeof COOKIE_PAYLOAD_VERSION
  readonly authority: string
  readonly issuedAt: number
  readonly expiresAt: number
}

interface CredentialServiceWithRecords {
  readRecord(key: string): Promise<CredentialRecord | undefined>
  modifyRecord(
    key: string,
    mutate: (current: CredentialRecord | undefined) => Promise<CredentialRecord | undefined>,
  ): Promise<CredentialRecord | undefined>
}

function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '')
}

function decodeBase64Url(value: string): Buffer | undefined {
  if (!BASE64URL_PATTERN.test(value) || value.length % 4 === 1) return undefined
  const padding = '='.repeat((4 - value.length % 4) % 4)
  const decoded = Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/') + padding, 'base64')
  return encodeBase64Url(decoded) === value ? decoded : undefined
}

/** Extract canonical authority (host:port) from incoming request headers. */
export function requestAuthority(headers: Record<string, string | string[] | undefined> | Headers): string | undefined {
  let host: string | undefined
  if (headers instanceof Headers) {
    host = headers.get('host') ?? undefined
  } else {
    const raw = headers['host'] ?? (headers as Record<string, string | undefined>)['Host']
    host = typeof raw === 'string' ? raw : Array.isArray(raw) ? raw[0] : undefined
  }
  if (host === undefined || host === '') return undefined
  try {
    return new URL(`http://${host}`).host
  } catch {
    return undefined
  }
}

/** Generate authority-bound cookie name. */
export function cookieName(authority: string): string {
  return COOKIE_PREFIX + encodeBase64Url(createHash('sha256').update(authority).digest())
}

function storedSecret(record: CredentialRecord | undefined): Buffer | undefined {
  if (record === undefined) return undefined
  if (record.kind !== 'grant' || typeof record.payload !== 'object' || record.payload === null
    || (record.payload as Record<string, unknown>).version !== STORED_SECRET_VERSION) {
    return undefined
  }
  const raw = (record.payload as Record<string, unknown>).secret
  if (typeof raw !== 'string') return undefined
  const decoded = decodeBase64Url(raw)
  if (decoded === undefined || decoded.byteLength !== SECRET_BYTES) return undefined
  return decoded
}

/** Retrieve existing signing secret or initialize the shared 32-byte secret in credentials. */
export async function getOrCreateSigningSecret(credentials: CredentialProvider): Promise<Buffer> {
  const service = credentials as unknown as CredentialServiceWithRecords
  const existingRecord = await service.readRecord(AUTH_RECORD_KEY)
  const existing = storedSecret(existingRecord)
  if (existing !== undefined) return existing

  const generated = {
    version: STORED_SECRET_VERSION,
    secret: encodeBase64Url(randomBytes(SECRET_BYTES)),
  }

  const updatedRecord = await service.modifyRecord(AUTH_RECORD_KEY, (current) => {
    if (current !== undefined && storedSecret(current) !== undefined) {
      return Promise.resolve(undefined)
    }
    return Promise.resolve({ kind: 'grant', payload: generated })
  })

  const secret = storedSecret(updatedRecord)
  if (secret === undefined) {
    throw new Error('dsh-web-auth: failed to initialize browser authentication secret')
  }
  return secret
}

function signature(secret: Buffer, body: string): Buffer {
  return createHmac('sha256', secret).update(body).digest()
}

/** Mint a signed dsh-auth-* cookie header valid for maxAgeDays. */
export function mintAuthCookie(authority: string, secret: Buffer, maxAgeDays = 30): { cookieHeader: string; name: string } {
  const issuedAt = Date.now()
  const maxAgeMilliseconds = maxAgeDays * DAY_MILLISECONDS
  const expiresAt = issuedAt + maxAgeMilliseconds
  const payload: BrowserCookiePayload = {
    version: COOKIE_PAYLOAD_VERSION,
    authority,
    issuedAt,
    expiresAt,
  }
  const body = encodeBase64Url(Buffer.from(JSON.stringify(payload), 'utf8'))
  const sig = encodeBase64Url(signature(secret, body))
  const cookieValue = `v1.${body}.${sig}`
  const name = cookieName(authority)
  const maxAgeSeconds = Math.floor(maxAgeMilliseconds / 1000)
  const cookieHeader = `${name}=${cookieValue}; Max-Age=${String(maxAgeSeconds)}; Path=/; Expires=${new Date(expiresAt).toUTCString()}; HttpOnly; SameSite=Strict`
  return { cookieHeader, name }
}

/** Verify incoming request headers against the signing secret. */
export function verifyAuthCookie(headers: Record<string, string | string[] | undefined> | Headers, secret: Buffer): boolean {
  const authority = requestAuthority(headers)
  if (authority === undefined) return false
  const name = cookieName(authority)

  let rawCookie: string | undefined
  if (headers instanceof Headers) {
    rawCookie = headers.get('cookie') ?? undefined
  } else {
    const raw = headers['cookie']
    rawCookie = typeof raw === 'string' ? raw : Array.isArray(raw) ? raw[0] : undefined
  }
  if (rawCookie === undefined || rawCookie === '') return false

  let val: string | undefined
  for (const segment of rawCookie.split(';')) {
    const at = segment.indexOf('=')
    if (at === -1 || segment.slice(0, at).trim() !== name) continue
    val = segment.slice(at + 1).trim()
    break
  }
  if (val === undefined) return false

  const parts = val.split('.')
  const [version, body, encodedSignature] = parts
  if (parts.length !== 3 || version !== 'v1' || body === undefined || encodedSignature === undefined) return false

  const actualSignature = decodeBase64Url(encodedSignature)
  if (actualSignature === undefined) return false
  const expectedSignature = signature(secret, body)
  if (actualSignature.byteLength !== expectedSignature.byteLength || !timingSafeEqual(actualSignature, expectedSignature)) {
    return false
  }

  let decoded: Record<string, unknown>
  try {
    const bodyBytes = decodeBase64Url(body)
    if (bodyBytes === undefined) return false
    decoded = JSON.parse(bodyBytes.toString('utf8')) as Record<string, unknown>
  } catch {
    return false
  }

  if (typeof decoded !== 'object' || decoded === null || decoded.version !== COOKIE_PAYLOAD_VERSION) return false
  if (decoded.authority !== authority) return false

  const issuedAt = Number(decoded.issuedAt)
  const expiresAt = Number(decoded.expiresAt)
  const now = Date.now()
  return (
    Number.isSafeInteger(issuedAt) &&
    Number.isSafeInteger(expiresAt) &&
    issuedAt <= now &&
    expiresAt > now &&
    expiresAt > issuedAt
  )
}
