import type { CredentialProvider } from '@deepseek-ai/dsh-credentials';
/** Extract canonical authority (host:port) from incoming request headers. */
export declare function requestAuthority(headers: Record<string, string | string[] | undefined> | Headers): string | undefined;
/** Generate authority-bound cookie name. */
export declare function cookieName(authority: string): string;
/** Retrieve existing signing secret or initialize a durable 32-byte secret in credentials. */
export declare function getOrCreateSigningSecret(credentials: CredentialProvider): Promise<Buffer>;
/** Mint a signed dsh-auth-* cookie header valid for maxAgeDays. */
export declare function mintAuthCookie(authority: string, secret: Buffer, maxAgeDays?: number): {
    cookieHeader: string;
    name: string;
};
/** Verify incoming request headers against the signing secret. */
export declare function verifyAuthCookie(headers: Record<string, string | string[] | undefined> | Headers, secret: Buffer): boolean;
