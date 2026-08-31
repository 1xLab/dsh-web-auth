/** Configuration for the dsh-web-auth Cordis host plugin. */
export interface Config {
    /** Password required for login. Defaults to DSH_WEB_PASSWORD environment variable or 'coder2026'. */
    readonly password?: string;
    /** Cookie Max-Age in days (default: 30 days). */
    readonly cookieMaxAgeDays?: number;
}
