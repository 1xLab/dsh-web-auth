/** HTML Login Page template for dsh-web-auth. */
export interface RenderLoginOptions {
    readonly error?: string;
}
/** Renderizar página de login HTML moderna (Dark Theme alinhada ao DSH). */
export declare function renderLoginPage(options?: RenderLoginOptions): string;
