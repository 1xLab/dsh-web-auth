/** HTML Page templates for dsh-web-auth. */
export interface RenderLoginOptions {
    readonly error?: string;
}
export interface RenderChangePasswordOptions {
    readonly error?: string;
    readonly success?: string;
}
/** Renderizar página de login HTML moderna (Dark Theme alinhada ao DSH). */
export declare function renderLoginPage(options?: RenderLoginOptions): string;
/** Renderizar página de alteração de senha (Dark Theme alinhada ao DSH). */
export declare function renderChangePasswordPage(options?: RenderChangePasswordOptions): string;
