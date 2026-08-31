import type { Context } from '@deepseek-ai/cordis';
import type { Config } from './types.ts';
export type * from './types.ts';
/** 宿主插件依赖 Web 路由与凭据存储。 */
export declare const inject: string[];
/**
 * 注册 /login、/logout 路由与 / 根路由拦截。
 *
 * @param ctx - 提供 WebServer 和 Credentials 的 Context。
 * @param config - 插件配置项。
 */
export declare function apply(ctx: Context, config?: Config): void;
