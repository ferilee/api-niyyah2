import type { AuthUser } from './types.ts';

declare module 'hono' {
  interface ContextVariableMap {
    user: AuthUser;
  }
}
