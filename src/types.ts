import type { UserRole } from './db/schema.ts';

export type AuthUser = {
  id: number;
  username: string;
  role: UserRole;
};
