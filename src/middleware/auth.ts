import { createMiddleware } from "hono/factory";
import { verify } from "hono/jwt";
import type { AuthUser } from "../types.ts";
import { env } from "../utils/env.ts";
import { users, type UserRole } from "../db/schema.ts";
import { db } from "../db/client.ts";
import { and, eq } from "drizzle-orm";

export const requireAuth = createMiddleware(async (c, next) => {
  const authHeader = c.req.header("authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return c.json({ message: "Unauthorized" }, 401);
  }

  const token = authHeader.slice(7);

  try {
    const payload = await verify(token, env.jwtSecret, "HS256");
    const userId = Number(payload.sub);
    const [dbUser] = await db
      .select({
        id: users.id,
        username: users.username,
        role: users.role,
      })
      .from(users)
      .where(and(eq(users.id, userId), eq(users.isActive, true)))
      .limit(1);

    if (!dbUser) {
      return c.json({ message: "Unauthorized" }, 401);
    }

    const user: AuthUser = {
      id: dbUser.id,
      username: dbUser.username,
      role: dbUser.role as UserRole,
    };

    c.set("user", user);
    await next();
  } catch {
    return c.json({ message: "Invalid token" }, 401);
  }
});

export function requireRole(...roles: UserRole[]) {
  return createMiddleware(async (c, next) => {
    const user = c.get("user") as AuthUser | undefined;
    if (!user) {
      return c.json({ message: "Unauthorized" }, 401);
    }

    if (!roles.includes(user.role)) {
      return c.json({ message: "Forbidden" }, 403);
    }

    await next();
  });
}
