import { Hono } from "hono";
import { sign } from "hono/jwt";
import { and, desc, eq, isNull } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db/client.ts";
import { authOtps, users } from "../db/schema.ts";
import { env } from "../utils/env.ts";
import { clearExpiredOtps } from "../db/init.ts";
import { sendOtpEmail } from "../utils/mailer.ts";
import { generateOtpCode, otpExpiryDate } from "../utils/otp.ts";

const loginSchema = z.object({
  username: z.string().min(3),
  password: z.string().min(6),
});

const otpRequestSchema = z.object({
  email: z.string().email(),
});

const otpVerifySchema = z.object({
  email: z.string().email(),
  code: z.string().regex(/^\d{6}$/),
});

type AuthUser = {
  id: number;
  name: string;
  username: string;
  role: "siswa" | "guru" | "admin" | "support" | "editor";
  email: string | null;
  isActive: boolean;
};

export const authRoutes = new Hono();

authRoutes.post("/login", async (c) => {
  const json = await c.req.json().catch(() => null);
  const parsed = loginSchema.safeParse(json);

  if (!parsed.success) {
    return c.json(
      { message: "Payload tidak valid", errors: parsed.error.flatten() },
      400,
    );
  }

  const username = parsed.data.username.trim();

  const user = await findUserByUsername(username);
  if (!user) {
    return c.json({ message: "Username atau password salah" }, 401);
  }

  if (user.role !== "admin") {
    return c.json(
      { message: "Siswa dan guru login menggunakan OTP email." },
      403,
    );
  }

  if (!user.isActive) {
    return c.json({ message: "Akun admin tidak aktif" }, 403);
  }

  const [authUser] = await db
    .select({
      id: users.id,
      name: users.name,
      username: users.username,
      role: users.role,
      className: users.className,
      points: users.points,
      isActive: users.isActive,
      email: users.email,
      passwordHash: users.passwordHash,
    })
    .from(users)
    .where(eq(users.id, user.id))
    .limit(1);

  if (!authUser) {
    return c.json({ message: "Username atau password salah" }, 401);
  }

  const validPassword = await Bun.password.verify(
    parsed.data.password,
    authUser.passwordHash,
  );

  if (!validPassword) {
    return c.json({ message: "Username atau password salah" }, 401);
  }

  const token = await buildAccessToken(authUser.id, authUser.username, authUser.role);

  return c.json({
    token,
    user: {
      id: authUser.id,
      name: authUser.name,
      username: authUser.username,
      role: authUser.role,
      className: authUser.className,
      points: authUser.points,
      email: authUser.email,
    },
  });
});

authRoutes.post("/otp/request", async (c) => {
  const json = await c.req.json().catch(() => null);
  const parsed = otpRequestSchema.safeParse(json);

  if (!parsed.success) {
    return c.json(
      { message: "Payload tidak valid", errors: parsed.error.flatten() },
      400,
    );
  }

  await clearExpiredOtps();

  const normalizedEmail = parsed.data.email.trim().toLowerCase();

  let user = await findUserByEmail(normalizedEmail);
  if (!user) {
    user = await createAutoStudentUser(normalizedEmail);
  }

  // User nonaktif tetap tidak bisa login via OTP.
  if (!user.isActive) {
    return c.json({
      message: "Jika email terdaftar, OTP akan dikirim.",
    });
  }

  if (user.role === "admin") {
    return c.json(
      { message: "Admin harus login menggunakan username dan password." },
      403,
    );
  }

  await db
    .update(authOtps)
    .set({ consumedAt: new Date() })
    .where(and(eq(authOtps.userId, user.id), isNull(authOtps.consumedAt)));

  const debugFixedCode = process.env.OTP_DEBUG_FIXED_CODE?.trim();
  const otpCode =
    debugFixedCode && debugFixedCode.length > 0
      ? debugFixedCode
      : generateOtpCode(6);
  const codeHash = await Bun.password.hash(otpCode);

  const [createdOtp] = await db
    .insert(authOtps)
    .values({
      userId: user.id,
      email: normalizedEmail,
      codeHash,
      expiresAt: otpExpiryDate(env.otpExpiresMinutes),
      attempts: 0,
      consumedAt: null,
    })
    .returning({ id: authOtps.id });

  let sendResult: { provider: "resend" | "nodemailer" | "mock" };
  try {
    sendResult = await sendOtpEmail({
      to: normalizedEmail,
      code: otpCode,
      studentName: user.name,
    });
  } catch (error) {
    await db
      .update(authOtps)
      .set({ consumedAt: new Date() })
      .where(eq(authOtps.id, createdOtp.id));
    return c.json(
      {
        message: "Gagal mengirim OTP email",
        detail: error instanceof Error ? error.message : "Unknown error",
      },
      500,
    );
  }

  const response: Record<string, unknown> = {
    message: "Jika email terdaftar, OTP akan dikirim.",
    provider: sendResult.provider,
  };

  if (process.env.OTP_DEBUG_RETURN_CODE === "true") {
    response.debugCode = otpCode;
  }

  return c.json(response);
});

authRoutes.post("/otp/verify", async (c) => {
  const json = await c.req.json().catch(() => null);
  const parsed = otpVerifySchema.safeParse(json);

  if (!parsed.success) {
    return c.json(
      { message: "Payload tidak valid", errors: parsed.error.flatten() },
      400,
    );
  }

  await clearExpiredOtps();

  const normalizedEmail = parsed.data.email.trim().toLowerCase();

  const [user] = await db
    .select({
      id: users.id,
      name: users.name,
      username: users.username,
      role: users.role,
      className: users.className,
      points: users.points,
      isActive: users.isActive,
      email: users.email,
    })
    .from(users)
    .where(and(eq(users.email, normalizedEmail), eq(users.isActive, true)))
    .limit(1);

  if (!user) {
    return c.json({ message: "OTP tidak valid atau sudah kedaluwarsa" }, 401);
  }

  if (user.role === "admin") {
    return c.json(
      { message: "Admin harus login menggunakan username dan password." },
      403,
    );
  }

  const [otp] = await db
    .select({
      id: authOtps.id,
      codeHash: authOtps.codeHash,
      attempts: authOtps.attempts,
      expiresAt: authOtps.expiresAt,
    })
    .from(authOtps)
    .where(
      and(
        eq(authOtps.userId, user.id),
        eq(authOtps.email, normalizedEmail),
        isNull(authOtps.consumedAt),
      ),
    )
    .orderBy(desc(authOtps.id))
    .limit(1);

  if (!otp || otp.expiresAt.getTime() < Date.now()) {
    return c.json({ message: "OTP tidak valid atau sudah kedaluwarsa" }, 401);
  }

  const isValidCode = await Bun.password.verify(parsed.data.code, otp.codeHash);
  if (!isValidCode) {
    const nextAttempts = otp.attempts + 1;
    await db
      .update(authOtps)
      .set({
        attempts: nextAttempts,
        ...(nextAttempts >= env.otpMaxAttempts
          ? { consumedAt: new Date() }
          : {}),
      })
      .where(eq(authOtps.id, otp.id));

    return c.json({ message: "OTP tidak valid atau sudah kedaluwarsa" }, 401);
  }

  await db
    .update(authOtps)
    .set({ consumedAt: new Date() })
    .where(eq(authOtps.id, otp.id));

  const token = await buildAccessToken(user.id, user.username, user.role);

  return c.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      username: user.username,
      role: user.role,
      className: user.className,
      points: user.points,
      email: user.email,
    },
  });
});

async function buildAccessToken(
  userId: number,
  username: string,
  role: "siswa" | "guru" | "admin" | "support" | "editor",
) {
  return sign(
    {
      sub: String(userId),
      username,
      role,
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 12,
    },
    env.jwtSecret,
  );
}

async function findUserByUsername(username: string): Promise<AuthUser | null> {
  const normalizedUsername = username.trim().toLowerCase();

  const [user] = await db
    .select({
      id: users.id,
      name: users.name,
      username: users.username,
      role: users.role,
      email: users.email,
      isActive: users.isActive,
    })
    .from(users)
    .where(eq(users.username, normalizedUsername))
    .limit(1);

  return user ?? null;
}

async function findUserByEmail(email: string): Promise<AuthUser | null> {
  const [user] = await db
    .select({
      id: users.id,
      name: users.name,
      username: users.username,
      role: users.role,
      email: users.email,
      isActive: users.isActive,
    })
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  return user ?? null;
}

async function createAutoStudentUser(email: string): Promise<AuthUser> {
  const baseUsername = buildUsernameBaseFromEmail(email);
  const username = await generateUniqueUsername(baseUsername);
  const passwordHash = await Bun.password.hash(crypto.randomUUID());

  try {
    const [createdUser] = await db
      .insert(users)
      .values({
        name: buildDisplayNameFromEmail(email),
        username,
        email,
        schoolNpsn: null,
        passwordHash,
        role: "siswa",
        className: null,
        isActive: true,
        points: 0,
      })
      .returning({
        id: users.id,
        name: users.name,
        username: users.username,
        role: users.role,
        email: users.email,
        isActive: users.isActive,
      });

    return createdUser;
  } catch (error) {
    // Antisipasi race condition request OTP paralel untuk email yang sama.
    if (
      error instanceof Error &&
      error.message.includes("UNIQUE constraint failed: users.email")
    ) {
      const existing = await findUserByEmail(email);
      if (existing) {
        return existing;
      }
    }
    throw error;
  }
}

function buildUsernameBaseFromEmail(email: string): string {
  const localPart = email.split("@")[0] ?? "";
  const cleaned = localPart.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (cleaned.length >= 3) {
    return cleaned.slice(0, 18);
  }
  return "siswa";
}

function buildDisplayNameFromEmail(email: string): string {
  const localPart = email.split("@")[0] ?? "";
  const cleaned = localPart
    .replace(/[^a-zA-Z0-9._-]/g, "")
    .replace(/[._-]+/g, " ")
    .trim();

  if (cleaned.length === 0) {
    return "Siswa Baru";
  }

  const name = cleaned
    .split(/\s+/)
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
  return `Siswa ${name}`.slice(0, 80);
}

async function generateUniqueUsername(base: string): Promise<string> {
  if (await isUsernameAvailable(base)) {
    return base;
  }

  for (let attempt = 0; attempt < 20; attempt += 1) {
    const suffix = crypto.randomUUID().replace(/-/g, "").slice(0, 6);
    const candidate = `${base}${suffix}`.slice(0, 24);
    if (await isUsernameAvailable(candidate)) {
      return candidate;
    }
  }

  // Fallback jika collision berulang.
  return `siswa${Date.now().toString().slice(-8)}`;
}

async function isUsernameAvailable(username: string): Promise<boolean> {
  const [existing] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.username, username))
    .limit(1);
  return !existing;
}
