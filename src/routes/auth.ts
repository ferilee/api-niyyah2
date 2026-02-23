import { Hono } from "hono";
import { sign, verify } from "hono/jwt";
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

type AuthRole = "siswa" | "guru" | "admin" | "support" | "editor";

type AuthUser = {
  id: number;
  name: string;
  username: string;
  role: AuthRole;
  email: string | null;
  isActive: boolean;
};

type OAuthStatePayload = {
  redirectUri: string;
  nonce: string;
  iat: number;
  exp: number;
};

type GoogleTokenPayload = {
  access_token?: string;
  token_type?: string;
  scope?: string;
  expires_in?: number;
  id_token?: string;
  error?: string;
  error_description?: string;
};

type GoogleUserInfoPayload = {
  sub?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
};

export const authRoutes = new Hono();

authRoutes.get("/google", async (c) => {
  if (!isGoogleOAuthConfigured()) {
    return c.json(
      {
        message:
          "Google OAuth belum dikonfigurasi. Isi GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET, dan GOOGLE_OAUTH_CALLBACK_URL.",
      },
      500,
    );
  }

  const requestedRedirectUri = c.req.query("redirect_uri")?.trim() || "";
  const frontendRedirectUri = resolveFrontendRedirectUri(requestedRedirectUri);

  if (!frontendRedirectUri) {
    return c.json(
      {
        message:
          "redirect_uri frontend tidak valid atau tidak diizinkan oleh GOOGLE_OAUTH_ALLOWED_REDIRECT_ORIGINS.",
      },
      400,
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const statePayload: OAuthStatePayload = {
    redirectUri: frontendRedirectUri,
    nonce: crypto.randomUUID(),
    iat: now,
    exp: now + 10 * 60,
  };
  const stateToken = await sign(statePayload, env.jwtSecret);

  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.searchParams.set("client_id", env.googleOauthClientId);
  authUrl.searchParams.set("redirect_uri", env.googleOauthCallbackUrl);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", env.googleOauthScopes);
  authUrl.searchParams.set("access_type", "online");
  authUrl.searchParams.set("include_granted_scopes", "true");
  authUrl.searchParams.set("prompt", "select_account");
  authUrl.searchParams.set("state", stateToken);

  return c.redirect(authUrl.toString(), 302);
});

authRoutes.get("/google/callback", async (c) => {
  const oauthError = c.req.query("error")?.trim();
  const authCode = c.req.query("code")?.trim();
  const stateToken = c.req.query("state")?.trim();

  const frontendRedirectUri =
    (await resolveFrontendRedirectUriFromState(stateToken)) ||
    resolveFrontendRedirectUri("") ||
    "http://localhost:7001/login";

  if (oauthError) {
    return c.redirect(
      buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
        error: `Google OAuth error: ${oauthError}`,
      }),
      302,
    );
  }

  if (!authCode) {
    return c.redirect(
      buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
        error: "Google OAuth gagal: code tidak ditemukan.",
      }),
      302,
    );
  }

  if (!isGoogleOAuthConfigured()) {
    return c.redirect(
      buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
        error:
          "Google OAuth belum dikonfigurasi. Isi GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET, dan GOOGLE_OAUTH_CALLBACK_URL.",
      }),
      302,
    );
  }

  let tokenPayload: GoogleTokenPayload = {};

  try {
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        code: authCode,
        client_id: env.googleOauthClientId,
        client_secret: env.googleOauthClientSecret,
        redirect_uri: env.googleOauthCallbackUrl,
        grant_type: "authorization_code",
      }).toString(),
    });

    tokenPayload = (await tokenResponse.json().catch(() =>
      ({}),
    )) as GoogleTokenPayload;

    if (!tokenResponse.ok || !tokenPayload.access_token) {
      const detail = sanitizeOAuthError(
        tokenPayload.error_description || tokenPayload.error,
      );
      return c.redirect(
        buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
          error: `Gagal menukar code Google OAuth.${detail ? ` ${detail}` : ""}`,
        }),
        302,
      );
    }
  } catch (error) {
    return c.redirect(
      buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
        error: `Gagal koneksi ke token endpoint Google. ${sanitizeOAuthError(error instanceof Error ? error.message : "Unknown error")}`,
      }),
      302,
    );
  }

  let googleUser: GoogleUserInfoPayload = {};

  try {
    const userInfoResponse = await fetch(
      "https://openidconnect.googleapis.com/v1/userinfo",
      {
        headers: {
          Authorization: `Bearer ${tokenPayload.access_token}`,
        },
      },
    );

    googleUser = (await userInfoResponse.json().catch(() =>
      ({}),
    )) as GoogleUserInfoPayload;

    if (!userInfoResponse.ok) {
      return c.redirect(
        buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
          error: "Gagal mengambil profil Google user.",
        }),
        302,
      );
    }
  } catch (error) {
    return c.redirect(
      buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
        error: `Gagal koneksi ke userinfo Google. ${sanitizeOAuthError(error instanceof Error ? error.message : "Unknown error")}`,
      }),
      302,
    );
  }

  const normalizedEmail = String(googleUser.email || "")
    .trim()
    .toLowerCase();
  if (!normalizedEmail) {
    return c.redirect(
      buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
        error: "Akun Google tidak memiliki email.",
      }),
      302,
    );
  }

  if (googleUser.email_verified !== true) {
    return c.redirect(
      buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
        error: "Email Google belum terverifikasi.",
      }),
      302,
    );
  }

  let user = await findUserByEmail(normalizedEmail);
  if (!user) {
    user = await createAutoStudentUser(normalizedEmail);
  }

  if (!user.isActive) {
    return c.redirect(
      buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
        error: "Akun tidak aktif.",
      }),
      302,
    );
  }

  if (user.role === "admin") {
    return c.redirect(
      buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
        error: "Admin harus login menggunakan Username dan Password.",
      }),
      302,
    );
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
    })
    .from(users)
    .where(eq(users.id, user.id))
    .limit(1);

  if (!authUser) {
    return c.redirect(
      buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
        error: "User tidak ditemukan setelah login Google.",
      }),
      302,
    );
  }

  const token = await buildAccessToken(
    authUser.id,
    authUser.username,
    authUser.role,
  );

  const userPayload = {
    id: authUser.id,
    name: authUser.name,
    username: authUser.username,
    role: authUser.role,
    className: authUser.className,
    points: authUser.points,
    email: authUser.email,
  };

  return c.redirect(
    buildFrontendRedirectUrl(frontendRedirectUri, c.req.url, {
      token,
      user: JSON.stringify(userPayload),
    }),
    302,
  );
});

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

  const token = await buildAccessToken(
    authUser.id,
    authUser.username,
    authUser.role,
  );

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

function isGoogleOAuthConfigured() {
  return Boolean(
    env.googleOauthClientId &&
      env.googleOauthClientSecret &&
      env.googleOauthCallbackUrl,
  );
}

function sanitizeOAuthError(value: string | undefined): string {
  if (!value) return "";
  return value.replace(/\s+/g, " ").trim().slice(0, 220);
}

function resolveFrontendRedirectUri(candidate: string): string | null {
  if (candidate && isAllowedFrontendRedirectUri(candidate)) {
    return candidate;
  }

  if (
    env.googleOauthFrontendRedirectUrl &&
    isAllowedFrontendRedirectUri(env.googleOauthFrontendRedirectUrl)
  ) {
    return env.googleOauthFrontendRedirectUrl;
  }

  return null;
}

function isAllowedFrontendRedirectUri(candidate: string): boolean {
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return false;
    }

    return env.googleOauthAllowedRedirectOrigins.includes(parsed.origin);
  } catch {
    return false;
  }
}

async function resolveFrontendRedirectUriFromState(
  stateToken: string | undefined,
): Promise<string | null> {
  if (!stateToken) return null;

  try {
    const payload = (await verify(stateToken, env.jwtSecret, "HS256")) as
      | Record<string, unknown>
      | null;

    const redirectUri =
      payload && typeof payload.redirectUri === "string"
        ? payload.redirectUri
        : "";

    if (!redirectUri || !isAllowedFrontendRedirectUri(redirectUri)) {
      return null;
    }

    return redirectUri;
  } catch {
    return null;
  }
}

function buildFrontendRedirectUrl(
  frontendRedirectUri: string,
  requestUrl: string,
  params: Record<string, string>,
): string {
  const url = toUrl(frontendRedirectUri, requestUrl);

  for (const [key, value] of Object.entries(params)) {
    if (!value) continue;
    url.searchParams.set(key, value);
  }

  return url.toString();
}

function toUrl(value: string, base: string): URL {
  try {
    return new URL(value);
  } catch {
    return new URL(value, base);
  }
}

async function buildAccessToken(
  userId: number,
  username: string,
  role: AuthRole,
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
