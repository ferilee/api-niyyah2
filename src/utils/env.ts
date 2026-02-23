function getFirstEnv(...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = process.env[key];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

function parseNumber(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (!value) {
    return fallback;
  }
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["false", "0", "no", "off"].includes(normalized)) {
    return false;
  }
  return fallback;
}

function parseCsv(value: string | undefined, fallback: string[]): string[] {
  const source = value && value.trim().length > 0 ? value : fallback.join(",");
  return source
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

export const env = {
  jwtSecret:
    getFirstEnv("JWT_SECRET", "SESSION_SECRET") ?? "dev-secret-change-me",
  host: process.env.HOST ?? "0.0.0.0",
  port: parseNumber(process.env.PORT, 3000),
  schoolApiBaseUrl:
    process.env.SCHOOL_API_BASE_URL ?? "https://sekolah.devapi.id/sekolah",
  schoolApiTimeoutMs: parseNumber(process.env.SCHOOL_API_TIMEOUT_MS, 5000),
  otpExpiresMinutes: parseNumber(process.env.OTP_EXPIRES_MINUTES, 10),
  otpMaxAttempts: parseNumber(process.env.OTP_MAX_ATTEMPTS, 5),
  appName: process.env.APP_NAME ?? "Niyyah",
  otpSubject: process.env.OTP_SUBJECT ?? "Kode OTP Login Siswa",
  mailFrom:
    process.env.MAIL_FROM ?? process.env.FROM_EMAIL ?? "no-reply@example.com",
  mailFromName: process.env.FROM_NAME,
  minioEndpoint: process.env.MINIO_ENDPOINT ?? "",
  minioRegion: process.env.MINIO_REGION ?? "us-east-1",
  minioAccessKey: process.env.MINIO_ACCESS_KEY ?? "",
  minioSecretKey: process.env.MINIO_SECRET_KEY ?? "",
  minioBucket: process.env.MINIO_BUCKET ?? "niyyah-proof",
  minioUseSsl: parseBoolean(process.env.MINIO_USE_SSL, false),
  minioPublicBaseUrl: process.env.MINIO_PUBLIC_BASE_URL ?? "",
  googleOauthClientId: process.env.GOOGLE_OAUTH_CLIENT_ID ?? "",
  googleOauthClientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET ?? "",
  googleOauthCallbackUrl:
    process.env.GOOGLE_OAUTH_CALLBACK_URL ??
    "http://localhost:3000/auth/google/callback",
  googleOauthFrontendRedirectUrl:
    process.env.GOOGLE_OAUTH_FRONTEND_REDIRECT_URL ??
    "http://localhost:7001/login",
  googleOauthScopes:
    process.env.GOOGLE_OAUTH_SCOPES ?? "openid email profile",
  googleOauthAllowedRedirectOrigins: parseCsv(
    process.env.GOOGLE_OAUTH_ALLOWED_REDIRECT_ORIGINS,
    ["http://localhost:7001", "http://127.0.0.1:7001"],
  ),
};
