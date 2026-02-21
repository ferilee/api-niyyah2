import { Resend } from "resend";
import nodemailer from "nodemailer";
import { env } from "./env.ts";

type SendOtpInput = {
  to: string;
  code: string;
  studentName: string;
};

type SendResult = {
  provider: "resend" | "nodemailer" | "mock";
};

const mailProvider = process.env.MAIL_PROVIDER ?? "auto";
const mailFrom = formatMailFrom(env.mailFromName, env.mailFrom);

export async function sendOtpEmail(input: SendOtpInput): Promise<SendResult> {
  if (
    process.env.NODE_ENV === "test" ||
    process.env.OTP_DEBUG_MOCK_SEND === "true"
  ) {
    return { provider: "mock" };
  }

  if (mailProvider === "resend" || mailProvider === "auto") {
    const resendApiKey = process.env.RESEND_API_KEY;
    if (resendApiKey) {
      const resend = new Resend(resendApiKey);
      await resend.emails.send({
        from: mailFrom,
        to: input.to,
        subject: env.otpSubject,
        html: buildOtpHtml(input.studentName, input.code),
      });
      return { provider: "resend" };
    }

    if (mailProvider === "resend") {
      throw new Error("RESEND_API_KEY belum diatur");
    }
  }

  if (mailProvider === "nodemailer" || mailProvider === "auto") {
    const host = process.env.SMTP_HOST;
    const port = Number(process.env.SMTP_PORT ?? 587);
    const user = normalizeEmail(
      process.env.SMTP_USER ?? process.env.GMAIL_USER,
    );
    const pass = normalizeSmtpPassword(
      process.env.SMTP_PASS ?? process.env.GMAIL_APP_PASSWORD,
    );
    const secure = parseBoolean(process.env.SMTP_SECURE) ?? port === 465;
    const requireTLS = parseBoolean(process.env.SMTP_STARTTLS) ?? false;

    if (host && user && pass) {
      const transporter = nodemailer.createTransport({
        host,
        port,
        secure,
        requireTLS,
        auth: {
          user,
          pass,
        },
      });

      try {
        await transporter.verify();
      } catch (error) {
        throw new Error(
          `SMTP auth gagal (${host}:${port}) untuk akun ${user}. Cek SMTP_USER/SMTP_PASS (App Password Gmail) dan verifikasi 2 langkah.`,
        );
      }

      await transporter.sendMail({
        from: mailFrom,
        to: input.to,
        subject: env.otpSubject,
        html: buildOtpHtml(input.studentName, input.code),
      });

      return { provider: "nodemailer" };
    }

    if (mailProvider === "nodemailer") {
      throw new Error(
        "Konfigurasi SMTP belum lengkap (SMTP_HOST/SMTP_USER/SMTP_PASS)",
      );
    }
  }

  throw new Error(
    "Provider email tidak dikonfigurasi. Atur Resend atau SMTP Nodemailer.",
  );
}

function buildOtpHtml(studentName: string, code: string): string {
  return `
  <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #1f2937;">
    <h2 style="margin-bottom: 8px;">OTP Login Siswa</h2>
    <p>Halo ${escapeHtml(studentName)},</p>
    <p>Gunakan kode OTP berikut untuk login:</p>
    <p style="font-size: 28px; font-weight: bold; letter-spacing: 4px; margin: 12px 0;">${code}</p>
    <p>Kode berlaku selama ${env.otpExpiresMinutes} menit dan hanya bisa dipakai sekali.</p>
  </div>
  `;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatMailFrom(name: string | undefined, email: string): string {
  if (!name) {
    return email;
  }
  return `${name} <${email}>`;
}

function parseBoolean(value: string | undefined): boolean | undefined {
  if (!value) {
    return undefined;
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === "true") {
    return true;
  }
  if (normalized === "false") {
    return false;
  }
  return undefined;
}

function normalizeEmail(value: string | undefined): string | undefined {
  return value?.trim().toLowerCase();
}

function normalizeSmtpPassword(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }

  // Gmail app password kadang disalin dengan spasi per 4 karakter.
  return value.trim().replaceAll(" ", "");
}
