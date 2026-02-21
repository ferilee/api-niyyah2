import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { env } from "./env.ts";

let s3Client: S3Client | null = null;

function buildClient(): S3Client {
  if (!env.minioEndpoint || !env.minioAccessKey || !env.minioSecretKey) {
    throw new Error(
      "Konfigurasi MinIO belum lengkap (MINIO_ENDPOINT/MINIO_ACCESS_KEY/MINIO_SECRET_KEY)",
    );
  }

  return new S3Client({
    region: env.minioRegion,
    endpoint: env.minioEndpoint,
    forcePathStyle: true,
    credentials: {
      accessKeyId: env.minioAccessKey,
      secretAccessKey: env.minioSecretKey,
    },
  });
}

function getClient(): S3Client {
  if (!s3Client) {
    s3Client = buildClient();
  }
  return s3Client;
}

function normalizeExt(contentType: string): string {
  if (contentType.includes("png")) return "png";
  if (contentType.includes("jpeg") || contentType.includes("jpg")) return "jpg";
  if (contentType.includes("webp")) return "webp";
  if (contentType.includes("gif")) return "gif";
  return "bin";
}

export async function uploadHabitProofToMinio(input: {
  userId: number;
  habitId: number;
  bytes: Uint8Array;
  contentType: string;
}) {
  const client = getClient();
  const ext = normalizeExt(input.contentType);
  const objectKey = `habit-proofs/${todayPath()}/${input.userId}/${input.habitId}-${crypto.randomUUID()}.${ext}`;

  await client.send(
    new PutObjectCommand({
      Bucket: env.minioBucket,
      Key: objectKey,
      Body: input.bytes,
      ContentType: input.contentType,
    }),
  );

  const publicBase = env.minioPublicBaseUrl.trim();
  const proofUrl = publicBase
    ? `${publicBase.replace(/\/$/, "")}/${objectKey}`
    : `${env.minioEndpoint.replace(/\/$/, "")}/${env.minioBucket}/${objectKey}`;

  return {
    objectKey,
    proofUrl,
  };
}

function todayPath(date = new Date()) {
  const yyyy = date.getUTCFullYear();
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(date.getUTCDate()).padStart(2, "0");
  return `${yyyy}/${mm}/${dd}`;
}
