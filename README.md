# API Niyyah (Bun + Hono + SQLite)

API backend monitoring kebiasaan siswa dengan Bun + Hono + SQLite, dilengkapi JWT, RBAC, gamifikasi poin/streak, dan login siswa via OTP email.

## Stack

- Runtime: Bun
- Framework: Hono
- Database: SQLite
- ORM: Drizzle ORM
- Validation: Zod
- Email OTP: Resend + Nodemailer
- Profil sekolah user: API Sekolah (`https://github.com/ikhsan-rfl/api-sekolah`)

## Setup

1. Install dependency

```bash
bun install
```

2. Buat env

```bash
cp .env.example .env
```

3. Jalankan API

```bash
bun run dev
```

## Konfigurasi OTP Email

Di `.env`:

- `MAIL_PROVIDER=auto|resend|nodemailer`
- `MAIL_FROM=no-reply@domain-anda.com`
- `SCHOOL_API_BASE_URL=https://sekolah.devapi.id/sekolah`
- `SCHOOL_API_TIMEOUT_MS=5000`
- Jika pakai Resend:
  - `RESEND_API_KEY=...`
- Jika pakai SMTP/Nodemailer:
  - `SMTP_HOST=...`
  - `SMTP_PORT=587`
  - `SMTP_USER=...`
  - `SMTP_PASS=...`

Mode debug lokal:

- `OTP_DEBUG_RETURN_CODE=true` untuk mengembalikan kode OTP di response (jangan aktifkan di production)
- `OTP_DEBUG_FIXED_CODE=123456` untuk kode OTP statis saat testing

## Seed Data Default

- Guru:
  - username: `guru1`
  - password: `guru123`
  - email: `guru1@example.com`
- Siswa:
  - username: `siswa1`
  - password tersimpan untuk admin reset, tapi login siswa menggunakan OTP
  - email: `siswa1@example.com`


## MinIO (Bukti Foto Habit)

Jalankan MinIO lokal (plus auto create bucket `niyyah-proof`):

```bash
bun run minio:up
```

Stop MinIO:

```bash
bun run minio:down
```

Lalu set `.env` backend:

```env
MINIO_ENDPOINT=http://127.0.0.1:9010
MINIO_REGION=us-east-1
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_BUCKET=niyyah-proof
MINIO_USE_SSL=false
MINIO_PUBLIC_BASE_URL=http://127.0.0.1:9010/niyyah-proof
```

Endpoint baru terkait bukti foto:
- `POST /habits/proof/upload` (multipart: `habitId`, `file`)
- `GET /admin/verifications/pending`
- `PATCH /admin/verifications/:logId` (action: `approve`/`reject`, optional `note`)

## Auth Endpoint

Semua endpoint juga tersedia dengan prefix `/api` untuk kompatibilitas reverse proxy (contoh: `/api/auth/login`).

### POST `/auth/login`

- Untuk guru: login username/password.
- Untuk siswa: akan ditolak (`403`) dan diarahkan ke OTP email.

Request:

```json
{
  "username": "guru1",
  "password": "guru123"
}
```

### POST `/auth/otp/request`

Kirim OTP ke email siswa.

Request:

```json
{
  "email": "siswa1@example.com"
}
```

### POST `/auth/otp/verify`

Verifikasi OTP siswa dan dapatkan JWT.

Request:

```json
{
  "email": "siswa1@example.com",
  "code": "123456"
}
```

## Endpoint Inti

- `GET /user/profile` (termasuk `schoolProfile` jika `schoolNpsn` tersedia)
- `GET /habits`
- `POST /habits/log`
- `GET /admin/stats`
- `GET /admin/leaderboard`
- `POST /admin/users`
- `GET /admin/users`
- `PATCH /admin/users/:id`
- `DELETE /admin/users/:id`
- `GET /admin/habits`
- `POST /admin/habits`
- `PATCH /admin/habits/:id`
- `DELETE /admin/habits/:id`

## Catatan Admin User

Pada `POST /admin/users`, field `email` wajib.

Contoh siswa:

```json
{
  "name": "Siswa Dua",
  "username": "siswa2",
  "email": "siswa2@example.com",
  "schoolNpsn": "40604924",
  "password": "siswa234",
  "role": "siswa",
  "className": "7B"
}
```

## Testing

```bash
bun run check
bun run test
```
