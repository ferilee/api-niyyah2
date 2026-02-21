import { and, count, eq, gte, lte, sql } from "drizzle-orm";
import { db, sqlite } from "./client.ts";
import {
  adminAuditLogs,
  authOtps,
  habits,
  habitLogs,
  rewardEvents,
  teacherClassAssignments,
  users,
} from "./schema.ts";

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  email TEXT UNIQUE,
  school_npsn TEXT,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('siswa', 'guru', 'admin', 'support', 'editor')),
  class_name TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  points INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS habits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'Umum',
  description TEXT,
  points INTEGER NOT NULL DEFAULT 10,
  requires_proof INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS habit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  habit_id INTEGER NOT NULL,
  log_date TEXT NOT NULL,
  note TEXT,
  proof_url TEXT,
  verification_status TEXT NOT NULL DEFAULT 'approved' CHECK (verification_status IN ('approved', 'pending', 'rejected')),
  verification_note TEXT,
  verified_by INTEGER,
  verified_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (habit_id) REFERENCES habits(id),
  FOREIGN KEY (verified_by) REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS user_habit_date_unique
  ON habit_logs(user_id, habit_id, log_date);

CREATE TABLE IF NOT EXISTS reward_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  source TEXT NOT NULL,
  points INTEGER NOT NULL,
  reference_id INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS auth_otps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_auth_otps_user_id ON auth_otps(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_otps_email ON auth_otps(email);

CREATE TABLE IF NOT EXISTS teacher_class_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_id INTEGER NOT NULL,
  class_name TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (teacher_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS teacher_class_unique
  ON teacher_class_assignments(teacher_id, class_name);

CREATE TABLE IF NOT EXISTS admin_audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  details TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (actor_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_created_at
  ON admin_audit_logs(created_at);
`;

const DEFAULT_HABITS = [
  {
    name: "Shalat Dhuha",
    category: "Shalat",
    description: "Melaksanakan shalat Dhuha",
    points: 15,
    requiresProof: false,
  },
  {
    name: "Membaca Buku",
    category: "Belajar",
    description: "Membaca buku minimal 15 menit",
    points: 10,
    requiresProof: false,
  },
  {
    name: "Membuang Sampah",
    category: "Kebersihan",
    description: "Membuang sampah pada tempatnya",
    points: 5,
    requiresProof: true,
  },
];

export async function initializeDatabase() {
  sqlite.exec(CREATE_TABLE_SQL);
  ensureUsersIsActiveColumn();
  ensureUsersEmailColumn();
  ensureUsersSchoolNpsnColumn();
  ensureUsersRoleSupportsAdminAndTeacherLevels();
  ensureHabitsRequiresProofColumn();
  ensureHabitsCategoryColumn();
  ensureHabitLogsVerificationColumns();
  await seedInitialData();
}

function ensureUsersIsActiveColumn() {
  const columns = sqlite.query("PRAGMA table_info(users);").all() as Array<{
    name: string;
  }>;
  const hasIsActive = columns.some((col) => col.name === "is_active");

  if (!hasIsActive) {
    sqlite.exec(
      "ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;",
    );
  }
}

function ensureUsersEmailColumn() {
  const columns = sqlite.query("PRAGMA table_info(users);").all() as Array<{
    name: string;
  }>;
  const hasEmail = columns.some((col) => col.name === "email");

  if (!hasEmail) {
    sqlite.exec("ALTER TABLE users ADD COLUMN email TEXT;");
  }

  sqlite.exec(
    "CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email);",
  );
}

function ensureUsersSchoolNpsnColumn() {
  const columns = sqlite.query("PRAGMA table_info(users);").all() as Array<{
    name: string;
  }>;
  const hasSchoolNpsn = columns.some((col) => col.name === "school_npsn");

  if (!hasSchoolNpsn) {
    sqlite.exec("ALTER TABLE users ADD COLUMN school_npsn TEXT;");
  }
}

function ensureHabitsRequiresProofColumn() {
  const columns = sqlite.query("PRAGMA table_info(habits);").all() as Array<{
    name: string;
  }>;
  const hasRequiresProof = columns.some((col) => col.name === "requires_proof");

  if (!hasRequiresProof) {
    sqlite.exec(
      "ALTER TABLE habits ADD COLUMN requires_proof INTEGER NOT NULL DEFAULT 0;",
    );
  }
}

function ensureHabitsCategoryColumn() {
  const columns = sqlite.query("PRAGMA table_info(habits);").all() as Array<{
    name: string;
  }>;
  const hasCategory = columns.some((col) => col.name === "category");

  if (!hasCategory) {
    sqlite.exec("ALTER TABLE habits ADD COLUMN category TEXT NOT NULL DEFAULT 'Umum';");
  }
}

function ensureHabitLogsVerificationColumns() {
  const columns = sqlite
    .query("PRAGMA table_info(habit_logs);")
    .all() as Array<{
    name: string;
  }>;
  const names = new Set(columns.map((col) => col.name));

  if (!names.has("proof_url")) {
    sqlite.exec("ALTER TABLE habit_logs ADD COLUMN proof_url TEXT;");
  }
  if (!names.has("verification_status")) {
    sqlite.exec(
      "ALTER TABLE habit_logs ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'approved';",
    );
  }
  if (!names.has("verification_note")) {
    sqlite.exec("ALTER TABLE habit_logs ADD COLUMN verification_note TEXT;");
  }
  if (!names.has("verified_by")) {
    sqlite.exec("ALTER TABLE habit_logs ADD COLUMN verified_by INTEGER;");
  }
  if (!names.has("verified_at")) {
    sqlite.exec("ALTER TABLE habit_logs ADD COLUMN verified_at INTEGER;");
  }
}

function ensureUsersRoleSupportsAdminAndTeacherLevels() {
  const [table] = sqlite
    .query(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users';",
    )
    .all() as Array<{ sql: string | null }>;

  const createSql = (table?.sql ?? "").toLowerCase();
  if (
    createSql.includes("'admin'") &&
    createSql.includes("'support'") &&
    createSql.includes("'editor'")
  ) {
    return;
  }

  sqlite.exec(`
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

CREATE TABLE users_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  email TEXT UNIQUE,
  school_npsn TEXT,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('siswa', 'guru', 'admin', 'support', 'editor')),
  class_name TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  points INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT INTO users_new (
  id,
  name,
  username,
  email,
  school_npsn,
  password_hash,
  role,
  class_name,
  is_active,
  points,
  created_at
)
SELECT
  id,
  name,
  username,
  email,
  school_npsn,
  password_hash,
  role,
  class_name,
  is_active,
  points,
  created_at
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

COMMIT;
PRAGMA foreign_keys=ON;
  `);

  sqlite.exec(
    "CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email);",
  );
}
async function seedInitialData() {
  const [habitCount] = await db.select({ count: count() }).from(habits);
  if ((habitCount?.count ?? 0) === 0) {
    await db.insert(habits).values(DEFAULT_HABITS);
  }

  const [teacher] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.username, "guru1"))
    .limit(1);
  if (!teacher) {
    const hash = await Bun.password.hash("guru123");
    await db.insert(users).values({
      name: "Guru Utama",
      username: "guru1",
      email: "guru1@example.com",
      schoolNpsn: null,
      passwordHash: hash,
      role: "guru",
      className: null,
      isActive: true,
      points: 0,
    });
  }

  const [admin] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.username, "ferilee"))
    .limit(1);
  if (!admin) {
    const hash = await Bun.password.hash("F3r!-lee");
    await db.insert(users).values({
      name: "Administrator",
      username: "ferilee",
      email: "ferilee@example.com",
      schoolNpsn: null,
      passwordHash: hash,
      role: "admin",
      className: null,
      isActive: true,
      points: 0,
    });
  }

  const [student] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.username, "siswa1"))
    .limit(1);
  if (!student) {
    const hash = await Bun.password.hash("siswa123");
    await db.insert(users).values({
      name: "Siswa Satu",
      username: "siswa1",
      email: "siswa1@example.com",
      schoolNpsn: null,
      passwordHash: hash,
      role: "siswa",
      className: "7A",
      isActive: true,
      points: 0,
    });
  }
}

export function todayISODate(date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

export async function calculateCurrentStreak(userId: number): Promise<number> {
  const [range] = await db
    .select({
      minDate: sql<string>`MIN(${habitLogs.logDate})`,
      maxDate: sql<string>`MAX(${habitLogs.logDate})`,
    })
    .from(habitLogs)
    .where(eq(habitLogs.userId, userId));

  if (!range?.maxDate || !range?.minDate) {
    return 0;
  }

  const [daysResult] = await db
    .select({ count: count() })
    .from(
      db
        .selectDistinct({ logDate: habitLogs.logDate })
        .from(habitLogs)
        .where(eq(habitLogs.userId, userId))
        .as("distinct_days"),
    );

  const distinctDaysCount = Number(daysResult?.count ?? 0);
  if (distinctDaysCount === 0) {
    return 0;
  }

  const today = todayISODate();
  const [hasTodayEntry] = await db
    .select({ count: count() })
    .from(habitLogs)
    .where(and(eq(habitLogs.userId, userId), eq(habitLogs.logDate, today)));

  const [hasYesterdayEntry] = await db
    .select({ count: count() })
    .from(habitLogs)
    .where(
      and(
        eq(habitLogs.userId, userId),
        eq(habitLogs.logDate, shiftISODate(today, -1)),
      ),
    );

  // Streak aktif jika ada log hari ini atau kemarin.
  if (
    (hasTodayEntry?.count ?? 0) === 0 &&
    (hasYesterdayEntry?.count ?? 0) === 0
  ) {
    return 0;
  }

  // Hitung streak mundur berdasarkan hari unik yang berurutan.
  let streak = 0;
  let cursor =
    (hasTodayEntry?.count ?? 0) > 0 ? today : shiftISODate(today, -1);

  while (true) {
    const [exists] = await db
      .select({ count: count() })
      .from(habitLogs)
      .where(and(eq(habitLogs.userId, userId), eq(habitLogs.logDate, cursor)));

    if ((exists?.count ?? 0) === 0) {
      break;
    }

    streak += 1;
    cursor = shiftISODate(cursor, -1);
  }

  return streak;
}

function shiftISODate(baseISODate: string, offsetDays: number): string {
  const date = new Date(`${baseISODate}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() + offsetDays);
  return todayISODate(date);
}

export async function getTodayCompletionCount(userId: number): Promise<number> {
  const [result] = await db
    .select({ count: count() })
    .from(habitLogs)
    .where(
      and(eq(habitLogs.userId, userId), eq(habitLogs.logDate, todayISODate())),
    );

  return Number(result?.count ?? 0);
}

export async function getMonthlyLogCount(userId: number): Promise<number> {
  const now = new Date();
  const firstDay = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1),
  );
  const lastDay = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 0),
  );

  const [result] = await db
    .select({ count: count() })
    .from(habitLogs)
    .where(
      and(
        eq(habitLogs.userId, userId),
        gte(habitLogs.logDate, todayISODate(firstDay)),
        lte(habitLogs.logDate, todayISODate(lastDay)),
      ),
    );

  return Number(result?.count ?? 0);
}

export async function addPoints(
  userId: number,
  points: number,
  source: string,
  referenceId?: number,
) {
  await db
    .update(users)
    .set({ points: sql`${users.points} + ${points}` })
    .where(eq(users.id, userId));

  await db.insert(rewardEvents).values({
    userId,
    points,
    source,
    referenceId: referenceId ?? null,
  });
}

export async function clearExpiredOtps() {
  await db
    .delete(authOtps)
    .where(
      and(
        lte(authOtps.expiresAt, new Date()),
        sql`${authOtps.consumedAt} IS NULL`,
      ),
    );
}
