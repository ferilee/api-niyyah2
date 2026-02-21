import {
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  name: text("name").notNull(),
  username: text("username").notNull().unique(),
  email: text("email").unique(),
  schoolNpsn: text("school_npsn"),
  passwordHash: text("password_hash").notNull(),
  role: text("role", {
    enum: ["siswa", "guru", "admin", "support", "editor"],
  }).notNull(),
  className: text("class_name"),
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
  points: integer("points").notNull().default(0),
  createdAt: integer("created_at", { mode: "timestamp" }).$defaultFn(
    () => new Date(),
  ),
});

export const habits = sqliteTable("habits", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  name: text("name").notNull(),
  category: text("category").notNull().default("Umum"),
  description: text("description"),
  points: integer("points").notNull().default(10),
  requiresProof: integer("requires_proof", { mode: "boolean" })
    .notNull()
    .default(false),
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
  createdAt: integer("created_at", { mode: "timestamp" }).$defaultFn(
    () => new Date(),
  ),
});

export const habitLogs = sqliteTable(
  "habit_logs",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    userId: integer("user_id")
      .notNull()
      .references(() => users.id),
    habitId: integer("habit_id")
      .notNull()
      .references(() => habits.id),
    logDate: text("log_date").notNull(),
    note: text("note"),
    proofUrl: text("proof_url"),
    verificationStatus: text("verification_status", {
      enum: ["approved", "pending", "rejected"],
    })
      .notNull()
      .default("approved"),
    verificationNote: text("verification_note"),
    verifiedBy: integer("verified_by").references(() => users.id),
    verifiedAt: integer("verified_at", { mode: "timestamp" }),
    createdAt: integer("created_at", { mode: "timestamp" }).$defaultFn(
      () => new Date(),
    ),
  },
  (table) => ({
    userHabitDateUnique: uniqueIndex("user_habit_date_unique").on(
      table.userId,
      table.habitId,
      table.logDate,
    ),
  }),
);

export const rewardEvents = sqliteTable("reward_events", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  userId: integer("user_id")
    .notNull()
    .references(() => users.id),
  source: text("source").notNull(),
  points: integer("points").notNull(),
  referenceId: integer("reference_id"),
  createdAt: integer("created_at", { mode: "timestamp" }).$defaultFn(
    () => new Date(),
  ),
});

export const authOtps = sqliteTable("auth_otps", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  userId: integer("user_id")
    .notNull()
    .references(() => users.id),
  email: text("email").notNull(),
  codeHash: text("code_hash").notNull(),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
  attempts: integer("attempts").notNull().default(0),
  consumedAt: integer("consumed_at", { mode: "timestamp" }),
  createdAt: integer("created_at", { mode: "timestamp" }).$defaultFn(
    () => new Date(),
  ),
});

export const teacherClassAssignments = sqliteTable(
  "teacher_class_assignments",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    teacherId: integer("teacher_id")
      .notNull()
      .references(() => users.id),
    className: text("class_name").notNull(),
    createdAt: integer("created_at", { mode: "timestamp" }).$defaultFn(
      () => new Date(),
    ),
  },
  (table) => ({
    teacherClassUnique: uniqueIndex("teacher_class_unique").on(
      table.teacherId,
      table.className,
    ),
  }),
);

export const adminAuditLogs = sqliteTable("admin_audit_logs", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  actorId: integer("actor_id")
    .notNull()
    .references(() => users.id),
  action: text("action").notNull(),
  targetType: text("target_type").notNull(),
  targetId: text("target_id"),
  details: text("details"),
  createdAt: integer("created_at", { mode: "timestamp" }).$defaultFn(
    () => new Date(),
  ),
});

export type UserRole = (typeof users.$inferSelect)["role"];
export type User = typeof users.$inferSelect;
