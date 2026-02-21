import { Hono } from "hono";
import { and, count, desc, eq, gte, lte, sql } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db/client.ts";
import { calculateCurrentStreak, todayISODate } from "../db/init.ts";
import {
  adminAuditLogs,
  habitLogs,
  habits,
  rewardEvents,
  teacherClassAssignments,
  users,
} from "../db/schema.ts";
import { requireAuth, requireRole } from "../middleware/auth.ts";
import type { AuthUser } from "../types.ts";

type Variables = { user: AuthUser };

const dateRegex = /^\d{4}-\d{2}-\d{2}$/;

const createHabitSchema = z.object({
  name: z.string().min(2).max(120),
  category: z.string().min(1).max(60).default("Umum"),
  description: z.string().max(300).optional(),
  points: z.number().int().min(1).max(1000).default(10),
  requiresProof: z.boolean().default(false),
});

const updateHabitSchema = z
  .object({
    name: z.string().min(2).max(120).optional(),
    category: z.string().min(1).max(60).nullable().optional(),
    description: z.string().max(300).nullable().optional(),
    points: z.number().int().min(1).max(1000).optional(),
    requiresProof: z.boolean().optional(),
    isActive: z.boolean().optional(),
  })
  .refine((data) => Object.keys(data).length > 0, {
    message: "Minimal satu field harus diisi",
  });

const createUserSchema = z
  .object({
    name: z.string().min(2).max(120),
    username: z.string().min(3).max(60),
    email: z.string().email(),
    schoolNpsn: z.string().min(3).max(20).optional(),
    password: z.string().min(6).max(200),
    role: z.enum(["siswa", "guru", "support", "editor"]),
    className: z.string().min(1).max(30).optional(),
  })
  .superRefine((data, ctx) => {
    if (data.role === "siswa" && !data.className) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["className"],
        message: "className wajib diisi untuk role siswa",
      });
    }
  });

const updateUserSchema = z
  .object({
    name: z.string().min(2).max(120).optional(),
    username: z.string().min(3).max(60).optional(),
    email: z.string().email().optional(),
    schoolNpsn: z.string().min(3).max(20).nullable().optional(),
    password: z.string().min(6).max(200).optional(),
    role: z.enum(["siswa", "guru", "support", "editor"]).optional(),
    className: z.string().min(1).max(30).nullable().optional(),
    isActive: z.boolean().optional(),
  })
  .refine((data) => Object.keys(data).length > 0, {
    message: "Minimal satu field harus diisi",
  });

const verifyHabitLogSchema = z.object({
  action: z.enum(["approve", "reject"]),
  note: z.string().max(300).optional(),
});

const createTeacherClassSchema = z.object({
  teacherId: z.number().int().positive(),
  className: z.string().min(1).max(30),
});

export const adminRoutes = new Hono<{ Variables: Variables }>();

async function writeAdminAuditLog(
  actorId: number,
  action: string,
  targetType: string,
  targetId?: string | number | null,
  details?: string | null,
) {
  try {
    await db.insert(adminAuditLogs).values({
      actorId,
      action,
      targetType,
      targetId: targetId == null ? null : String(targetId),
      details: details ?? null,
    });
  } catch {
    // do not break main flow when logging fails
  }
}

adminRoutes.use("*", requireAuth);
adminRoutes.use("*", requireRole("admin", "guru", "support", "editor"));

adminRoutes.post("/users", async (c) => {
  const body = await c.req.json().catch(() => null);
  const parsed = createUserSchema.safeParse(body);

  if (!parsed.success) {
    return c.json(
      { message: "Payload tidak valid", errors: parsed.error.flatten() },
      400,
    );
  }

  const [existing] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.username, parsed.data.username))
    .limit(1);

  const [existingEmail] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.email, parsed.data.email.trim().toLowerCase()))
    .limit(1);

  if (existing || existingEmail) {
    return c.json({ message: "Username atau email sudah digunakan" }, 409);
  }

  const passwordHash = await Bun.password.hash(parsed.data.password);

  const [created] = await db
    .insert(users)
    .values({
      name: parsed.data.name,
      username: parsed.data.username,
      email: parsed.data.email.trim().toLowerCase(),
      schoolNpsn:
        parsed.data.role === "siswa" || parsed.data.role === "guru"
          ? (parsed.data.schoolNpsn ?? null)
          : null,
      passwordHash,
      role: parsed.data.role,
      className:
        parsed.data.role === "siswa" ? (parsed.data.className ?? null) : null,
      isActive: true,
      points: 0,
    })
    .returning({
      id: users.id,
      name: users.name,
      username: users.username,
      email: users.email,
      schoolNpsn: users.schoolNpsn,
      role: users.role,
      className: users.className,
      isActive: users.isActive,
      points: users.points,
    });

  await writeAdminAuditLog(
    c.get("user").id,
    "create_user",
    "user",
    created?.id,
    "role=" + String(created?.role || parsed.data.role),
  );

  return c.json({ message: "User berhasil dibuat", data: created }, 201);
});

adminRoutes.get("/users", async (c) => {
  const role = c.req.query("role");
  const className = c.req.query("className");
  const q = c.req.query("q");
  const includeInactive = c.req.query("includeInactive") === "true";
  const page = Number(c.req.query("page") ?? 1);
  const limit = Number(c.req.query("limit") ?? 10);
  const safePage = Number.isNaN(page) ? 1 : Math.max(page, 1);
  const safeLimit = Number.isNaN(limit)
    ? 10
    : Math.min(Math.max(limit, 1), 100);

  if (role && !["siswa", "guru", "support", "editor"].includes(role)) {
    return c.json(
      { message: "role hanya boleh siswa|guru|support|editor" },
      400,
    );
  }

  const filters = [];

  if (!includeInactive) {
    filters.push(eq(users.isActive, true));
  }

  if (role) {
    filters.push(
      eq(users.role, role as "siswa" | "guru" | "support" | "editor"),
    );
  }

  if (className) {
    filters.push(eq(users.className, className));
  }

  if (q) {
    const pattern = `%${q.trim().toLowerCase()}%`;
    filters.push(
      sql`(LOWER(${users.name}) LIKE ${pattern} OR LOWER(${users.username}) LIKE ${pattern})`,
    );
  }

  const whereClause = filters.length > 0 ? and(...filters) : undefined;

  const [totalResult] = whereClause
    ? await db.select({ count: count() }).from(users).where(whereClause)
    : await db.select({ count: count() }).from(users);

  const baseQuery = db
    .select({
      id: users.id,
      name: users.name,
      username: users.username,
      email: users.email,
      schoolNpsn: users.schoolNpsn,
      role: users.role,
      className: users.className,
      isActive: users.isActive,
      points: users.points,
      createdAt: users.createdAt,
    })
    .from(users)
    .orderBy(desc(users.id))
    .limit(safeLimit)
    .offset((safePage - 1) * safeLimit);

  const rows = whereClause
    ? await baseQuery.where(whereClause)
    : await baseQuery;
  const totalItems = Number(totalResult?.count ?? 0);

  return c.json({
    filters: {
      role: role ?? null,
      className: className ?? null,
      q: q ?? null,
    },
    pagination: {
      page: safePage,
      limit: safeLimit,
      totalItems,
      totalPages: Math.max(1, Math.ceil(totalItems / safeLimit)),
    },
    users: rows,
  });
});

adminRoutes.patch("/users/:id", async (c) => {
  const authUser = c.get("user");
  const id = Number(c.req.param("id"));
  if (Number.isNaN(id) || id < 1) {
    return c.json({ message: "ID user tidak valid" }, 400);
  }

  const body = await c.req.json().catch(() => null);
  const parsed = updateUserSchema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      { message: "Payload tidak valid", errors: parsed.error.flatten() },
      400,
    );
  }

  const [existing] = await db
    .select({
      id: users.id,
      name: users.name,
      username: users.username,
      email: users.email,
      schoolNpsn: users.schoolNpsn,
      role: users.role,
      className: users.className,
      isActive: users.isActive,
      passwordHash: users.passwordHash,
    })
    .from(users)
    .where(eq(users.id, id))
    .limit(1);

  if (!existing) {
    return c.json({ message: "User tidak ditemukan" }, 404);
  }

  const nextRole = parsed.data.role ?? existing.role;
  const nextEmail =
    parsed.data.email !== undefined
      ? parsed.data.email.trim().toLowerCase()
      : existing.email;
  const nextClassName =
    parsed.data.className !== undefined
      ? parsed.data.className
      : nextRole === "guru"
        ? null
        : existing.className;

  if (nextRole === "siswa" && !nextClassName) {
    return c.json({ message: "className wajib diisi untuk role siswa" }, 400);
  }

  if (nextRole === "siswa" && !nextEmail) {
    return c.json({ message: "email wajib diisi untuk role siswa" }, 400);
  }

  if (parsed.data.username && parsed.data.username !== existing.username) {
    const [usernameTaken] = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.username, parsed.data.username))
      .limit(1);
    if (usernameTaken) {
      return c.json({ message: "Username sudah digunakan" }, 409);
    }
  }

  if (
    parsed.data.email &&
    parsed.data.email !== (existing.email ?? undefined)
  ) {
    const [emailTaken] = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.email, parsed.data.email.trim().toLowerCase()))
      .limit(1);
    if (emailTaken && emailTaken.id !== existing.id) {
      return c.json({ message: "Email sudah digunakan" }, 409);
    }
  }

  const nextIsActive =
    parsed.data.isActive === undefined
      ? existing.isActive
      : parsed.data.isActive;

  const nextPasswordHash =
    parsed.data.password !== undefined
      ? await Bun.password.hash(parsed.data.password)
      : existing.passwordHash;

  if (existing.id === authUser.id && nextIsActive === false) {
    return c.json({ message: "Tidak bisa menonaktifkan akun sendiri" }, 400);
  }

  if (existing.role === "guru" && nextIsActive === false) {
    const [activeGuruCount] = await db
      .select({ count: count() })
      .from(users)
      .where(and(eq(users.role, "guru"), eq(users.isActive, true)));

    if (Number(activeGuruCount?.count ?? 0) <= 1) {
      return c.json(
        { message: "Tidak bisa menonaktifkan guru aktif terakhir" },
        400,
      );
    }
  }

  const patch = {
    ...(parsed.data.name !== undefined ? { name: parsed.data.name } : {}),
    ...(parsed.data.username !== undefined
      ? { username: parsed.data.username }
      : {}),
    ...(parsed.data.email !== undefined
      ? { email: parsed.data.email.trim().toLowerCase() }
      : {}),
    ...(parsed.data.schoolNpsn !== undefined
      ? {
        schoolNpsn:
          nextRole === "siswa" || nextRole === "guru"
            ? (parsed.data.schoolNpsn ?? null)
            : null,
      }
      : {}),
    ...(parsed.data.role !== undefined ? { role: parsed.data.role } : {}),
    ...(parsed.data.className !== undefined
      ? {
        className:
          nextRole === "siswa" ? (parsed.data.className ?? null) : null,
      }
      : {}),
    ...(parsed.data.password !== undefined
      ? { passwordHash: nextPasswordHash }
      : {}),
    ...(parsed.data.isActive !== undefined
      ? { isActive: parsed.data.isActive }
      : {}),
  };

  const [updated] = await db
    .update(users)
    .set(patch)
    .where(eq(users.id, id))
    .returning({
      id: users.id,
      name: users.name,
      username: users.username,
      email: users.email,
      schoolNpsn: users.schoolNpsn,
      role: users.role,
      className: users.className,
      isActive: users.isActive,
      points: users.points,
    });

  await writeAdminAuditLog(
    c.get("user").id,
    "update_user",
    "user",
    updated?.id || id,
    `role=${updated?.role ?? nextRole}`,
  );

  return c.json({ message: "User berhasil diperbarui", data: updated });
});

adminRoutes.delete("/users/:id", async (c) => {
  const authUser = c.get("user");
  const id = Number(c.req.param("id"));
  if (Number.isNaN(id) || id < 1) {
    return c.json({ message: "ID user tidak valid" }, 400);
  }

  const [existing] = await db
    .select({ id: users.id, role: users.role, isActive: users.isActive })
    .from(users)
    .where(eq(users.id, id))
    .limit(1);

  if (!existing) {
    return c.json({ message: "User tidak ditemukan" }, 404);
  }

  if (existing.id === authUser.id) {
    return c.json({ message: "Tidak bisa menghapus akun sendiri" }, 400);
  }

  if (existing.role === "guru" && existing.isActive) {
    const [activeGuruCount] = await db
      .select({ count: count() })
      .from(users)
      .where(and(eq(users.role, "guru"), eq(users.isActive, true)));

    if (Number(activeGuruCount?.count ?? 0) <= 1) {
      return c.json(
        { message: "Tidak bisa menghapus guru aktif terakhir" },
        400,
      );
    }
  }

  await db.update(users).set({ isActive: false }).where(eq(users.id, id));
  await writeAdminAuditLog(
    authUser.id,
    "deactivate_user",
    "user",
    id,
    null,
  );

  return c.json({ message: "User berhasil dinonaktifkan" });
});

adminRoutes.get("/stats", async (c) => {
  const className = c.req.query("className");
  const page = Number(c.req.query("page") ?? 1);
  const limit = Number(c.req.query("limit") ?? 10);
  const safePage = Math.max(1, page);
  const safeLimit = Math.min(Math.max(1, limit), 100);

  const filters = [eq(users.role, "siswa")];
  if (className) {
    filters.push(eq(users.className, className));
  }

  const whereClause = and(...filters);

  const [totalResult] = await db
    .select({ count: count() })
    .from(users)
    .where(whereClause);

  const studentList = await db
    .select({
      id: users.id,
      name: users.name,
      username: users.username,
      className: users.className,
      points: users.points,
      isActive: users.isActive,
    })
    .from(users)
    .where(whereClause)
    .limit(safeLimit)
    .offset((safePage - 1) * safeLimit);

  const totalStudents = Number(totalResult?.count ?? 0);

  return c.json({
    summary: {
      totalStudents,
      className: className ?? "Semua",
    },
    pagination: {
      page: safePage,
      limit: safeLimit,
      totalItems: totalStudents,
      totalPages: Math.ceil(totalStudents / safeLimit),
    },
    students: studentList,
  });
});

adminRoutes.get("/leaderboard", async (c) => {
  const className = c.req.query("className");
  const limit = Number(c.req.query("limit") ?? 10);
  const page = Number(c.req.query("page") ?? 1);
  const safePage = Math.max(1, page);
  const safeLimit = Math.min(Math.max(1, limit), 100);

  const filters = [eq(users.role, "siswa"), eq(users.isActive, true)];
  if (className) {
    filters.push(eq(users.className, className));
  }

  const whereClause = and(...filters);

  const [totalResult] = await db
    .select({ count: count() })
    .from(users)
    .where(whereClause);

  const totalItems = Number(totalResult?.count ?? 0);

  const rows = await db
    .select({
      id: users.id,
      name: users.name,
      username: users.username,
      className: users.className,
      points: users.points,
    })
    .from(users)
    .where(whereClause)
    .orderBy(desc(users.points))
    .limit(safeLimit)
    .offset((safePage - 1) * safeLimit);

  const leaderboardRows = rows.map((row, index) => ({
    rank: (safePage - 1) * safeLimit + index + 1,
    ...row,
  }));

  return c.json({
    pagination: {
      page: safePage,
      limit: safeLimit,
      totalItems,
      totalPages: Math.ceil(totalItems / safeLimit),
    },
    leaderboard: leaderboardRows,
  });
});

adminRoutes.get("/habits", async (c) => {
  const includeInactive =
    c.req.query("includeInactive") === "true" ||
    c.req.query("showInactive") === "true";
  const rows = includeInactive
    ? await db
      .select({
        id: habits.id,
        name: habits.name,
        category: habits.category,
        description: habits.description,
        points: habits.points,
        requiresProof: habits.requiresProof,
        isActive: habits.isActive,
        createdAt: habits.createdAt,
      })
      .from(habits)
      .orderBy(desc(habits.id))
    : await db
      .select({
        id: habits.id,
        name: habits.name,
        category: habits.category,
        description: habits.description,
        points: habits.points,
        requiresProof: habits.requiresProof,
        isActive: habits.isActive,
        createdAt: habits.createdAt,
      })
      .from(habits)
      .where(eq(habits.isActive, true))
      .orderBy(desc(habits.id));

  return c.json({ habits: rows });
});

adminRoutes.post("/habits", async (c) => {
  const body = await c.req.json().catch(() => null);
  const parsed = createHabitSchema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      { message: "Payload tidak valid", errors: parsed.error.flatten() },
      400,
    );
  }

  const [created] = await db
    .insert(habits)
    .values({
      name: parsed.data.name.trim(),
      category: (parsed.data.category || "Umum").trim(),
      description: parsed.data.description?.trim() || null,
      points: parsed.data.points,
      requiresProof: parsed.data.requiresProof,
      isActive: true,
    })
    .returning({
      id: habits.id,
      name: habits.name,
      category: habits.category,
      description: habits.description,
      points: habits.points,
      requiresProof: habits.requiresProof,
      isActive: habits.isActive,
    });

  await writeAdminAuditLog(
    c.get("user").id,
    "create_habit",
    "habit",
    created?.id,
    created?.name || parsed.data.name,
  );

  return c.json({ message: "Habit berhasil ditambahkan", data: created }, 201);
});

adminRoutes.patch("/habits/:id", async (c) => {
  const id = Number(c.req.param("id"));
  if (Number.isNaN(id) || id < 1) {
    return c.json({ message: "ID habit tidak valid" }, 400);
  }

  const body = await c.req.json().catch(() => null);
  const parsed = updateHabitSchema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      { message: "Payload tidak valid", errors: parsed.error.flatten() },
      400,
    );
  }

  const [existing] = await db
    .select({ id: habits.id })
    .from(habits)
    .where(eq(habits.id, id))
    .limit(1);
  if (!existing) {
    return c.json({ message: "Habit tidak ditemukan" }, 404);
  }

  const patch = {
    ...(parsed.data.name !== undefined ? { name: parsed.data.name } : {}),
    ...(parsed.data.category !== undefined
      ? { category: parsed.data.category ?? "Umum" }
      : {}),
    ...(parsed.data.description !== undefined
      ? { description: parsed.data.description }
      : {}),
    ...(parsed.data.points !== undefined ? { points: parsed.data.points } : {}),
    ...(parsed.data.requiresProof !== undefined
      ? { requiresProof: parsed.data.requiresProof }
      : {}),
    ...(parsed.data.isActive !== undefined
      ? { isActive: parsed.data.isActive }
      : {}),
  };

  const [updated] = await db
    .update(habits)
    .set(patch)
    .where(eq(habits.id, id))
    .returning({
      id: habits.id,
      name: habits.name,
      category: habits.category,
      description: habits.description,
      points: habits.points,
      requiresProof: habits.requiresProof,
      isActive: habits.isActive,
    });

  await writeAdminAuditLog(
    c.get("user").id,
    "update_habit",
    "habit",
    updated?.id || id,
    updated?.name || null,
  );

  return c.json({ message: "Habit berhasil diperbarui", data: updated });
});

adminRoutes.delete("/habits/:id", async (c) => {
  const id = Number(c.req.param("id"));
  if (Number.isNaN(id) || id < 1) {
    return c.json({ message: "ID habit tidak valid" }, 400);
  }

  const [existing] = await db
    .select({ id: habits.id })
    .from(habits)
    .where(eq(habits.id, id))
    .limit(1);
  if (!existing) {
    return c.json({ message: "Habit tidak ditemukan" }, 404);
  }

  await db.update(habits).set({ isActive: false }).where(eq(habits.id, id));
  await writeAdminAuditLog(c.get("user").id, "deactivate_habit", "habit", id, null);

  return c.json({ message: "Habit berhasil dinonaktifkan" });
});

adminRoutes.get("/verifications/pending", async (c) => {
  const className = c.req.query("className");
  const rows = await db
    .select({
      logId: habitLogs.id,
      logDate: habitLogs.logDate,
      note: habitLogs.note,
      proofUrl: habitLogs.proofUrl,
      verificationStatus: habitLogs.verificationStatus,
      studentId: users.id,
      studentName: users.name,
      studentUsername: users.username,
      studentClassName: users.className,
      habitId: habits.id,
      habitName: habits.name,
      habitPoints: habits.points,
    })
    .from(habitLogs)
    .innerJoin(users, eq(users.id, habitLogs.userId))
    .innerJoin(habits, eq(habits.id, habitLogs.habitId))
    .where(
      and(
        eq(habitLogs.verificationStatus, "pending"),
        eq(users.role, "siswa"),
        eq(users.isActive, true),
        ...(className ? [eq(users.className, className)] : []),
      ),
    )
    .orderBy(desc(habitLogs.id));

  return c.json({
    total: rows.length,
    className: className ?? null,
    pending: rows,
  });
});

adminRoutes.patch("/verifications/:logId", async (c) => {
  const authUser = c.get("user");
  const logId = Number(c.req.param("logId"));
  if (Number.isNaN(logId) || logId < 1) {
    return c.json({ message: "ID log tidak valid" }, 400);
  }

  const body = await c.req.json().catch(() => null);
  const parsed = verifyHabitLogSchema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      { message: "Payload tidak valid", errors: parsed.error.flatten() },
      400,
    );
  }

  const [log] = await db
    .select({
      id: habitLogs.id,
      userId: habitLogs.userId,
      habitId: habitLogs.habitId,
      verificationStatus: habitLogs.verificationStatus,
      points: habits.points,
    })
    .from(habitLogs)
    .innerJoin(habits, eq(habits.id, habitLogs.habitId))
    .where(eq(habitLogs.id, logId))
    .limit(1);

  if (!log) {
    return c.json({ message: "Log tidak ditemukan" }, 404);
  }

  if (log.verificationStatus !== "pending") {
    return c.json({ message: "Log ini sudah diverifikasi sebelumnya" }, 409);
  }

  const nextStatus = parsed.data.action === "approve" ? "approved" : "rejected";
  const now = new Date();

  await db
    .update(habitLogs)
    .set({
      verificationStatus: nextStatus,
      verificationNote: parsed.data.note ?? null,
      verifiedBy: authUser.id,
      verifiedAt: now,
    })
    .where(eq(habitLogs.id, logId));

  if (nextStatus === "approved") {
    const [alreadyRewarded] = await db
      .select({ count: count() })
      .from(rewardEvents)
      .where(
        and(
          eq(rewardEvents.source, "habit_log"),
          eq(rewardEvents.referenceId, logId),
          eq(rewardEvents.userId, log.userId),
        ),
      );

    if (Number(alreadyRewarded?.count ?? 0) === 0) {
      await db
        .update(users)
        .set({ points: sql`${users.points} + ${log.points}` })
        .where(eq(users.id, log.userId));

      await db.insert(rewardEvents).values({
        userId: log.userId,
        source: "habit_log",
        points: log.points,
        referenceId: logId,
        createdAt: now,
      });
    }
  }

  return c.json({
    message:
      nextStatus === "approved" ? "Bukti berhasil disetujui" : "Bukti ditolak",
    data: {
      logId,
      verificationStatus: nextStatus,
      verificationNote: parsed.data.note ?? null,
      verifiedBy: authUser.id,
      verifiedAt: now,
    },
  });
});
