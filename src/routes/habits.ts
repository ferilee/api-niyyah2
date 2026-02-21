import { Hono } from "hono";
import { and, count, eq } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db/client.ts";
import { addPoints, todayISODate } from "../db/init.ts";
import { habits, habitLogs } from "../db/schema.ts";
import { requireAuth, requireRole } from "../middleware/auth.ts";
import type { AuthUser } from "../types.ts";
import { uploadHabitProofToMinio } from "../utils/minio.ts";

type Variables = { user: AuthUser };

const logHabitSchema = z.object({
  habitId: z.number().int().positive(),
  note: z.string().max(300).optional(),
  proofUrl: z.string().url().max(1000).optional(),
  logDate: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/)
    .optional(),
});

export const habitRoutes = new Hono<{ Variables: Variables }>();

habitRoutes.use("*", requireAuth);

habitRoutes.post(
  "/proof/upload",
  requireRole("siswa", "guru", "support", "editor"),
  async (c) => {
    const user = c.get("user");
    const formData = await c.req.formData().catch(() => null);
    if (!formData) {
      return c.json({ message: "Payload form-data tidak valid" }, 400);
    }

    const habitIdRaw = String(formData.get("habitId") ?? "");
    const habitId = Number(habitIdRaw);
    if (Number.isNaN(habitId) || habitId < 1) {
      return c.json({ message: "habitId tidak valid" }, 400);
    }

    const file = formData.get("file");
    if (!(file instanceof File)) {
      return c.json({ message: "File bukti wajib diunggah" }, 400);
    }

    if (!file.type.startsWith("image/")) {
      return c.json({ message: "Bukti harus berupa gambar" }, 400);
    }

    const maxBytes = 5 * 1024 * 1024;
    if (file.size > maxBytes) {
      return c.json({ message: "Ukuran file maksimal 5MB" }, 400);
    }

    const [habit] = await db
      .select({ id: habits.id, requiresProof: habits.requiresProof })
      .from(habits)
      .where(and(eq(habits.id, habitId), eq(habits.isActive, true)))
      .limit(1);

    if (!habit) {
      return c.json({ message: "Habit tidak ditemukan atau nonaktif" }, 404);
    }

    const bytes = new Uint8Array(await file.arrayBuffer());
    const uploaded = await uploadHabitProofToMinio({
      userId: user.id,
      habitId: habit.id,
      bytes,
      contentType: file.type || "application/octet-stream",
    });

    return c.json({
      message: "Bukti berhasil diunggah",
      data: uploaded,
    });
  },
);

habitRoutes.get("/", async (c) => {
  const user = c.get("user");
  const date = todayISODate();

  const habitList = await db
    .select({
      id: habits.id,
      name: habits.name,
      description: habits.description,
      points: habits.points,
      requiresProof: habits.requiresProof,
    })
    .from(habits)
    .where(eq(habits.isActive, true));

  const loggedToday = await db
    .select({
      habitId: habitLogs.habitId,
      verificationStatus: habitLogs.verificationStatus,
    })
    .from(habitLogs)
    .where(and(eq(habitLogs.userId, user.id), eq(habitLogs.logDate, date)));

  const logMap = new Map(
    loggedToday.map((item) => [item.habitId, item.verificationStatus]),
  );

  return c.json({
    date,
    habits: habitList.map((habit) => ({
      ...habit,
      completed: logMap.has(habit.id),
      verificationStatus: logMap.get(habit.id) ?? null,
    })),
  });
});

habitRoutes.post(
  "/log",
  requireRole("siswa", "guru", "support", "editor"),
  async (c) => {
    const user = c.get("user");
    const body = await c.req.json().catch(() => null);
    const parsed = logHabitSchema.safeParse(body);

    if (!parsed.success) {
      return c.json(
        { message: "Payload tidak valid", errors: parsed.error.flatten() },
        400,
      );
    }

    const logDate = parsed.data.logDate ?? todayISODate();
    if (logDate > todayISODate()) {
      return c.json({ message: "Tanggal log tidak boleh di masa depan" }, 400);
    }

    const [habit] = await db
      .select({
        id: habits.id,
        points: habits.points,
        requiresProof: habits.requiresProof,
      })
      .from(habits)
      .where(and(eq(habits.id, parsed.data.habitId), eq(habits.isActive, true)))
      .limit(1);

    if (!habit) {
      return c.json({ message: "Habit tidak ditemukan atau nonaktif" }, 404);
    }

    const [alreadyLogged] = await db
      .select({ count: count() })
      .from(habitLogs)
      .where(
        and(
          eq(habitLogs.userId, user.id),
          eq(habitLogs.habitId, parsed.data.habitId),
          eq(habitLogs.logDate, logDate),
        ),
      );

    if (Number(alreadyLogged?.count ?? 0) > 0) {
      return c.json({ message: "Habit sudah dicatat untuk tanggal ini" }, 409);
    }

    if (habit.requiresProof && !parsed.data.proofUrl) {
      return c.json({ message: "Habit ini wajib upload bukti foto" }, 400);
    }

    const verificationStatus = habit.requiresProof ? "pending" : "approved";

    const [inserted] = await db
      .insert(habitLogs)
      .values({
        userId: user.id,
        habitId: parsed.data.habitId,
        logDate,
        note: parsed.data.note,
        proofUrl: parsed.data.proofUrl ?? null,
        verificationStatus,
        verificationNote: null,
        verifiedBy: habit.requiresProof ? null : user.id,
        verifiedAt: habit.requiresProof ? null : new Date(),
      })
      .returning({ id: habitLogs.id });

    if (!habit.requiresProof) {
      await addPoints(user.id, habit.points, "habit_log", inserted.id);
    }

    return c.json(
      {
        message: habit.requiresProof
          ? "Habit dicatat, menunggu verifikasi guru"
          : "Habit berhasil dicatat",
        data: {
          logId: inserted.id,
          habitId: parsed.data.habitId,
          logDate,
          pointsEarned: habit.requiresProof ? 0 : habit.points,
          verificationStatus,
        },
      },
      201,
    );
  },
);
