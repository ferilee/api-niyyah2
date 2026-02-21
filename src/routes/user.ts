import { Hono } from "hono";
import { and, count, eq } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db/client.ts";
import { habits, habitLogs, users } from "../db/schema.ts";
import { requireAuth } from "../middleware/auth.ts";
import type { AuthUser } from "../types.ts";
import {
  calculateCurrentStreak,
  getMonthlyLogCount,
  getTodayCompletionCount,
  todayISODate,
} from "../db/init.ts";
import { fetchSchoolProfileByNpsn } from "../utils/school-api.ts";

type Variables = { user: AuthUser };

export const userRoutes = new Hono<{ Variables: Variables }>();

userRoutes.use("*", requireAuth);

const patchProfileSchema = z
  .object({
    name: z.string().min(2).max(80).optional(),
    fullName: z.string().min(2).max(80).optional(),
    schoolNpsn: z.string().min(3).max(20).optional(),
    npsn: z.string().min(3).max(20).optional(),
    className: z.string().min(1).max(40).optional(),
  })
  .passthrough();

userRoutes.get("/profile", async (c) => {
  const authUser = c.get("user");

  const [user] = await db
    .select({
      id: users.id,
      name: users.name,
      username: users.username,
      email: users.email,
      schoolNpsn: users.schoolNpsn,
      role: users.role,
      className: users.className,
      points: users.points,
    })
    .from(users)
    .where(eq(users.id, authUser.id))
    .limit(1);

  if (!user) {
    return c.json({ message: "User tidak ditemukan" }, 404);
  }

  const [activeHabitCount] = await db
    .select({ count: count() })
    .from(habits)
    .where(eq(habits.isActive, true));

  const [todayDoneCount] = await db
    .select({ count: count() })
    .from(habitLogs)
    .where(
      and(
        eq(habitLogs.userId, authUser.id),
        eq(habitLogs.logDate, todayISODate()),
      ),
    );

  const monthlyLogs = await getMonthlyLogCount(authUser.id);
  const streak = await calculateCurrentStreak(authUser.id);
  const schoolProfile = user.schoolNpsn
    ? await fetchSchoolProfileByNpsn(user.schoolNpsn)
    : null;

  return c.json({
    user,
    schoolProfile,
    progress: {
      todayCompleted: Number(todayDoneCount?.count ?? 0),
      totalHabitsToday: Number(activeHabitCount?.count ?? 0),
      monthlyLogs,
      streak,
    },
  });
});

userRoutes.patch("/profile", async (c) => {
  const authUser = c.get("user");
  const json = await c.req.json().catch(() => null);
  const parsed = patchProfileSchema.safeParse(json);

  if (!parsed.success) {
    return c.json(
      { message: "Payload tidak valid", errors: parsed.error.flatten() },
      400,
    );
  }

  const payload = parsed.data;
  const nextName = payload.name ?? payload.fullName;
  const nextSchoolNpsn = payload.schoolNpsn ?? payload.npsn;

  const updates: {
    name?: string;
    schoolNpsn?: string | null;
    className?: string | null;
  } = {};

  if (nextName !== undefined) {
    updates.name = nextName.trim();
  }
  if (nextSchoolNpsn !== undefined) {
    updates.schoolNpsn = nextSchoolNpsn.trim();
  }
  if (payload.className !== undefined) {
    updates.className = payload.className.trim();
  }

  if (Object.keys(updates).length === 0) {
    return c.json(
      { message: "Tidak ada data profil yang dapat diperbarui" },
      400,
    );
  }

  const [updated] = await db
    .update(users)
    .set(updates)
    .where(eq(users.id, authUser.id))
    .returning({
      id: users.id,
      name: users.name,
      username: users.username,
      email: users.email,
      schoolNpsn: users.schoolNpsn,
      role: users.role,
      className: users.className,
      points: users.points,
    });

  if (!updated) {
    return c.json({ message: "User tidak ditemukan" }, 404);
  }

  return c.json({
    message: "Profil berhasil diperbarui",
    user: updated,
  });
});

userRoutes.get("/leaderboard", async (c) => {
  const authUser = c.get("user");
  const className = c.req.query("className")?.trim();

  const rows = await db
    .select({
      id: users.id,
      name: users.name,
      username: users.username,
      className: users.className,
      points: users.points,
    })
    .from(users)
    .where(
      and(
        eq(users.role, "siswa"),
        eq(users.isActive, true),
        ...(className ? [eq(users.className, className)] : []),
      ),
    );

  const sorted = rows
    .slice()
    .sort(
      (a, b) =>
        Number(b.points ?? 0) - Number(a.points ?? 0) ||
        a.name.localeCompare(b.name),
    )
    .map((item, index) => ({
      rank: index + 1,
      ...item,
    }));

  const myIndex = sorted.findIndex((item) => item.id === authUser.id);
  const myRank = myIndex >= 0 ? myIndex + 1 : null;

  return c.json({
    className: className ?? null,
    top10: sorted.slice(0, 10),
    myRank,
    totalParticipants: sorted.length,
  });
});

userRoutes.get("/summary", async (c) => {
  const authUser = c.get("user");
  const streak = await calculateCurrentStreak(authUser.id);
  const todayDone = await getTodayCompletionCount(authUser.id);
  return c.json({ streak, todayDone });
});
