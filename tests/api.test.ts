import { afterAll, beforeAll, expect, test } from "bun:test";
import { existsSync, rmSync } from "node:fs";

const TEST_DB_PATH = "./test.sqlite";

type ApiServer = {
  fetch: (request: Request) => Promise<Response>;
};

let api: ApiServer;

function cleanupTestDb() {
  for (const path of [
    TEST_DB_PATH,
    `${TEST_DB_PATH}-shm`,
    `${TEST_DB_PATH}-wal`,
  ]) {
    if (existsSync(path)) {
      rmSync(path);
    }
  }
}

async function requestJson(
  path: string,
  init: RequestInit & { token?: string } = {},
): Promise<{ status: number; body: any }> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (init.token) {
    headers.set("Authorization", `Bearer ${init.token}`);
  }

  const res = await api.fetch(
    new Request(`http://localhost:3001${path}`, {
      ...init,
      headers,
    }),
  );

  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  return { status: res.status, body };
}

beforeAll(async () => {
  cleanupTestDb();

  process.env.DB_PATH = TEST_DB_PATH;
  process.env.JWT_SECRET = "test-secret";
  process.env.PORT = "3001";
  process.env.OTP_DEBUG_RETURN_CODE = "true";
  process.env.OTP_DEBUG_FIXED_CODE = "123456";
  process.env.NODE_ENV = "test";

  const mod = await import("../src/index.ts");
  api = mod.default;
});

afterAll(() => {
  cleanupTestDb();
});

test("auth, habit flow, rbac, admin users management, filters, and habit CRUD", async () => {
  const guruLogin = await requestJson("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username: "guru1", password: "guru123" }),
  });
  expect(guruLogin.status).toBe(403);

  const requestOtpGuru = await requestJson("/auth/otp/request", {
    method: "POST",
    body: JSON.stringify({ email: "guru1@example.com" }),
  });
  expect(requestOtpGuru.status).toBe(200);
  expect(requestOtpGuru.body.debugCode).toBe("123456");

  const verifyOtpGuru = await requestJson("/auth/otp/verify", {
    method: "POST",
    body: JSON.stringify({ email: "guru1@example.com", code: "123456" }),
  });
  expect(verifyOtpGuru.status).toBe(200);
  const guruToken = verifyOtpGuru.body.token as string;

  const siswaLoginPassword = await requestJson("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username: "siswa1", password: "siswa123" }),
  });
  expect(siswaLoginPassword.status).toBe(403);

  const requestOtp = await requestJson("/auth/otp/request", {
    method: "POST",
    body: JSON.stringify({ email: "siswa1@example.com" }),
  });
  expect(requestOtp.status).toBe(200);
  expect(requestOtp.body.debugCode).toBe("123456");

  const verifyOtp = await requestJson("/auth/otp/verify", {
    method: "POST",
    body: JSON.stringify({ email: "siswa1@example.com", code: "123456" }),
  });
  expect(verifyOtp.status).toBe(200);
  const siswaToken = verifyOtp.body.token as string;

  const patchSiswaProfile = await requestJson("/user/profile", {
    method: "PATCH",
    token: siswaToken,
    body: JSON.stringify({
      fullName: "Siswa Ferilee",
      npsn: "20521455",
      nisn: "1234567890",
      gender: "L",
      schoolName: "SMKN PASIRIAN",
    }),
  });
  expect(patchSiswaProfile.status).toBe(200);
  expect(patchSiswaProfile.body.user.name).toBe("Siswa Ferilee");
  expect(patchSiswaProfile.body.user.schoolNpsn).toBe("20521455");

  const requestOtpNewEmail = await requestJson("/auth/otp/request", {
    method: "POST",
    body: JSON.stringify({ email: "baru.siswa@example.com" }),
  });
  expect(requestOtpNewEmail.status).toBe(200);
  expect(requestOtpNewEmail.body.debugCode).toBe("123456");

  const verifyOtpNewEmail = await requestJson("/auth/otp/verify", {
    method: "POST",
    body: JSON.stringify({ email: "baru.siswa@example.com", code: "123456" }),
  });
  expect(verifyOtpNewEmail.status).toBe(200);
  expect(verifyOtpNewEmail.body.user.role).toBe("siswa");
  expect(verifyOtpNewEmail.body.user.email).toBe("baru.siswa@example.com");

  const habitList = await requestJson("/habits", {
    method: "GET",
    token: siswaToken,
  });
  expect(habitList.status).toBe(200);
  expect(Array.isArray(habitList.body.habits)).toBe(true);
  expect(habitList.body.habits.length).toBeGreaterThan(0);

  const selectedHabitId = habitList.body.habits[0].id as number;

  const logHabit = await requestJson("/habits/log", {
    method: "POST",
    token: siswaToken,
    body: JSON.stringify({ habitId: selectedHabitId, note: "dari test" }),
  });
  expect(logHabit.status).toBe(201);
  expect(logHabit.body.data.pointsEarned).toBeGreaterThan(0);

  const duplicateLog = await requestJson("/habits/log", {
    method: "POST",
    token: siswaToken,
    body: JSON.stringify({ habitId: selectedHabitId }),
  });
  expect(duplicateLog.status).toBe(409);

  const siswaProfile = await requestJson("/user/profile", {
    method: "GET",
    token: siswaToken,
  });
  expect(siswaProfile.status).toBe(200);
  expect(siswaProfile.body.user.points).toBeGreaterThan(0);
  expect(siswaProfile.body.progress.todayCompleted).toBeGreaterThanOrEqual(1);

  const siswaTryAdmin = await requestJson("/admin/stats", {
    method: "GET",
    token: siswaToken,
  });
  expect(siswaTryAdmin.status).toBe(403);

  const createNewStudent = await requestJson("/admin/users", {
    method: "POST",
    token: guruToken,
    body: JSON.stringify({
      name: "Siswa Dua",
      username: "siswa2",
      email: "siswa2@example.com",
      password: "siswa234",
      role: "siswa",
      className: "7B",
    }),
  });
  expect(createNewStudent.status).toBe(201);
  expect(createNewStudent.body.data.username).toBe("siswa2");

  const listUsers = await requestJson(
    "/admin/users?role=siswa&className=7B&q=siswa&page=1&limit=10",
    {
      method: "GET",
      token: guruToken,
    },
  );
  expect(listUsers.status).toBe(200);
  expect(listUsers.body.pagination.page).toBe(1);
  expect(Array.isArray(listUsers.body.users)).toBe(true);
  expect(listUsers.body.users.some((u: any) => u.username === "siswa2")).toBe(
    true,
  );

  const siswa2Id = createNewStudent.body.data.id as number;

  const patchStudent = await requestJson(`/admin/users/${siswa2Id}`, {
    method: "PATCH",
    token: guruToken,
    body: JSON.stringify({ name: "Siswa Dua Update", className: "8A" }),
  });
  expect(patchStudent.status).toBe(200);
  expect(patchStudent.body.data.name).toBe("Siswa Dua Update");
  expect(patchStudent.body.data.className).toBe("8A");

  const deleteStudent = await requestJson(`/admin/users/${siswa2Id}`, {
    method: "DELETE",
    token: guruToken,
  });
  expect(deleteStudent.status).toBe(200);

  const loginDeletedStudent = await requestJson("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username: "siswa2", password: "siswa234" }),
  });
  expect(loginDeletedStudent.status).toBe(403);

  const listInactiveUsers = await requestJson(
    "/admin/users?includeInactive=true&q=siswa2",
    {
      method: "GET",
      token: guruToken,
    },
  );
  expect(listInactiveUsers.status).toBe(200);
  const inactiveFound = listInactiveUsers.body.users.find(
    (u: any) => u.username === "siswa2",
  );
  expect(inactiveFound).toBeDefined();
  expect(inactiveFound.isActive).toBe(false);

  const adminStats = await requestJson(
    "/admin/stats?className=7A&page=1&limit=5",
    {
      method: "GET",
      token: guruToken,
    },
  );
  expect(adminStats.status).toBe(200);
  expect(adminStats.body.summary.totalStudents).toBeGreaterThanOrEqual(1);
  expect(adminStats.body.pagination.page).toBe(1);
  expect(Array.isArray(adminStats.body.students)).toBe(true);

  const createHabit = await requestJson("/admin/habits", {
    method: "POST",
    token: guruToken,
    body: JSON.stringify({
      name: "Merapikan Kelas",
      description: "Merapikan kelas sebelum pulang",
      points: 12,
    }),
  });
  expect(createHabit.status).toBe(201);
  const createdHabitId = createHabit.body.data.id as number;

  const updateHabit = await requestJson(`/admin/habits/${createdHabitId}`, {
    method: "PATCH",
    token: guruToken,
    body: JSON.stringify({ points: 20, isActive: true }),
  });
  expect(updateHabit.status).toBe(200);
  expect(updateHabit.body.data.points).toBe(20);

  const deleteHabit = await requestJson(`/admin/habits/${createdHabitId}`, {
    method: "DELETE",
    token: guruToken,
  });
  expect(deleteHabit.status).toBe(200);

  const listAllHabits = await requestJson("/admin/habits?showInactive=true", {
    method: "GET",
    token: guruToken,
  });
  expect(listAllHabits.status).toBe(200);
  const found = listAllHabits.body.habits.find(
    (h: any) => h.id === createdHabitId,
  );
  expect(found).toBeDefined();
  expect(found.isActive).toBe(false);

  const leaderboard = await requestJson(
    "/admin/leaderboard?limit=5&page=1&sort=points&className=7A",
    {
      method: "GET",
      token: guruToken,
    },
  );
  expect(leaderboard.status).toBe(200);
  expect(leaderboard.body.pagination.totalItems).toBeGreaterThanOrEqual(1);
  expect(Array.isArray(leaderboard.body.leaderboard)).toBe(true);
});
