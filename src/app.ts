import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { authRoutes } from "./routes/auth.ts";
import { userRoutes } from "./routes/user.ts";
import { habitRoutes } from "./routes/habits.ts";
import { adminRoutes } from "./routes/admin.ts";

export function createApp() {
  const app = new Hono();

  app.use("*", logger());
  app.use(
    "*",
    cors({
      origin: ["http://localhost:7001", "http://127.0.0.1:7001"],
      allowHeaders: ["Content-Type", "Authorization"],
      allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    }),
  );

  app.get("/", (c) => {
    return c.json({
      name: "API Niyyah",
      status: "ok",
      docs: "Lihat README.md untuk dokumentasi lengkap endpoint.",
    });
  });

  app.route("/auth", authRoutes);
  app.route("/user", userRoutes);
  app.route("/habits", habitRoutes);
  app.route("/admin", adminRoutes);

  app.notFound((c) => c.json({ message: "Endpoint tidak ditemukan" }, 404));

  app.onError((err, c) => {
    console.error(err);
    return c.json({ message: "Terjadi kesalahan pada server" }, 500);
  });

  return app;
}
