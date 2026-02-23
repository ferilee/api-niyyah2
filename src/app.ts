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
      origin: "*",
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

  app.get("/api", (c) => {
    return c.json({
      name: "API Niyyah",
      status: "ok",
      docs: "Lihat README.md untuk dokumentasi lengkap endpoint.",
    });
  });

  const mountCoreRoutes = (prefix = "") => {
    app.route(`${prefix}/auth`, authRoutes);
    app.route(`${prefix}/user`, userRoutes);
    app.route(`${prefix}/habits`, habitRoutes);
    app.route(`${prefix}/admin`, adminRoutes);
  };

  mountCoreRoutes("");
  mountCoreRoutes("/api");

  app.notFound((c) => c.json({ message: "Endpoint tidak ditemukan" }, 404));

  app.onError((err, c) => {
    console.error(err);
    return c.json({ message: "Terjadi kesalahan pada server" }, 500);
  });

  return app;
}
