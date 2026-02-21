import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Database } from 'bun:sqlite';
import { drizzle } from 'drizzle-orm/bun-sqlite';

const dbPath = process.env.DB_PATH ?? './database.sqlite';
const dbDir = dirname(dbPath);

if (dbDir && dbDir !== '.') {
  mkdirSync(dbDir, { recursive: true });
}

export const sqlite = new Database(dbPath, { create: true });
export const db = drizzle(sqlite);
