import { createApp } from './app.ts';
import { initializeDatabase } from './db/init.ts';
import { env } from './utils/env.ts';

const app = createApp();

await initializeDatabase();

const publicHost = env.host === '0.0.0.0' ? 'localhost' : env.host;
console.log(`API Niyyah berjalan di http://${publicHost}:${env.port}`);

export { app };

export default {
  host: env.host,
  port: env.port,
  fetch: app.fetch
};
