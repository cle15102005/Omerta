import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import mongoose from 'mongoose';
import mongoSanitize from 'express-mongo-sanitize';
import pinoHttp from 'pino-http';
import { PORT, MONGO_URI, CORS_ORIGIN, BODY_LIMIT } from './env';

import authRouter  from './routes/auth.routes';
import vaultRouter from './routes/vault.routes';
import sharedVaultRouter from './routes/shared-vault.routes';

const app = express();

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(express.json({ limit: BODY_LIMIT })); // configurable via BODY_LIMIT env var
app.use(cookieParser());
app.use(mongoSanitize());  // strips $ and . from req.body/params/query — blocks NoSQL injection
app.use(pinoHttp());       // structured JSON request logging (method, url, status, responseTime)

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api/auth',  authRouter);
app.use('/api/vault', vaultRouter);
app.use('/api/shared-vaults', sharedVaultRouter);

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function bootstrap() {
  await mongoose.connect(MONGO_URI);
  console.log('[DB] MongoDB connected');

  app.listen(PORT, () => {
    console.log(`[Server] Omerta backend running on http://localhost:${PORT}`);
  });
}

bootstrap().catch((err) => {
  console.error('[Fatal]', err);
  process.exit(1);
});
