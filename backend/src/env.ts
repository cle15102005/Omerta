// ── Helpers ───────────────────────────────────────────────────────────────────

function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`[Config] Required environment variable "${key}" is not set`);
  return value;
}

function intEnv(key: string, defaultValue: number): number {
  const raw = process.env[key];
  if (!raw) return defaultValue;
  const parsed = parseInt(raw, 10);
  if (isNaN(parsed)) throw new Error(`[Config] "${key}" must be an integer, got: "${raw}"`);
  return parsed;
}

// ── Required secrets (no defaults — must be set explicitly) ───────────────────

export const JWT_SECRET  = requireEnv('JWT_SECRET');
export const MONGO_URI   = requireEnv('MONGO_URI');

// ── Server ────────────────────────────────────────────────────────────────────

export const PORT        = intEnv('PORT', 3000);
export const NODE_ENV    = process.env.NODE_ENV ?? 'development';
export const CORS_ORIGIN = process.env.CORS_ORIGIN ?? 'http://localhost:5173';

// ── JWT / Session ─────────────────────────────────────────────────────────────

/** JWT token lifetime. Also controls cookie maxAge. Examples: '24h', '7d', '1h' */
export const JWT_EXPIRY      = process.env.JWT_EXPIRY ?? '24h';

/** Cookie maxAge in ms — derived from JWT_EXPIRY for consistency */
export function jwtExpiryMs(): number {
  const raw = JWT_EXPIRY;
  const match = raw.match(/^(\d+)(h|d|m)$/);
  if (!match) return 24 * 60 * 60 * 1000; // fallback 24h
  const n = parseInt(match[1], 10);
  if (match[2] === 'h') return n * 60 * 60 * 1000;
  if (match[2] === 'd') return n * 24 * 60 * 60 * 1000;
  if (match[2] === 'm') return n * 60 * 1000;
  return 24 * 60 * 60 * 1000;
}

// ── Bcrypt ────────────────────────────────────────────────────────────────────

/** bcrypt hash rounds. Higher = slower but more secure. 10–12 is standard. */
export const BCRYPT_ROUNDS = intEnv('BCRYPT_ROUNDS', 12);

// ── Account lockout ───────────────────────────────────────────────────────────

/** Number of consecutive failed logins before account is locked */
export const LOCKOUT_MAX_ATTEMPTS  = intEnv('LOCKOUT_MAX_ATTEMPTS', 5);

/** How long (minutes) an account stays locked after too many failures */
export const LOCKOUT_DURATION_MIN  = intEnv('LOCKOUT_DURATION_MIN', 15);

/** Derived ms value for use in Date arithmetic */
export const LOCKOUT_DURATION_MS   = LOCKOUT_DURATION_MIN * 60 * 1000;

// ── Rate limiting ─────────────────────────────────────────────────────────────

/** Max login/recover attempts per IP per window */
export const RATE_AUTH_MAX         = intEnv('RATE_AUTH_MAX', 5);

/** Rate limit window for login/recover (minutes) */
export const RATE_AUTH_WINDOW_MIN  = intEnv('RATE_AUTH_WINDOW_MIN', 15);

/** Max salt lookups per IP per minute */
export const RATE_SALT_MAX         = intEnv('RATE_SALT_MAX', 20);

/** Max new account registrations per IP per hour */
export const RATE_REGISTER_MAX     = intEnv('RATE_REGISTER_MAX', 3);

// ── Request body ──────────────────────────────────────────────────────────────

/** Maximum allowed request body size. Keep small to prevent payload-based DoS. */
export const BODY_LIMIT            = process.env.BODY_LIMIT ?? '10mb';

// ── Vault ─────────────────────────────────────────────────────────────────────

/** How many previous versions to keep per vault item (git-like history) */
export const VAULT_HISTORY_LIMIT   = intEnv('VAULT_HISTORY_LIMIT', 10);

