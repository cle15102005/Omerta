import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import {
  NODE_ENV,
  RATE_AUTH_MAX, RATE_AUTH_WINDOW_MIN,
  RATE_SALT_MAX,
  RATE_REGISTER_MAX,
  jwtExpiryMs,
} from '../env';
import { User } from '../entities/User.entity';
import { RegisterDto, LoginDto, RecoverDto, RecoveryDataRequestDto } from '../dtos/auth.dto';
import {
  registerUser, loginUser, getSalt, getRecoverySalt,
  getEncryptedPEKBackup, getRecoveryData, resetPassword, generateToken, deleteAccount
} from '../services/auth.service';
import { authMiddleware } from '../middleware/auth.middleware';

const router = Router();

// ── Rate limiters ─────────────────────────────────────────────────────────────

/** Login / recover: configurable via RATE_AUTH_MAX + RATE_AUTH_WINDOW_MIN */
const authLimiter = rateLimit({
  windowMs:               RATE_AUTH_WINDOW_MIN * 60 * 1000,
  max:                    RATE_AUTH_MAX,
  standardHeaders:        true,
  legacyHeaders:          false,
  skipSuccessfulRequests: true,
  message:                { message: `Too many attempts. Try again in ${RATE_AUTH_WINDOW_MIN} minutes.` },
});

/** Salt lookups: configurable via RATE_SALT_MAX */
const saltLimiter = rateLimit({
  windowMs:        60 * 1000,
  max:             RATE_SALT_MAX,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { message: 'Too many requests. Slow down.' },
});

/** Register: configurable via RATE_REGISTER_MAX */
const registerLimiter = rateLimit({
  windowMs:        60 * 60 * 1000,
  max:             RATE_REGISTER_MAX,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { message: 'Too many accounts created from this IP.' },
});

// POST /api/auth/register
router.post('/register', registerLimiter, async (req: Request, res: Response) => {
  const parsed = RegisterDto.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ message: 'Invalid input', errors: parsed.error.flatten() }); return; }

  try {
    await registerUser(parsed.data);
    res.status(201).json({ message: 'Account created' });
  } catch (err: any) {
    if (err.message === 'EMAIL_TAKEN') { res.status(409).json({ message: 'Email already in use' }); return; }
    console.error('[Auth] Register error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/auth/salt/:email  — client needs salt BEFORE login to run PBKDF2
router.get('/salt/:email', saltLimiter, async (req: Request, res: Response) => {
  const salt = await getSalt(req.params.email as string);
  if (!salt) { res.status(404).json({ message: 'User not found' }); return; }
  res.json({ salt });
});

// POST /api/auth/login
router.post('/login', authLimiter, async (req: Request, res: Response) => {
  const parsed = LoginDto.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ message: 'Invalid input' }); return; }

  const result = await loginUser(parsed.data);

  if (!result) {
    res.status(401).json({ message: 'Invalid credentials' });
    return;
  }

  if ('locked' in result) {
    const minutes = Math.ceil((result.retryAfter.getTime() - Date.now()) / 60000);
    res.status(423).json({
      message: `Account locked. Too many failed attempts. Try again in ${minutes} minute(s).`,
      retryAfter: result.retryAfter,
    });
    return;
  }

  const token = generateToken(result.payload);
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure:   NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge:   jwtExpiryMs(), // stays in sync with JWT_EXPIRY automatically
  });
  res.json({ message: 'Login successful', email: result.payload.email });
});

// POST /api/auth/logout
router.post('/logout', (_req: Request, res: Response) => {
  res.clearCookie('auth_token', { httpOnly: true, secure: NODE_ENV === 'production', sameSite: 'strict' });
  res.json({ message: 'Logged out' });
});

// GET /api/auth/me
router.get('/me', authMiddleware, async (req: Request, res: Response) => {
  const user = await User.findById(req.user?.userId);
  if (!user) { res.status(404).json({ message: 'User not found' }); return; }

  res.json({ 
    email: user.email, 
    userId: user._id,
    encryptedPrivateKey: user.encryptedPrivateKey,
    encryptedECDSAPrivateKey: user.encryptedECDSAPrivateKey,
    ecdsaPublicKey: user.ecdsaPublicKey
  });
});

// DELETE /api/auth/account
router.delete('/account', authMiddleware, async (req: Request, res: Response) => {
  const ok = await deleteAccount(req.user!.userId);
  if (!ok) { res.status(404).json({ message: 'User not found' }); return; }
  res.clearCookie('auth_token', { httpOnly: true, secure: NODE_ENV === 'production', sameSite: 'strict' });
  res.json({ message: 'Account deleted' });
});

// GET /api/auth/recovery-salt/:email  — for recovery code PBKDF2
router.get('/recovery-salt/:email', saltLimiter, async (req: Request, res: Response) => {
  const salt2 = await getRecoverySalt(req.params.email as string);
  if (!salt2) { res.status(404).json({ message: 'User not found' }); return; }
  res.json({ salt2 });
});

// GET /api/auth/pek-backup/:email  — returns encryptedPEKBackup for recovery flow
router.get('/pek-backup/:email', async (req: Request, res: Response) => {
  const backup = await getEncryptedPEKBackup(req.params.email as string);
  if (!backup) { res.status(404).json({ message: 'User not found' }); return; }
  res.json({ encryptedPEKBackup: backup });
});

// POST /api/auth/recovery-data
router.post('/recovery-data', authLimiter, async (req: Request, res: Response) => {
  const parsed = RecoveryDataRequestDto.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ message: 'Invalid input' }); return; }

  try {
    const data = await getRecoveryData(parsed.data.email, parsed.data.recoveryAuthHash);
    if (!data) { res.status(404).json({ message: 'User not found' }); return; }
    res.json(data);
  } catch (err: any) {
    if (err.message === 'INVALID_RECOVERY_HASH') {
      res.status(401).json({ message: 'Invalid recovery code' });
      return;
    }
    res.status(500).json({ message: 'Internal server error' });
  }
});

// POST /api/auth/recover  — set new master password after recovery code verification
router.post('/recover', authLimiter, async (req: Request, res: Response) => {
  const parsed = RecoverDto.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ message: 'Invalid input', error: parsed.error.issues }); return; }

  try {
    const ok = await resetPassword(parsed.data);
    if (!ok) { res.status(404).json({ message: 'User not found' }); return; }
    res.json({ message: 'Password reset successful' });
  } catch (err: any) {
    if (err.message === 'INVALID_RECOVERY_HASH') {
      res.status(401).json({ message: 'Invalid recovery code' });
      return;
    }
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/auth/public-keys/:email
// Returns the three key-bundle fields needed for the vault invite flow.
// Requires authentication — only logged-in users can fetch other users' public keys.
// Caller (Alice) MUST verify keySignature client-side before encrypting VEK with publicKey.
router.get('/public-keys/:email', authMiddleware, saltLimiter, async (req: Request, res: Response) => {
  const user = await User.findOne(
    { email: (req.params.email as string).toLowerCase() },
    'publicKey ecdsaPublicKey keySignature'  // only expose public material
  );
  if (!user) { res.status(404).json({ message: 'User not found' }); return; }

  res.json({
    publicKey:      user.publicKey,       // RSA-OAEP public key PEM
    ecdsaPublicKey: user.ecdsaPublicKey,  // ECDSA P-256 public key (base64 JWK)
    keySignature:   user.keySignature,    // ECDSA_Sign(ecdsaPriv, SHA-256(rsaPublicKeyPEM))
    // Client must call verifyRSAPublicKey(ecdsaPublicKey, keySignature, publicKey)
    // If verification fails → key substitution attack detected → abort invite
  });
});

export default router;
