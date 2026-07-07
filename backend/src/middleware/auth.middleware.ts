import { Request, Response, NextFunction } from 'express';
import { verifyToken, type TokenPayload } from '../services/auth.service';

// Extend Express Request to carry authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
    }
  }
}

export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const token = req.cookies?.auth_token as string | undefined;

  if (!token) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  const payload = verifyToken(token);
  if (!payload) {
    res.status(401).json({ message: 'Invalid or expired session' });
    return;
  }

  req.user = payload;
  next();
}
