import { Router, Request, Response } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';
import { CreateVaultItemDto, UpdateVaultItemDto } from '../dtos/vault.dto';
import {
  listItems, getItem, createItem, updateItem,
  deleteItem, getItemHistory, exportVault,
} from '../services/vault.service';

const router = Router();

// All vault routes require authentication
router.use(authMiddleware);

// GET /api/vault/  — list (metadata only, no encryptedData)
router.get('/', async (req: Request, res: Response) => {
  const items = await listItems(req.user!.userId);
  res.json(items);
});

// POST /api/vault/  — create new item
router.post('/', async (req: Request, res: Response) => {
  const parsed = CreateVaultItemDto.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ message: 'Invalid input', errors: parsed.error.flatten() }); return; }

  try {
    const item = await createItem(req.user!.userId, parsed.data);
    res.status(201).json(item);
  } catch (err) {
    console.error('[Vault] Create error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/vault/:id  — get single item (with encryptedData)
router.get('/:id', async (req: Request, res: Response) => {
  const item = await getItem(req.user!.userId, req.params.id as string);
  if (!item) { res.status(404).json({ message: 'Item not found' }); return; }
  res.json(item);
});

// PUT /api/vault/:id  — update item (auto-pushes current to history)
router.put('/:id', async (req: Request, res: Response) => {
  const parsed = UpdateVaultItemDto.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ message: 'Invalid input', errors: parsed.error.flatten() }); return; }

  const item = await updateItem(req.user!.userId, req.params.id as string, parsed.data);
  if (!item) { res.status(404).json({ message: 'Item not found' }); return; }
  res.json(item);
});

// DELETE /api/vault/:id
router.delete('/:id', async (req: Request, res: Response) => {
  const { merkleRoot, leafHashes } = req.body;
  const ok = await deleteItem(req.user!.userId, req.params.id as string, { merkleRoot, leafHashes });
  if (!ok) { res.status(404).json({ message: 'Item not found' }); return; }
  res.json({ message: 'Item deleted' });
});

// GET /api/vault/:id/history  — get version history (client decrypts)
router.get('/:id/history', async (req: Request, res: Response) => {
  const history = await getItemHistory(req.user!.userId, req.params.id as string);
  if (history === null) { res.status(404).json({ message: 'Item not found' }); return; }
  res.json(history);
});

// GET /api/vault/export  — full encrypted backup
router.get('/export', async (req: Request, res: Response) => {
  const data = await exportVault(req.user!.userId);
  res.json({ version: 1, createdAt: new Date().toISOString(), ...data });
});

export default router;
