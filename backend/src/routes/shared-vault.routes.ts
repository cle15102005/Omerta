import { Router, Request, Response } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';
import * as sharedVaultService from '../services/shared-vault.service';
import { CreateSharedVaultDto, InviteMemberDto, SharedVaultItemDto } from '../dtos/shared-vault.dto';

const router = Router();
router.use(authMiddleware);

// ── Vault Management ──────────────────────────────────────────────────────────

router.post('/', async (req: Request, res: Response) => {
  try {
    const parsed = CreateSharedVaultDto.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ message: 'Invalid input' }); return; }

    const result = await sharedVaultService.createSharedVault(req.user!.userId, parsed.data);
    res.status(201).json(result);
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

router.get('/', async (req: Request, res: Response) => {
  try {
    const vaults = await sharedVaultService.getMySharedVaults(req.user!.userId);
    res.json(vaults);
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

router.delete('/:vaultId', async (req: Request, res: Response) => {
  try {
    const ok = await sharedVaultService.deleteSharedVault(req.user!.userId, req.params.vaultId as string);
    if (ok) {
      res.json({ message: 'Vault deleted successfully' });
    } else {
      res.status(404).json({ message: 'Vault not found' });
    }
  } catch (error: any) {
    res.status(403).json({ message: error.message });
  }
});

// ── Member Management ─────────────────────────────────────────────────────────

router.post('/:vaultId/invite', async (req: Request, res: Response) => {
  try {
    const parsed = InviteMemberDto.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ message: 'Invalid input' }); return; }

    const result = await sharedVaultService.inviteMember(req.user!.userId, req.params.vaultId as string, parsed.data);
    res.json(result);
  } catch (error: any) {
    res.status(403).json({ message: error.message });
  }
});

router.delete('/:vaultId/members/:uid', async (req: Request, res: Response) => {
  try {
    const ok = await sharedVaultService.removeMember(req.user!.userId, req.params.vaultId as string, req.params.uid as string);
    if (ok) {
      res.json({ message: 'Member removed' });
    } else {
      res.status(404).json({ message: 'Member not found' });
    }
  } catch (error: any) {
    res.status(403).json({ message: error.message });
  }
});

// ── Item CRUD ─────────────────────────────────────────────────────────────────

router.get('/:vaultId/items', async (req: Request, res: Response) => {
  try {
    const items = await sharedVaultService.getVaultItems(req.user!.userId, req.params.vaultId as string);
    res.json(items);
  } catch (error: any) {
    res.status(403).json({ message: error.message });
  }
});

router.post('/:vaultId/items', async (req: Request, res: Response) => {
  try {
    const parsed = SharedVaultItemDto.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ message: 'Invalid input' }); return; }

    const item = await sharedVaultService.addVaultItem(req.user!.userId, req.params.vaultId as string, parsed.data);
    res.status(201).json(item);
  } catch (error: any) {
    res.status(403).json({ message: error.message });
  }
});

router.put('/:vaultId/items/:itemId', async (req: Request, res: Response) => {
  try {
    const parsed = SharedVaultItemDto.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ message: 'Invalid input' }); return; }

    const item = await sharedVaultService.updateVaultItem(req.user!.userId, req.params.vaultId as string, req.params.itemId as string, parsed.data);
    res.json(item);
  } catch (error: any) {
    res.status(403).json({ message: error.message });
  }
});

router.delete('/:vaultId/items/:itemId', async (req: Request, res: Response) => {
  try {
    const ok = await sharedVaultService.deleteVaultItem(req.user!.userId, req.params.vaultId as string, req.params.itemId as string);
    if (ok) {
      res.json({ message: 'Item deleted' });
    } else {
      res.status(404).json({ message: 'Item not found' });
    }
  } catch (error: any) {
    res.status(403).json({ message: error.message });
  }
});

export default router;
