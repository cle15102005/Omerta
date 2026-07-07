import { z } from 'zod';

const CategoryEnum = z.enum(['password', 'api_key', 'note', 'card']);

// POST /api/vault/
export const CreateVaultItemDto = z.object({
  nameLeafHash:  z.string().min(1), // SHA-256(name+nameSalt) hex
  category:      CategoryEnum,
  encryptedData: z.string().min(1), // AES-256-GCM(PEK) blob
  // After adding, client sends updated merkle index
  vaultIndex: z.object({
    merkleRoot: z.string(),
    leafHashes: z.array(z.string()),
  }),
});

// PUT /api/vault/:id
export const UpdateVaultItemDto = z.object({
  nameLeafHash:  z.string().min(1).optional(),
  category:      CategoryEnum.optional(),
  encryptedData: z.string().min(1),
  // If name changed, include updated index; otherwise omit
  vaultIndex: z.object({
    merkleRoot: z.string(),
    leafHashes: z.array(z.string()),
  }).optional(),
});

export type CreateVaultItemInput = z.infer<typeof CreateVaultItemDto>;
export type UpdateVaultItemInput = z.infer<typeof UpdateVaultItemDto>;
