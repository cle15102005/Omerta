import { z } from 'zod';

export const CreateSharedVaultDto = z.object({
  encryptedMetadata: z.string().min(1), // AES-256-GCM(VEK) of { name, description }
  encryptedVEK: z.string().min(1), // Owner's VEK encrypted with their RSA public key
});

export const InviteMemberDto = z.object({
  email: z.string().email(),
  role: z.enum(['owner', 'editor', 'viewer']),
  encryptedVEK: z.string().min(1), // VEK encrypted with the invitee's RSA public key
});

export const SharedVaultItemDto = z.object({
  name: z.string().min(1),
  category: z.string().min(1),
  encryptedData: z.string().min(1),
});

export type CreateSharedVaultInput = z.infer<typeof CreateSharedVaultDto>;
export type InviteMemberInput = z.infer<typeof InviteMemberDto>;
export type SharedVaultItemInput = z.infer<typeof SharedVaultItemDto>;
