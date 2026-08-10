import axios from 'axios';

const BASE = import.meta.env.VITE_API_URL ?? '';

const api = axios.create({
  baseURL:         `${BASE}/api/shared-vaults`,
  withCredentials: true,
});


export const sharedVaultApi = {
  create: (data: { encryptedMetadata: string; encryptedVEK: string }) => 
    api.post('/', data).then(res => res.data),

  getAll: () => 
    api.get('/').then(res => res.data),

  deleteVault: (vaultId: string) =>
    api.delete(`/${vaultId}`).then(res => res.data),

  inviteMember: (vaultId: string, data: { email: string; role: 'owner' | 'editor' | 'viewer'; encryptedVEK: string }) =>
    api.post(`/${vaultId}/invite`, data).then(res => res.data),

  removeMember: (vaultId: string, uid: string) =>
    api.delete(`/${vaultId}/members/${uid}`).then(res => res.data),

  getItems: (vaultId: string) =>
    api.get(`/${vaultId}/items`).then(res => res.data),

  addItem: (vaultId: string, data: { name: string; category: string; encryptedData: string }) =>
    api.post(`/${vaultId}/items`, data).then(res => res.data),

  updateItem: (vaultId: string, itemId: string, data: { name: string; category: string; encryptedData: string }) =>
    api.put(`/${vaultId}/items/${itemId}`, data).then(res => res.data),

  deleteItem: (vaultId: string, itemId: string) =>
    api.delete(`/${vaultId}/items/${itemId}`).then(res => res.data),
};
