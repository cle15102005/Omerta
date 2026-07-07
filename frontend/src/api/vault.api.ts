import axios from 'axios';
import type { VaultItemMeta, VaultItemFull } from '../types';

const api = axios.create({ baseURL: '/api', withCredentials: true });

export const vaultApi = {
  list:      ()                      => api.get<VaultItemMeta[]>('/vault/'),
  get:       (id: string)            => api.get<VaultItemFull>(`/vault/${id}`),
  create:    (data: object)          => api.post<VaultItemFull>('/vault/', data),
  update:    (id: string, data: object) => api.put<VaultItemFull>(`/vault/${id}`, data),
  delete:    (id: string, vaultIndex: object) => api.delete(`/vault/${id}`, { data: vaultIndex }),
  history:   (id: string)            => api.get(`/vault/${id}/history`),
  export:    ()                      => api.get('/vault/export'),
};
