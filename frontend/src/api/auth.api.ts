import axios from 'axios';

const api = axios.create({
  baseURL:         '/api',
  withCredentials: true, // sends httpOnly cookie
});

export const authApi = {
  getSalt:             (email: string) => api.get<{ salt: string }>(`/auth/salt/${email}`),
  getRecoverySalt:     (email: string) => api.get<{ salt2: string }>(`/auth/recovery-salt/${email}`),
  getPEKBackup:        (email: string) => api.get<{ encryptedPEKBackup: string }>(`/auth/pek-backup/${email}`),
  register:            (data: object)  => api.post('/auth/register', data),
  login:               (data: object)  => api.post('/auth/login', data),
  logout:              ()              => api.post('/auth/logout'),
  me:                  ()              => api.get<{ email: string; userId: string }>('/auth/me'),
  recover:             (data: object)  => api.post('/auth/recover', data),
};
