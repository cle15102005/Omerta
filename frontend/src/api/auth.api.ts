import axios from 'axios';

const api = axios.create({
  baseURL:         '/api',
  withCredentials: true, // sends httpOnly cookie
});

export const authApi = {
  getSalt:             (email: string) => api.get<{ salt: string }>(`/auth/salt/${email}`),
  getRecoverySalt:     (email: string) => api.get<{ salt2: string }>(`/auth/recovery-salt/${email}`),
  getRecoveryData:     (data: { email: string; recoveryAuthHash: string }) => api.post<{ 
    encryptedPEKBackup: string; 
    encryptedPrivateKey: string; 
    encryptedECDSAPrivateKey: string; 
    vaultItems: Array<{ _id: string; encryptedData: string; history?: Array<{ encryptedData: string; savedAt: string }> }> 
  }>('/auth/recovery-data', data),
  register:            (data: object)  => api.post('/auth/register', data),
  login:               (data: object)  => api.post('/auth/login', data),
  logout:              ()              => api.post('/auth/logout'),
  deleteAccount:       ()              => api.delete('/auth/account'),
  me:                  ()              => api.get<{ email: string; userId: string; encryptedPrivateKey?: string; encryptedECDSAPrivateKey?: string; ecdsaPublicKey?: string }>('/auth/me'),
  recover:             (data: object)  => api.post('/auth/recover', data),
};
