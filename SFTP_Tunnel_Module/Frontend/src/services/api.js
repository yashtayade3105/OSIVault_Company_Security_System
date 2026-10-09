import axios from 'axios';

const API_BASE = '/api';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const ediApi = {
  uploadFile: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    try {
      return await axios.post('/api/documents/upload/', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 120000,
      });
    } catch (err) {
      return await axios.post('http://127.0.0.1:8000/api/documents/upload/', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 120000,
      });
    }
  },
  getDocuments: () => api.get('/documents/'),
  getDocumentDetails: (id) => api.get(`/documents/${id}/`),
  getMembers: (params) => api.get('/members/', { params }),
  getAuditEvents: () => api.get('/audit/'),
  getDashboardStats: () => api.get('/dashboard/stats/'),
  getServerDirectoryFiles: () => api.get('/server-directory/files/'),

  // OSIVault Security Module API Integrations
  getOSIVaultSuperusers: () => api.get('/osivault/sftp/superusers/'),
  getOSIVaultSFTPLogs: () => api.get('/osivault/sftp/logs/'),
  encryptFileOSIVault: (filename) => api.post('/osivault/sftp/encrypt-file/', { filename }),
  decryptFileOSIVault: (filename, username, password) => api.post('/osivault/sftp/decrypt-file/', { filename, username, password }),
  
  // osivault.fields API Endpoints
  getOSIVaultFieldsInspect: () => api.get('/osivault/fields/inspect/'),
  searchOSIVaultFieldsBlindIndex: (query) => api.get('/osivault/fields/search/', { params: { query } }),
  rotateOSIVaultFieldsKeys: () => api.post('/osivault/fields/rotate-keys/'),

  // osivault.audit Cryptographic Verification API Endpoints
  getOSIVaultAuditLogs: (table = 'central') => api.get(`/osivault/audit/logs/?table=${table}`),
  verifyOSIVaultAuditChain: (table = 'central') => api.post('/osivault/audit/verify-chain/', { table }),
  createOSIVaultAuditCheckpoint: (table = 'central') => api.post('/osivault/audit/checkpoint/', { table }),

  // osivault.auth Step-by-Step API Endpoints
  getOSIVaultAuthInspect: () => api.get('/osivault/auth/inspect/'),
  sendEmailOTP: (email, purpose = 'REGISTRATION') => axios.post('/osivault/auth/api/email-otp/send/', { email, purpose }),
  verifyEmailOTP: (email, otp_code, purpose = 'REGISTRATION') => axios.post('/osivault/auth/api/email-otp/verify/', { email, otp_code, purpose }),
  registerUserAuth: (username, email, password, otp_code) => axios.post('/osivault/auth/api/user/register/', { username, email, password, otp_code }),
  loginUserAuth: (username_or_email, password) => axios.post('/osivault/auth/api/user/login/', { username_or_email, password }),
};

export default api;
