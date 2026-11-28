import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to attach JWT token if present in localStorage
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('mailsentra_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor: automatically purge expired or invalid bearer tokens from localStorage
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      const detail = String(error.response.data?.detail || '');
      if (
        detail.toLowerCase().includes('token') ||
        detail.toLowerCase().includes('bearer') ||
        detail.toLowerCase().includes('credentials')
      ) {
        localStorage.removeItem('mailsentra_token');
      }
    }
    return Promise.reject(error);
  }
);

export default api;
