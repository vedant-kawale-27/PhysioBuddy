const rawApi = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
export const API_BASE = rawApi.replace(/\/+$/, '');

const deriveWsUrl = (apiUrl) => {
  if (apiUrl.startsWith('https://')) {
    return apiUrl.replace(/^https:\/\//, 'wss://');
  }
  return apiUrl.replace(/^http:\/\//, 'ws://');
};

const rawWs = import.meta.env.VITE_WS_URL || deriveWsUrl(API_BASE);

const baseWs = API_BASE.startsWith('https://')
  ? rawWs.replace(/^ws:\/\//, 'wss://')
  : rawWs;

export const WS_BASE = baseWs.replace(/\/+$/, '');
