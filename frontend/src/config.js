export const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

const deriveWsUrl = (apiUrl) => {
  if (apiUrl.startsWith('https://')) {
    return apiUrl.replace(/^https:\/\//, 'wss://');
  }
  return apiUrl.replace(/^http:\/\//, 'ws://');
};

const rawWs = import.meta.env.VITE_WS_URL || deriveWsUrl(API_BASE);

export const WS_BASE = API_BASE.startsWith('https://')
  ? rawWs.replace(/^ws:\/\//, 'wss://')
  : rawWs;
