import { API_BASE } from './config';

export function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i += 1) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === `${name}=`) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}

export async function ensureCsrfToken() {
  let csrfToken = getCookie('csrftoken');
  if (csrfToken) return csrfToken;

  const response = await fetch(`${API_BASE}/api/csrf/`, {
    method: 'GET',
    credentials: 'include',
  });

  if (!response.ok) {
    throw new Error('Unable to initialize CSRF protection.');
  }

  csrfToken = getCookie('csrftoken');
  if (!csrfToken) {
    throw new Error('CSRF token was not created.');
  }

  return csrfToken;
}
