import { normalizeEmail } from './validation.ts';

export interface RegisterValues {
  name: string;
  email: string;
  password: string;
}

export interface RegisterResponse {
  email: string;
  status: 'registered';
}

export interface UserResponse {
  id: number;
  email: string;
  name: string;
}

export class AuthError extends Error {
  readonly status: number;

  constructor(status: number) {
    super('Authentication request failed.');
    this.name = 'AuthError';
    this.status = status;
  }
}

async function csrfToken(signal: AbortSignal): Promise<string> {
  const response = await fetch('/api/auth/csrf', {
    credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
    headers: { Accept: 'application/json' },
  });
  if (response.status !== 200) {
    throw new AuthError(response.status);
  }
  // Read the current raw cookie after every GET, never the masked JSON token.
  const cookie = document.cookie.split(';').map((part) => part.trim())
    .find((part) => part.startsWith('XSRF-TOKEN='));
  const token = cookie?.slice('XSRF-TOKEN='.length);
  if (!token) {
    throw new AuthError(403);
  }
  return token;
}

export async function register(values: RegisterValues, signal: AbortSignal): Promise<RegisterResponse> {
  const token = await csrfToken(signal);
  const response = await fetch('/api/auth/register', {
    method: 'POST', credentials: 'same-origin', redirect: 'error', signal,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-XSRF-TOKEN': token },
    body: JSON.stringify({ name: values.name, email: normalizeEmail(values.email), password: values.password }),
  });
  if (response.status !== 201) {
    throw new AuthError(response.status);
  }
  const data: unknown = await response.json();
  if (data === null || typeof data !== 'object' || !('email' in data) || typeof data.email !== 'string'
    || !('status' in data) || data.status !== 'registered') {
    throw new AuthError(500);
  }
  return { email: data.email, status: data.status };
}

export async function login(email: string, password: string, signal: AbortSignal): Promise<void> {
  const token = await csrfToken(signal);
  const response = await fetch('/api/auth/login', {
    method: 'POST', credentials: 'same-origin', redirect: 'error', signal,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-XSRF-TOKEN': token },
    body: new URLSearchParams({ email: normalizeEmail(email), password }),
  });
  if (response.status !== 204) {
    throw new AuthError(response.status);
  }
}

export async function currentUser(signal: AbortSignal): Promise<UserResponse | null> {
  const response = await fetch('/api/auth/me', {
    credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
    headers: { Accept: 'application/json' },
  });
  if (response.status === 401) {
    return null;
  }
  if (response.status !== 200) {
    throw new AuthError(response.status);
  }
  const data: unknown = await response.json();
  if (data === null || typeof data !== 'object'
    || !('id' in data) || typeof data.id !== 'number'
    || !('email' in data) || typeof data.email !== 'string'
    || !('name' in data) || typeof data.name !== 'string') {
    throw new AuthError(500);
  }
  return { id: data.id, email: data.email, name: data.name };
}

export async function logout(signal: AbortSignal): Promise<void> {
  const token = await csrfToken(signal);
  const response = await fetch('/api/auth/logout', {
    method: 'POST', credentials: 'same-origin', redirect: 'error', signal,
    headers: { 'X-XSRF-TOKEN': token },
  });
  if (response.status !== 204) {
    throw new AuthError(response.status);
  }
}
