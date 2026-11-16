import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AuthError, currentUser, login, logout, register } from '../src/auth/api.ts';

function transport(t, handler) {
  const originalDocument = Object.getOwnPropertyDescriptor(globalThis, 'document');
  const document = { cookie: '' };
  Object.defineProperty(globalThis, 'document', { value: document, configurable: true });
  t.after(() => {
    if (originalDocument) {
      Object.defineProperty(globalThis, 'document', originalDocument);
    } else {
      delete globalThis.document;
    }
  });
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
    options.signal.throwIfAborted();
    return handler(url, options, document);
  });
}

test('registration sends JSON with the unchanged password and returns the server-normalized email', async (t) => {
  const password = '  Știință🔐 e\u0301  ';
  let posts = 0;
  transport(t, (url, options, document) => {
    if (url === '/api/auth/csrf') {
      assert.equal(options.cache, 'no-store');
      document.cookie = 'other=value; XSRF-TOKEN=test-raw-register';
      // Deliberately not JSON: the masked response body must never be used.
      return new Response('unused masked token', { status: 200 });
    }
    assert.equal(url, '/api/auth/register');
    assert.equal(options.method, 'POST');
    assert.equal(options.headers['Content-Type'], 'application/json');
    assert.equal(options.headers.Accept, 'application/json');
    assert.ok(options.headers['X-XSRF-TOKEN'] === 'test-raw-register');
    const body = JSON.parse(options.body);
    assert.deepEqual(Object.keys(body).sort(), ['email', 'name', 'password']);
    assert.equal(body.email, 'alice@example.com');
    assert.equal(body.name, ' Alice ');
    assert.ok(body.password === password, 'password is unchanged');
    posts++;
    return Response.json({ email: 'alice@example.com', status: 'registered' }, { status: 201 });
  });
  const result = await register({ name: ' Alice ', email: '\u2003ALICE@Example.COM ', password }, new AbortController().signal);
  assert.deepEqual(result, { email: 'alice@example.com', status: 'registered' });
  assert.equal(posts, 1);
});

test('login and logout acquire a fresh raw CSRF cookie for each POST and accept empty 204 responses', async (t) => {
  let generation = 0;
  const calls = [];
  const password = '  Știință 🔐 +&=  ';
  transport(t, (url, options, document) => {
    calls.push(url);
    if (url === '/api/auth/csrf') {
      generation++;
      document.cookie = `XSRF-TOKEN=test-raw-${generation}`;
      return Response.json({ token: 'test-masked-value' });
    }
    assert.equal(options.method, 'POST');
    assert.ok(options.headers['X-XSRF-TOKEN'] === `test-raw-${generation}`);
    if (url === '/api/auth/login') {
      assert.equal(options.headers['Content-Type'], 'application/x-www-form-urlencoded');
      assert.ok(options.body instanceof URLSearchParams);
      assert.deepEqual([...options.body.keys()], ['email', 'password']);
      assert.equal(options.body.get('email'), 'alice@example.com');
      assert.ok(options.body.get('password') === password, 'form encoding preserves the password');
    } else {
      assert.equal(url, '/api/auth/logout');
    }
    document.cookie = '';
    return new Response(null, { status: 204 });
  });
  const signal = new AbortController().signal;
  await login(' ALICE@Example.com ', password, signal);
  await logout(signal);
  await login('alice@example.com', password, signal);
  assert.deepEqual(calls, [
    '/api/auth/csrf', '/api/auth/login', '/api/auth/csrf', '/api/auth/logout', '/api/auth/csrf', '/api/auth/login',
  ]);
});

test('missing CSRF cookie prevents submission', async (t) => {
  transport(t, (url) => {
    assert.equal(url, '/api/auth/csrf');
    return Response.json({ token: 'test-masked-only' });
  });
  await assert.rejects(login('alice@example.com', 'test-password', new AbortController().signal),
    (error) => error instanceof AuthError && error.status === 403);
});

test('a failed CSRF request prevents submission even when an old cookie exists', async (t) => {
  transport(t, (url, _options, document) => {
    assert.equal(url, '/api/auth/csrf');
    document.cookie = 'XSRF-TOKEN=test-stale';
    return new Response(null, { status: 500 });
  });
  await assert.rejects(logout(new AbortController().signal),
    (error) => error instanceof AuthError && error.status === 500);
});

test('authentication failures preserve status without exposing response details', async (t) => {
  let failureStatus = 401;
  transport(t, (url, _options, document) => {
    if (url === '/api/auth/csrf') {
      document.cookie = 'XSRF-TOKEN=test-raw';
      return new Response(null);
    }
    return Response.json({ detail: 'internal database diagnostic' }, { status: failureStatus });
  });
  for (const status of [400, 401, 403, 409, 500]) {
    failureStatus = status;
    await assert.rejects(login('alice@example.com', 'test-password', new AbortController().signal),
      (error) => error instanceof AuthError && error.status === status
        && error.message === 'Authentication request failed.');
  }
});

test('current user is fetched without caching; only 401 means unauthenticated', async (t) => {
  let status = 200;
  transport(t, (url, options) => {
    assert.equal(url, '/api/auth/me');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.headers.Accept, 'application/json');
    return Response.json({ id: 42, email: 'alice@example.com', name: 'Ștefania 👋' }, { status });
  });
  const signal = new AbortController().signal;
  assert.deepEqual(await currentUser(signal), { id: 42, email: 'alice@example.com', name: 'Ștefania 👋' });
  status = 401;
  assert.equal(await currentUser(signal), null);
  for (const errorStatus of [403, 500]) {
    status = errorStatus;
    await assert.rejects(currentUser(signal), (error) => error instanceof AuthError && error.status === errorStatus);
  }
});

test('malformed successful responses do not produce a user or a registration confirmation', async (t) => {
  transport(t, (url, _options, document) => {
    if (url === '/api/auth/csrf') {
      document.cookie = 'XSRF-TOKEN=test-raw';
      return new Response(null);
    }
    return Response.json({}, { status: url === '/api/auth/register' ? 201 : 200 });
  });
  const signal = new AbortController().signal;
  await assert.rejects(currentUser(signal), AuthError);
  await assert.rejects(register({ email: 'alice@example.com', name: '', password: 'test-password' }, signal), AuthError);
});

test('network failures remain failures, never successful login or logout', async (t) => {
  transport(t, () => { throw new TypeError('Network unavailable'); });
  const signal = new AbortController().signal;
  await assert.rejects(login('alice@example.com', 'test-password', signal), TypeError);
  await assert.rejects(logout(signal), TypeError);
  await assert.rejects(currentUser(signal), TypeError);
});

test('aborting during CSRF retrieval prevents the mutation', async (t) => {
  const controller = new AbortController();
  transport(t, (url, _options, document) => {
    assert.equal(url, '/api/auth/csrf');
    document.cookie = 'XSRF-TOKEN=test-raw';
    controller.abort();
    return new Response(null);
  });
  await assert.rejects(logout(controller.signal), (error) => error.name === 'AbortError');
});
