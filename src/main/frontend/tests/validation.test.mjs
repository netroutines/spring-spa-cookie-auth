import assert from 'node:assert/strict';
import { test } from 'node:test';
import { normalizeEmail, validateEmail, validateName, validatePassword } from '../src/auth/validation.ts';

test('email normalization follows Java strip and locale-independent lowercase', () => {
  assert.equal(normalizeEmail('\u2003 ALICE@Example.COM\u001c'), 'alice@example.com');
  assert.equal(normalizeEmail('\u00a0Alice@example.com\ufeff'), '\u00a0alice@example.com\ufeff');
  assert.equal(normalizeEmail('İ@example.com'), 'i\u0307@example.com');
});

test('email accepts backend-supported quoted, Unicode and domain literal forms', () => {
  const addresses = [
    'alice@example.com', ' \u2003Alice@Example.COM ', 'alice@localhost',
    '"Alice@Home"@example.com', '"alice home"@example.com', '"a\\"b"@example.com',
    '"a\\\\b"@example.com', 'Ștefania@example.com', 'alice@bücher.de',
    'alice@under_score.example', 'alice@[999.999.999.999]', 'alice@[IPv6:::1]',
    'alice@[IPv6:2001:db8::1]', 'alice@[IPv6:::ffff:192.168.01.1]',
    'alice@[IPv6:fe80::1%eth0]',
  ];
  addresses.forEach((email, index) => assert.equal(validateEmail(email), null, `valid email case ${index}`));
});

test('email rejects malformed addresses and embedded control characters', () => {
  const addresses = [
    '', ' ', 'alice', '@example.com', 'alice@', 'alice@@example.com',
    'alice..home@example.com', '.alice@example.com', 'alice.@example.com',
    'alice home@example.com', 'alice@-example.com', 'alice@example-.com',
    'alice@example..com', 'alice@example.com.', 'alice\n@example.com',
    'alice@exam\nple.com', 'alice\0@example.com', 'alice@\u0001example.com',
    'alice@[IPv6:12345::1]', 'alice@[IPv6:::1]/path]', 'alice@[IPv6:::ffff:256.0.0.1]',
    'alice@[IPv6:1:2:3:4:5:6:192.168.1.1]',
  ];
  addresses.forEach((email, index) => assert.ok(validateEmail(email), `invalid email case ${index}`));
});

test('email enforces normalized UTF-16, local-part and ASCII domain-label boundaries', () => {
  const longest = `${'a'.repeat(64)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`;
  assert.equal(longest.length, 254);
  assert.equal(validateEmail(` ${longest} `), null);
  assert.ok(validateEmail(`${longest}x`));
  assert.ok(validateEmail(`${'a'.repeat(65)}@example.com`));
  assert.ok(validateEmail(`a@${'b'.repeat(64)}.com`));
  assert.ok(validateEmail(`${'İ'.repeat(33)}@example.com`));
});

test('name is optional and measured before trimming; NUL cannot be persisted', () => {
  for (const name of ['', ' \u2003 ', 'Ștefania 👋', 'a'.repeat(100), '😀'.repeat(50)]) {
    assert.equal(validateName(name), null);
  }
  for (const name of ['a'.repeat(101), `${' '.repeat(100)}a`, '😀'.repeat(51), 'Alice\0']) {
    assert.ok(validateName(name));
  }
});

test('password boundaries count UTF-16 and allow Unicode, spaces and NUL without alteration', () => {
  const passwords = ['a'.repeat(8), 'a'.repeat(1024), '😀'.repeat(512), '  parola  ', 'Știință🔐 e\u0301', '\0'.repeat(8)];
  passwords.forEach((password, index) => assert.equal(validatePassword(password), null, `password case ${index}`));
  for (const password of ['', 'a'.repeat(7), 'a'.repeat(1025), '😀'.repeat(513)]) {
    assert.ok(validatePassword(password));
  }
});

test('blank-password checks use Java whitespace, not JavaScript trim', () => {
  for (const password of [' '.repeat(8), '\u2003'.repeat(8), '\u001c'.repeat(8), '\t\n\r     ']) {
    assert.ok(validatePassword(password));
  }
  for (const password of ['\u00a0'.repeat(8), '\ufeff'.repeat(8), '\u2007'.repeat(8), '\u202f'.repeat(8)]) {
    assert.equal(validatePassword(password), null);
  }
});
