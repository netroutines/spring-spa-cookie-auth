// Keep these rules aligned with RegisterRequest and LoginAuthenticationProvider.
// Java String.length() and JS string.length both count UTF-16 code units.
const MAX_EMAIL_LENGTH = 254;
const MAX_NAME_LENGTH = 100;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 1024;

// Character.isWhitespace / String.strip, unlike JS trim(), excludes NBSP and BOM.
const JAVA_WHITESPACE = '[\\u0009-\\u000d\\u001c-\\u0020\\u1680\\u2000-\\u2006\\u2008-\\u200a\\u2028\\u2029\\u205f\\u3000]';
const EDGE_WHITESPACE = new RegExp(`^${JAVA_WHITESPACE}+|${JAVA_WHITESPACE}+$`, 'gu');
const BLANK = new RegExp(`^${JAVA_WHITESPACE}*$`, 'u');

// Hibernate Validator 9.1.5: allow quoted local parts, including spaces and @.
const LOCAL_PART = /^(?:[a-z0-9!#$%&'*+/=?^_`{|}~\u0080-\uffff-]+|"(?:[a-z0-9!#$%&'*.(),<>[\]:; @+/=?^_`{|}~\u0080-\uffff-]|\\\\|\\")+")(?:\.(?:[a-z0-9!#$%&'*+/=?^_`{|}~\u0080-\uffff-]+|"(?:[a-z0-9!#$%&'*.(),<>[\]:; @+/=?^_`{|}~\u0080-\uffff-]|\\\\|\\")+"))*$/iu;
const DOMAIN_LABEL = /^[a-z0-9!#$%&'*+/=?^_`{|}~\u0080-\uffff]+(?:-+[a-z0-9!#$%&'*+/=?^_`{|}~\u0080-\uffff]+)*$/iu;

export function normalizeEmail(value: string): string {
  return value.replace(EDGE_WHITESPACE, '').toLowerCase();
}

function validEmailDomain(domain: string): boolean {
  // The backend also accepts IPv4 literals without checking octet ranges.
  if (/^\[\d{1,3}(?:\.\d{1,3}){3}\]$/u.test(domain)) {
    return true;
  }

  if (domain.startsWith('[ipv6:') && domain.endsWith(']')) {
    let address = domain.slice(6, -1);
    // This scoped link-local form is explicitly accepted by Hibernate Validator.
    if (/^fe80:(?::[0-9a-f]{0,4}){0,4}%[0-9a-z]+$/u.test(address)) {
      return domain.length <= 63;
    }
    if (!/^[0-9a-f:.]+$/u.test(address) || domain.split('.').some((label) => label.length > 63)) {
      return false;
    }
    if (address.includes('.')) {
      const lastColon = address.lastIndexOf(':');
      const prefix = address.slice(0, lastColon + 1);
      const octets = address.slice(lastColon + 1).split('.');
      // Match Hibernate's supported embedded IPv4 forms (not every valid IPv6 form).
      if (!/^(?:::|::ffff:(?:0{1,4}:)?|(?:[0-9a-f]{1,4}:){1,4}:)$/u.test(prefix)
        || octets.length !== 4
        || !octets.every((octet) => /^(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})$/u.test(octet))) {
        return false;
      }
      // The browser rejects leading zeros, which Hibernate permits here.
      address = prefix + octets.map(Number).join('.');
    }
    try {
      return new URL(`http://[${address}]/`).hostname.startsWith('[');
    } catch {
      return false;
    }
  }

  return domain.split('.').every((label) => {
    if (!DOMAIN_LABEL.test(label)) {
      return false;
    }
    // Java IDN.toASCII uses IDNA2003, unlike browser URL/UTS46. Do not reject
    // international labels using a different standard. Their conversion and ACE
    // length remain server-validated; ASCII label lengths are identical here.
    return /[^\x20-\x7e]/u.test(label) || label.length <= 63;
  });
}

export function validateEmail(value: string): string | null {
  const email = normalizeEmail(value);
  if (email.length === 0) {
    return 'Enter your email.';
  }
  if (email.length > MAX_EMAIL_LENGTH) {
    return 'Email must be at most 254 characters.';
  }
  if ([...email].some((character) => character < ' ' || character === '\u007f')) {
    return 'Enter a valid email address.';
  }
  const at = email.lastIndexOf('@');
  const local = email.slice(0, at);
  if (at < 1 || local.length > 64 || !LOCAL_PART.test(local) || !validEmailDomain(email.slice(at + 1))) {
    return 'Enter a valid email address.';
  }
  return null;
}

export function validateName(value: string): string | null {
  // @Size runs before AuthService strips the optional name.
  if (value.length > MAX_NAME_LENGTH) {
    return 'Name must be at most 100 characters.';
  }
  return value.includes('\0') ? 'Name cannot contain a null character.' : null;
}

export function validatePassword(value: string): string | null {
  if (value.length < MIN_PASSWORD_LENGTH || value.length > MAX_PASSWORD_LENGTH) {
    return 'Password must be between 8 and 1024 characters.';
  }
  return BLANK.test(value) ? 'Password cannot contain only whitespace.' : null;
}
