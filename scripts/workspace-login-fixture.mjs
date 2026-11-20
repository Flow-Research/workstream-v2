// Ephemeral issuer for the TLS drill. Export only public configuration and test tokens.
import { generateKeyPairSync, sign } from 'node:crypto';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const { n, e } = publicKey.export({ format: 'jwk' });
const issuer = 'https://issuer.example', audience = 'workstream-workspace';
const now = Math.floor(Date.now() / 1000);
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
function token(overrides, typ = 'at+jwt') {
  const claims = { iss: issuer, aud: audience, sub: 'pilot', scope: 'workspace:login',
    iat: now - 60, exp: now + 600, roles: ['admin'], ...overrides };
  const message = `${encode({ alg: 'RS256', typ })}.${encode(claims)}`;
  return `${message}.${sign('sha256', Buffer.from(message), privateKey).toString('base64url')}`;
}
console.log(JSON.stringify({ config: { issuer, audience, n, e }, valid: token({}),
  expired: token({ exp: now - 1 }), wrongIssuer: token({ iss: 'https://other.example' }),
  wrongAudience: token({ aud: 'other' }), wrongScope: token({ scope: 'other' }),
  future: token({ nbf: now + 3600 }), idToken: token({}, 'JWT') }));
