---
name: jwt-knowledge
description: 'JWT concepts, validation steps, and JavaScript examples. Use when designing, implementing, or reviewing JWT issuance and verification.'
license: Forward Proprietary
compatibility: VS Code 1.x+, GitHub Copilot
---

# JWT Knowledge

Practical guidance for working with JSON Web Tokens (JWTs) in JavaScript apps and APIs.

## When to Use This Skill

- Implementing JWT issuance or verification flows
- Reviewing JWT usage for security correctness
- Troubleshooting claim validation or expiration errors

## Not For

- Long-term session storage (prefer server-side sessions)
- Encrypted payloads (use JWE, not JWT)

## Core Concepts

- **Structure**: compact JWTs are `base64url(header) + "." + base64url(payload) + "." + base64url(signature)`.
- **Header**: indicates algorithm (for example, `alg`) and optional `typ`.
- **Payload (claims)**: the claims set. Registered claims include `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`.
- **Signature**: JWS signature over the ASCII bytes of `base64url(header) || "." || base64url(payload)`.

## Validation Checklist

1. **Verify signature** with the expected key and algorithm.
2. **Reject `alg=none`** and unexpected algorithms.
3. **Validate `iss`** against your trusted issuer list.
4. **Validate `aud`** to ensure the token is intended for your service.
5. **Enforce time claims**: reject before `nbf` and after `exp`.
6. **Apply clock skew** if needed, but keep it small (for example, 1-2 minutes).
7. **Require critical claims** for your app (for example, `sub` or custom roles).

## Quick Reference

| Claim | Meaning | Notes |
| --- | --- | --- |
| `iss` | Issuer | Must match expected issuer |
| `sub` | Subject | Identifies the principal |
| `aud` | Audience | Must include your service |
| `exp` | Expiration time | Reject if current time is after `exp` |
| `nbf` | Not before | Reject if current time is before `nbf` |
| `iat` | Issued at | Useful for debugging/rotation |

## Examples

### Example 1: Verify a JWT (HS256)

```javascript
import { jwtVerify } from 'jose';

const token = process.env.ACCESS_TOKEN;
const secret = new TextEncoder().encode(process.env.JWT_SECRET);

try {
  const { payload, protectedHeader } = await jwtVerify(token, secret, {
    issuer: 'https://issuer.example.com',
    audience: 'my-api'
  });

  console.log('alg:', protectedHeader.alg);
  console.log('sub:', payload.sub);
} catch (err) {
  console.error('JWT verification failed:', err.message);
}
```

### Example 2: Issue a JWT (HS256)

```javascript
import { SignJWT } from 'jose';

const secret = new TextEncoder().encode(process.env.JWT_SECRET);

const token = await new SignJWT({ role: 'admin' })
  .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
  .setIssuer('https://issuer.example.com')
  .setAudience('my-api')
  .setSubject('user-123')
  .setIssuedAt()
  .setExpirationTime('15m')
  .sign(secret);

console.log(token);
```

## Troubleshooting

- **Invalid signature**: key mismatch, wrong algorithm, or corrupted token.
- **Token expired**: check `exp` and consider small clock skew.
- **Audience mismatch**: ensure `aud` includes your service identifier.
- **Issuer mismatch**: verify the configured `iss` matches the token.

## References

- RFC 7519 - JSON Web Token (JWT): https://www.rfc-editor.org/rfc/rfc7519
- RFC 7515 - JSON Web Signature (JWS): https://www.rfc-editor.org/rfc/rfc7515
