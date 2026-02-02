const { expect } = require('chai');
const { TextEncoder } = require('util');
const { loadJwtModules } = require('./helpers/jwt-modules');

describe('jwt interop', function () {
  const { sign, verify } = loadJwtModules();
  const encoder = new TextEncoder();

  function getSecret() {
    return encoder.encode('secret');
  }

  it('verifies custom token with jose', async function () {
    const jose = await import('jose');
    const token = sign.signJWT({
      sub: 'user',
      exp: Math.floor(Date.now() / 1000) + 60,
      iss: 'issuer',
      aud: 'aud1'
    }, {
      algorithm: 'HS256',
      privateKeyOrSecret: 'secret',
      kid: 'kid-1'
    });

    const result = await jose.jwtVerify(token, getSecret(), {
      issuer: 'issuer',
      audience: 'aud1'
    });

    expect(result.protectedHeader.alg).to.equal('HS256');
    expect(result.protectedHeader.kid).to.equal('kid-1');
    expect(result.payload.sub).to.equal('user');
  });

  it('verifies jose token with custom verify', async function () {
    const jose = await import('jose');
    const token = await new jose.SignJWT({ sub: 'user' })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT', kid: 'kid-1' })
      .setIssuer('issuer')
      .setAudience('aud1')
      .setExpirationTime('2m')
      .sign(getSecret());

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret',
      issuer: 'issuer',
      audience: 'aud1'
    });

    expect(result).to.equal(true);
  });
});
