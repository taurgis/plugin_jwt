const { expect } = require('chai');
const crypto = require('crypto');
const { loadJwtModules } = require('./helpers/jwt-modules');

describe('jwt pss interop', function () {
  const { sign, verify } = loadJwtModules();

  function createRsaKeyPair() {
    return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  }

  it('signs PS512 and verifies with jose + custom verify', async function () {
    const jose = await import('jose');
    const { publicKey, privateKey } = createRsaKeyPair();

    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

    const token = sign.signJWT({
      sub: 'user',
      exp: Math.floor(Date.now() / 1000) + 60,
      iss: 'issuer',
      aud: 'aud1'
    }, {
      algorithm: 'PS512',
      privateKeyOrSecret: privatePem,
      kid: 'kid-pss'
    });

    const customVerified = verify.verifyJWT(token, {
      publicKeyOrSecret: publicPem,
      issuer: 'issuer',
      audience: 'aud1'
    });
    expect(customVerified).to.equal(true);

    const result = await jose.jwtVerify(token, publicKey, {
      issuer: 'issuer',
      audience: 'aud1'
    });
    expect(result.protectedHeader.alg).to.equal('PS512');
  });

  it('verifies jose PS512 token with custom verify', async function () {
    const jose = await import('jose');
    const { publicKey, privateKey } = createRsaKeyPair();

    const token = await new jose.SignJWT({ sub: 'user' })
      .setProtectedHeader({ alg: 'PS512', typ: 'JWT' })
      .setIssuer('issuer')
      .setAudience('aud1')
      .setExpirationTime('2m')
      .sign(privateKey);

    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
    const verified = verify.verifyJWT(token, {
      publicKeyOrSecret: publicPem,
      issuer: 'issuer',
      audience: 'aud1'
    });

    expect(verified).to.equal(true);
  });
});
