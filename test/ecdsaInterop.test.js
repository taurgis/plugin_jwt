const { expect } = require('chai');
const crypto = require('crypto');
const { loadJwtEcModules } = require('./helpers/jwt-ec-modules');

describe('jwt ecdsa interop', function () {
  const { sign, verify } = loadJwtEcModules();

  it('signs ES256 and verifies with jose + custom verify', async function () {
    const jose = await import('jose');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });

    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

    const token = sign.signJWT({
      sub: 'user',
      exp: Math.floor(Date.now() / 1000) + 60,
      iss: 'issuer',
      aud: 'aud1'
    }, {
      algorithm: 'ES256',
      privateKeyOrSecret: privatePem,
      kid: 'kid-ec'
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
    expect(result.protectedHeader.alg).to.equal('ES256');
    expect(result.protectedHeader.kid).to.equal('kid-ec');
    expect(result.payload.sub).to.equal('user');
  });

  it('verifies jose ES512 token with custom verify', async function () {
    const jose = await import('jose');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp521r1'
    });

    const token = await new jose.SignJWT({ sub: 'user' })
      .setProtectedHeader({ alg: 'ES512', typ: 'JWT' })
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
