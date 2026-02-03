const { expect } = require('chai');
const crypto = require('crypto');
const { loadJwtEcModules } = require('./helpers/jwt-ec-modules');

describe('plugin_jwt_ec sign/verify', function () {
  const { sign, verify, jwtHelper } = loadJwtEcModules();

  function signEcToken(alg, privatePem, payload, kid) {
    return sign.signJWT(payload, {
      algorithm: alg,
      privateKeyOrSecret: privatePem,
      kid: kid
    });
  }

  function verifyEcToken(token, publicPem, opts) {
    return verify.verifyJWT(token, {
      publicKeyOrSecret: publicPem,
      issuer: opts && opts.issuer,
      audience: opts && opts.audience,
      ignoreExpiration: opts && opts.ignoreExpiration,
      allowedAlgorithms: opts && opts.allowedAlgorithms
    });
  }

  it('signs and verifies ES256', function () {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

    const token = signEcToken('ES256', privatePem, {
      sub: 'user',
      exp: Math.floor(Date.now() / 1000) + 60,
      iss: 'issuer',
      aud: 'aud1'
    }, 'kid-ec');

    const parts = token.split('.');
    expect(parts).to.have.length(3);
    const header = JSON.parse(jwtHelper.decodeBase64UrlToString(parts[0]));
    expect(header.alg).to.equal('ES256');
    expect(header.kid).to.equal('kid-ec');

    // ES256 signatures are raw R||S where each part is 32 bytes.
    const sigBytes = jwtHelper.fromBase64Url(parts[2]);
    expect(sigBytes).to.not.equal(null);
    expect(sigBytes.buffer.length).to.equal(64);

    expect(verifyEcToken(token, publicPem, { issuer: 'issuer', audience: 'aud1' })).to.equal(true);
  });

  it('rejects tampered signatures', function () {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

    const token = signEcToken('ES256', privatePem, {
      exp: Math.floor(Date.now() / 1000) + 60
    });

    const parts = token.split('.');
    parts[2] = `${parts[2]}tamper`;
    expect(verifyEcToken(parts.join('.'), publicPem, {})).to.equal(false);
  });

  it('rejects expired tokens unless ignoreExpiration is true', function () {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

    const token = signEcToken('ES256', privatePem, {
      exp: Math.floor(Date.now() / 1000) - 10
    });

    expect(verifyEcToken(token, publicPem, {})).to.equal(false);
    expect(verifyEcToken(token, publicPem, { ignoreExpiration: true })).to.equal(true);
  });

  it('rejects issuer/audience mismatches', function () {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

    const token = signEcToken('ES256', privatePem, {
      exp: Math.floor(Date.now() / 1000) + 60,
      iss: 'issuer',
      aud: 'aud1'
    });

    expect(verifyEcToken(token, publicPem, { issuer: 'other', audience: 'aud1' })).to.equal(false);
    expect(verifyEcToken(token, publicPem, { issuer: 'issuer', audience: 'other' })).to.equal(false);
  });

  it('throws when alg is not allowlisted', function () {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

    const token = signEcToken('ES256', privatePem, {
      exp: Math.floor(Date.now() / 1000) + 60
    });

    expect(function () {
      verifyEcToken(token, publicPem, { allowedAlgorithms: ['HS256'] });
    }).to.throw('not supported');
  });

  it('accepts allowedAlgorithms as a string', function () {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

    const token = signEcToken('ES256', privatePem, {
      exp: Math.floor(Date.now() / 1000) + 60
    });

    const verified = verify.verifyJWT(token, {
      publicKeyOrSecret: publicPem,
      allowedAlgorithms: 'ES256'
    });

    expect(verified).to.equal(true);
  });

  it('returns false for invalid base64url signature characters', function () {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

    const token = signEcToken('ES256', privatePem, {
      exp: Math.floor(Date.now() / 1000) + 60
    });

    const parts = token.split('.');
    parts[2] = '***';
    expect(verifyEcToken(parts.join('.'), publicPem, {})).to.equal(false);
  });

  it('returns false for wrong decoded signature length', function () {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

    const token = signEcToken('ES256', privatePem, {
      exp: Math.floor(Date.now() / 1000) + 60
    });
    const parts = token.split('.');

    // Valid base64url which decodes to the wrong size.
    const wrongSigB64Url = Buffer.from('deadbeef', 'hex')
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');

    parts[2] = wrongSigB64Url;
    expect(verifyEcToken(parts.join('.'), publicPem, {})).to.equal(false);
  });

  it('signs and verifies ES384 and ES512', function () {
    const { publicKey: pub384, privateKey: priv384 } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp384r1'
    });
    const token384 = signEcToken('ES384', priv384.export({ type: 'pkcs8', format: 'pem' }), {
      exp: Math.floor(Date.now() / 1000) + 60
    });
    expect(verifyEcToken(token384, pub384.export({ type: 'spki', format: 'pem' }), {})).to.equal(true);

    const { publicKey: pub521, privateKey: priv521 } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp521r1'
    });
    const token512 = signEcToken('ES512', priv521.export({ type: 'pkcs8', format: 'pem' }), {
      exp: Math.floor(Date.now() / 1000) + 60
    });
    expect(verifyEcToken(token512, pub521.export({ type: 'spki', format: 'pem' }), {})).to.equal(true);
  });
});
