const { expect } = require('chai');
const { loadJwtModules } = require('./helpers/jwt-modules');

describe('signJWT', function () {
  const { sign, jwtHelper } = loadJwtModules();

  function parseSegment(segment) {
    return JSON.parse(jwtHelper.decodeBase64UrlToString(segment));
  }

  it('throws for invalid payload', function () {
    expect(function () {
      sign.signJWT('nope', { algorithm: 'HS256', privateKeyOrSecret: 'secret' });
    }).to.throw('Invalid payload');
  });

  it('throws for unsupported algorithm', function () {
    expect(function () {
      sign.signJWT({ sub: 'user' }, { algorithm: 'none', privateKeyOrSecret: 'secret' });
    }).to.throw('not supported');
  });

  it('throws when secret is missing', function () {
    expect(function () {
      sign.signJWT({ sub: 'user' }, { algorithm: 'HS256' });
    }).to.throw('private key or secret not supplied');
  });

  it('creates a signed token with header and payload', function () {
    const payload = { sub: 'user' };
    const token = sign.signJWT(payload, {
      algorithm: 'HS256',
      privateKeyOrSecret: 'secret',
      kid: 'kid-1'
    });

    const parts = token.split('.');
    expect(parts).to.have.length(3);

    const header = parseSegment(parts[0]);
    const decodedPayload = parseSegment(parts[1]);

    expect(header.alg).to.equal('HS256');
    expect(header.kid).to.equal('kid-1');
    expect(decodedPayload.sub).to.equal('user');
  });
});
