const { expect } = require('chai');
const { loadJwtModules } = require('./helpers/jwt-modules');

describe('verifyJWT', function () {
  const { sign, verify } = loadJwtModules();

  function signToken(payload) {
    return sign.signJWT(payload, {
      algorithm: 'HS256',
      privateKeyOrSecret: 'secret'
    });
  }

  it('verifies a valid token with audience and issuer', function () {
    const payload = {
      sub: 'user',
      exp: Math.floor(Date.now() / 1000) + 60,
      aud: 'aud1',
      iss: 'issuer'
    };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret',
      audience: 'aud1',
      issuer: 'issuer'
    });

    expect(result).to.equal(true);
  });

  it('rejects invalid signatures', function () {
    const payload = { exp: Math.floor(Date.now() / 1000) + 60 };
    const token = signToken(payload);
    const parts = token.split('.');
    parts[2] = 'tampered';

    const result = verify.verifyJWT(parts.join('.'), {
      publicKeyOrSecret: 'secret'
    });

    expect(result).to.equal(false);
  });

  it('rejects expired tokens', function () {
    const payload = { exp: Math.floor(Date.now() / 1000) - 10 };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret'
    });

    expect(result).to.equal(false);
  });

  it('allows expired tokens when ignoreExpiration is true', function () {
    const payload = { exp: Math.floor(Date.now() / 1000) - 10 };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret',
      ignoreExpiration: true
    });

    expect(result).to.equal(true);
  });

  it('rejects tokens with non-numeric exp', function () {
    const payload = { exp: 'not-a-number' };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret'
    });

    expect(result).to.equal(false);
  });

  it('requires exp when requireExpiration is true', function () {
    const payload = { sub: 'user' };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret',
      requireExpiration: true
    });

    expect(result).to.equal(false);
  });

  it('rejects tokens before not-before time', function () {
    const now = Math.floor(Date.now() / 1000);
    const payload = { exp: now + 60, nbf: now + 30 };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret'
    });

    expect(result).to.equal(false);
  });

  it('allows nbf within clock tolerance', function () {
    const now = Math.floor(Date.now() / 1000);
    const payload = { exp: now + 60, nbf: now + 30 };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret',
      clockTolerance: 30
    });

    expect(result).to.equal(true);
  });

  it('rejects tokens with iat in the future', function () {
    const now = Math.floor(Date.now() / 1000);
    const payload = { exp: now + 60, iat: now + 30 };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret'
    });

    expect(result).to.equal(false);
  });

  it('handles audience arrays', function () {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + 60,
      aud: ['aud1', 'aud2']
    };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret',
      audience: 'aud2'
    });

    expect(result).to.equal(true);
  });

  it('rejects audience mismatches', function () {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + 60,
      aud: 'aud1'
    };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret',
      audience: 'other'
    });

    expect(result).to.equal(false);
  });

  it('rejects issuer mismatches', function () {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + 60,
      iss: 'issuer'
    };
    const token = signToken(payload);

    const result = verify.verifyJWT(token, {
      publicKeyOrSecret: 'secret',
      issuer: 'other'
    });

    expect(result).to.equal(false);
  });

  it('throws for unsupported algorithms', function () {
    const payload = { exp: Math.floor(Date.now() / 1000) + 60 };
    const token = signToken(payload);

    expect(function () {
      verify.verifyJWT(token, {
        publicKeyOrSecret: 'secret',
        allowedAlgorithms: ['RS256']
      });
    }).to.throw('not supported');
  });

  it('throws for invalid allowedAlgorithms type', function () {
    const payload = { exp: Math.floor(Date.now() / 1000) + 60 };
    const token = signToken(payload);

    expect(function () {
      verify.verifyJWT(token, {
        publicKeyOrSecret: 'secret',
        allowedAlgorithms: { foo: 'bar' }
      });
    }).to.throw('allowedAlgorithms must be a string or array');
  });

  it('throws for invalid clockTolerance', function () {
    const payload = { exp: Math.floor(Date.now() / 1000) + 60 };
    const token = signToken(payload);

    expect(function () {
      verify.verifyJWT(token, {
        publicKeyOrSecret: 'secret',
        clockTolerance: -1
      });
    }).to.throw('clockTolerance must be a non-negative number');
  });

  it('returns false for invalid format', function () {
    const result = verify.verifyJWT('invalid', {
      publicKeyOrSecret: 'secret'
    });

    expect(result).to.equal(false);
  });
});
