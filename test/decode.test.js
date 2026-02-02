const { expect } = require('chai');
const { loadJwtModules } = require('./helpers/jwt-modules');

describe('decodeJWT', function () {
  const { jwtHelper, decode, mocks } = loadJwtModules();

  function encodeSegment(obj) {
    const base64 = mocks.Encoding.toBase64(new mocks.Bytes(JSON.stringify(obj)));
    return jwtHelper.toBase64UrlEncoded(base64);
  }

  it('decodes a valid token', function () {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { sub: 'user' };
    const token = encodeSegment(header) + '.' + encodeSegment(payload) + '.sig';
    const decoded = decode.decodeJWT(token);

    expect(decoded.header.alg).to.equal('HS256');
    expect(decoded.payload.sub).to.equal('user');
    expect(decoded.signature).to.equal('sig');
  });

  it('returns null for invalid format', function () {
    expect(decode.decodeJWT('invalid')).to.equal(null);
  });

  it('returns null for invalid JSON segments', function () {
    const badHeader = jwtHelper.toBase64UrlEncoded(
      mocks.Encoding.toBase64(new mocks.Bytes('not-json'))
    );
    const payload = encodeSegment({ sub: 'user' });
    const token = badHeader + '.' + payload + '.sig';

    expect(decode.decodeJWT(token)).to.equal(null);
  });
});
