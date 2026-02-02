const { expect } = require('chai');
const { loadJwtModules } = require('./helpers/jwt-modules');

describe('jwtHelper', function () {
  const { jwtHelper, mocks } = loadJwtModules();

  it('validates JWT format', function () {
    expect(jwtHelper.isValidJWT('aaa.bbb.ccc')).to.equal(true);
    expect(jwtHelper.isValidJWT('aaa.bbb')).to.equal(false);
  });

  it('base64url encodes strings', function () {
    expect(jwtHelper.toBase64UrlEncoded('ab+/=')).to.equal('ab-_');
  });

  it('decodes base64url to string', function () {
    const base64 = mocks.Encoding.toBase64(new mocks.Bytes('hello'));
    const base64url = jwtHelper.toBase64UrlEncoded(base64);
    expect(jwtHelper.decodeBase64UrlToString(base64url)).to.equal('hello');
  });

  it('returns null for invalid base64url', function () {
    expect(jwtHelper.fromBase64Url('abcde')).to.equal(null);
  });

  it('exposes supported algorithms', function () {
    expect(jwtHelper.SUPPORTED_ALGORITHMS).to.include('HS256');
  });
});
