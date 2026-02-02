const { expect } = require('chai');
const { loadJwtModules } = require('./helpers/jwt-modules');

describe('rsaToDer', function () {
  const { rsaToDer } = loadJwtModules();

  it('returns null for missing inputs', function () {
    expect(rsaToDer.getRSAPublicKey(null, null)).to.equal(null);
  });

  it('returns a DER base64 string for valid inputs', function () {
    const result = rsaToDer.getRSAPublicKey('AQID', 'AQAB');
    expect(result).to.be.a('string');
    expect(result.length).to.be.greaterThan(0);
  });
});
