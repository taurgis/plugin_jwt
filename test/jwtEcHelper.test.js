const { expect } = require('chai');
const { loadJwtEcModules } = require('./helpers/jwt-ec-modules');

describe('jwtHelper (plugin_jwt_ec)', function () {
  const { jwtHelper } = loadJwtEcModules();

  it('exposes supported algorithms including ES*', function () {
    expect(jwtHelper.SUPPORTED_ALGORITHMS).to.include('ES256');
    expect(jwtHelper.SUPPORTED_ALGORITHMS).to.include('ES384');
    expect(jwtHelper.SUPPORTED_ALGORITHMS).to.include('ES512');
  });

  it('maps ES* algorithms to SFCC Signature algorithms', function () {
    expect(jwtHelper.JWTAlgoToSFCCMapping.ES256).to.equal('SHA256withECDSA');
    expect(jwtHelper.JWTAlgoToSFCCMapping.ES384).to.equal('SHA384withECDSA');
    expect(jwtHelper.JWTAlgoToSFCCMapping.ES512).to.equal('SHA512withECDSA');
  });
});
