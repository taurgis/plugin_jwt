const proxyquire = require('proxyquire').noCallThru();
const { createDwMocks } = require('./dw-mocks');

function loadJwtModules() {
  const mocks = createDwMocks();

  const jwtHelper = proxyquire('../../cartridges/plugin_jwt/cartridge/scripts/jwt/jwtHelper', {
    'dw/crypto/Mac': mocks.Mac,
    'dw/crypto/Encoding': mocks.Encoding
  });

  const decode = proxyquire('../../cartridges/plugin_jwt/cartridge/scripts/jwt/decode', {
    '*/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    '~/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    'dw/system/Logger': mocks.Logger
  });

  const verifyHelpers = proxyquire('../../cartridges/plugin_jwt/cartridge/scripts/jwt/verifyHelpers', {});

  const sign = proxyquire('../../cartridges/plugin_jwt/cartridge/scripts/jwt/sign', {
    '*/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    '~/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    'dw/system/Logger': mocks.Logger,
    'dw/crypto/Encoding': mocks.Encoding,
    'dw/util/Bytes': mocks.Bytes,
    'dw/crypto/Signature': mocks.Signature,
    'dw/util/StringUtils': mocks.StringUtils,
    'dw/crypto/Mac': mocks.Mac,
    'dw/crypto/KeyRef': mocks.KeyRef
  });

  const verify = proxyquire('../../cartridges/plugin_jwt/cartridge/scripts/jwt/verify', {
    '*/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    '~/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    '*/cartridge/scripts/jwt/decode': decode,
    '~/cartridge/scripts/jwt/decode': decode,
    '*/cartridge/scripts/jwt/verifyHelpers': verifyHelpers,
    '~/cartridge/scripts/jwt/verifyHelpers': verifyHelpers,
    'dw/system/Logger': mocks.Logger,
    'dw/util/Bytes': mocks.Bytes,
    'dw/crypto/Encoding': mocks.Encoding,
    'dw/crypto/Signature': mocks.Signature,
    'dw/util/StringUtils': mocks.StringUtils,
    'dw/crypto/Mac': mocks.Mac,
    'dw/crypto/CertificateRef': mocks.CertificateRef,
    '*/cartridge/scripts/helpers/rsaToDer': {
      getRSAPublicKey: function () {
        return null;
      }
    },
    '~/cartridge/scripts/helpers/rsaToDer': {
      getRSAPublicKey: function () {
        return null;
      }
    }
  });

  const rsaToDer = proxyquire('../../cartridges/plugin_jwt/cartridge/scripts/helpers/rsaToDer', {
    'dw/crypto/Encoding': mocks.Encoding,
    '*/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    '~/cartridge/scripts/jwt/jwtHelper': jwtHelper
  });

  return {
    mocks: mocks,
    jwtHelper: jwtHelper,
    decode: decode,
    sign: sign,
    verify: verify,
    rsaToDer: rsaToDer
  };
}

module.exports = {
  loadJwtModules: loadJwtModules
};
