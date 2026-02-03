const proxyquire = require('proxyquire').noCallThru();
const { createDwMocks } = require('./dw-mocks');

function decodeJwtWithoutVerify(jwt) {
  const parts = String(jwt || '').split('.');
  if (parts.length !== 3) {
    return null;
  }

  function decodeBase64Url(str) {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    const padded = pad === 2 ? `${base64}==` : pad === 3 ? `${base64}=` : pad === 0 ? base64 : null;
    if (!padded) {
      return null;
    }

    return Buffer.from(padded, 'base64').toString('utf8');
  }

  try {
    return {
      header: JSON.parse(decodeBase64Url(parts[0])),
      payload: JSON.parse(decodeBase64Url(parts[1])),
      signature: parts[2]
    };
  } catch (e) {
    return null;
  }
}

function loadJwtEcModules() {
  const mocks = createDwMocks();

  const jwtHelper = proxyquire('../../cartridges/plugin_jwt_ec/cartridge/scripts/jwt/jwtHelper', {
    'dw/crypto/Mac': mocks.Mac,
    'dw/crypto/Encoding': mocks.Encoding
  });

  const ecdsaTranscode = proxyquire('../../cartridges/plugin_jwt_ec/cartridge/scripts/jwt/ecdsaTranscode', {
    'dw/crypto/Encoding': mocks.Encoding,
    'dw/util/StringUtils': mocks.StringUtils
  });

  const sign = proxyquire('../../cartridges/plugin_jwt_ec/cartridge/scripts/jwt/sign', {
    '*/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    '~/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    '*/cartridge/scripts/jwt/ecdsaTranscode': ecdsaTranscode,
    '~/cartridge/scripts/jwt/ecdsaTranscode': ecdsaTranscode,
    'dw/crypto/Encoding': mocks.Encoding,
    'dw/util/Bytes': mocks.Bytes,
    'dw/crypto/Signature': mocks.Signature,
    'dw/util/StringUtils': mocks.StringUtils,
    'dw/crypto/Mac': mocks.Mac,
    'dw/crypto/KeyRef': mocks.KeyRef
  });

  const verify = proxyquire('../../cartridges/plugin_jwt_ec/cartridge/scripts/jwt/verify', {
    '*/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    '~/cartridge/scripts/jwt/jwtHelper': jwtHelper,
    '*/cartridge/scripts/jwt/ecdsaTranscode': ecdsaTranscode,
    '~/cartridge/scripts/jwt/ecdsaTranscode': ecdsaTranscode,
    'dw/util/Bytes': mocks.Bytes,
    'dw/crypto/Encoding': mocks.Encoding,
    'dw/crypto/Signature': mocks.Signature,
    'dw/util/StringUtils': mocks.StringUtils,
    'dw/crypto/Mac': mocks.Mac,
    'dw/crypto/CertificateRef': mocks.CertificateRef,
    'plugin_jwt': {
      decode: decodeJwtWithoutVerify
    }
  });

  return {
    mocks,
    jwtHelper,
    ecdsaTranscode,
    sign,
    verify
  };
}

module.exports = {
  loadJwtEcModules
};
