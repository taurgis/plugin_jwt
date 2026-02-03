const crypto = require('crypto');

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value && Buffer.isBuffer(value.buffer)) {
    return value.buffer;
  }
  return Buffer.from(String(value || ''), 'utf8');
}

function Bytes(input) {
  this.buffer = toBuffer(input);
}

Bytes.prototype.toString = function (encoding) {
  return this.buffer.toString(encoding || 'utf8');
};

const Encoding = {
  toBase64: function (bytes) {
    return toBuffer(bytes).toString('base64');
  },
  fromBase64: function (base64) {
    return new Bytes(Buffer.from(base64, 'base64'));
  },
  toHex: function (bytes) {
    return toBuffer(bytes).toString('hex');
  },
  fromHex: function (hex) {
    return new Bytes(Buffer.from(hex, 'hex'));
  }
};

function normalizeAlgorithm(algorithm) {
  const map = {
    HMAC_SHA_256: 'sha256',
    HMAC_SHA_384: 'sha384',
    HMAC_SHA_512: 'sha512',
    sha256: 'sha256',
    sha384: 'sha384',
    sha512: 'sha512'
  };

  return map[algorithm] || 'sha256';
}

function Mac(algorithm) {
  this.algorithm = normalizeAlgorithm(algorithm);
}

Mac.HMAC_SHA_256 = 'HMAC_SHA_256';
Mac.HMAC_SHA_384 = 'HMAC_SHA_384';
Mac.HMAC_SHA_512 = 'HMAC_SHA_512';

Mac.prototype.digest = function (inputBytes, secretBytes) {
  const hmac = crypto.createHmac(this.algorithm, toBuffer(secretBytes));
  hmac.update(toBuffer(inputBytes));
  return new Bytes(hmac.digest());
};

function Signature() {}

function normalizeSignatureAlgorithm(algorithm) {
  const map = {
    SHA256withECDSA: 'sha256',
    SHA384withECDSA: 'sha384',
    SHA512withECDSA: 'sha512',
    SHA256withRSA: 'RSA-SHA256',
    SHA384withRSA: 'RSA-SHA384',
    SHA512withRSA: 'RSA-SHA512'
  };

  return map[algorithm] || null;
}

function getRsaPssParams(algorithm) {
  const map = {
    'SHA256withRSA/PSS': { hash: 'sha256', saltLength: 32 },
    'SHA384withRSA/PSS': { hash: 'sha384', saltLength: 48 },
    'SHA512withRSA/PSS': { hash: 'sha512', saltLength: 64 }
  };

  return map[algorithm] || null;
}

Signature.prototype.signBytes = function (contentBytes, keyBytes, algorithm) {
  const data = toBuffer(contentBytes);
  const key = toBuffer(keyBytes).toString('utf8');

  const pssParams = getRsaPssParams(algorithm);
  if (pssParams) {
    return new Bytes(crypto.sign(pssParams.hash, data, {
      key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: pssParams.saltLength
    }));
  }

  const nodeAlg = normalizeSignatureAlgorithm(algorithm);
  if (!nodeAlg) {
    throw new Error(`Unsupported Signature algorithm in tests: ${algorithm}`);
  }

  // For ECDSA, SFCC/JCA-style signatures are DER encoded.
  const isEcdsa = String(algorithm).indexOf('ECDSA') !== -1;
  const options = isEcdsa ? { key, dsaEncoding: 'der' } : { key };

  return new Bytes(crypto.sign(nodeAlg, data, options));
};

Signature.prototype.verifyBytesSignature = function (signatureBytes, contentBytes, keyBytes, algorithm) {
  const data = toBuffer(contentBytes);
  const signature = toBuffer(signatureBytes);
  const key = toBuffer(keyBytes).toString('utf8');

  const pssParams = getRsaPssParams(algorithm);
  if (pssParams) {
    return crypto.verify(pssParams.hash, data, {
      key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: pssParams.saltLength
    }, signature);
  }

  const nodeAlg = normalizeSignatureAlgorithm(algorithm);
  if (!nodeAlg) {
    throw new Error(`Unsupported Signature algorithm in tests: ${algorithm}`);
  }

  const isEcdsa = String(algorithm).indexOf('ECDSA') !== -1;
  const options = isEcdsa ? { key, dsaEncoding: 'der' } : { key };

  return crypto.verify(nodeAlg, data, options, signature);
};

const Logger = {
  error: function () {},
  warn: function () {},
  info: function () {},
  debug: function () {}
};

const StringUtils = {
  format: function (str) {
    const args = Array.prototype.slice.call(arguments, 1);
    return String(str).replace(/\{(\d+)\}/g, function (match, index) {
      return args[index];
    });
  }
};

function KeyRef(alias) {
  this.alias = alias;
}

function CertificateRef(alias) {
  this.alias = alias;
}

function createDwMocks() {
  return {
    Bytes: Bytes,
    Encoding: Encoding,
    Mac: Mac,
    Signature: Signature,
    Logger: Logger,
    StringUtils: StringUtils,
    KeyRef: KeyRef,
    CertificateRef: CertificateRef
  };
}

module.exports = {
  createDwMocks: createDwMocks
};
