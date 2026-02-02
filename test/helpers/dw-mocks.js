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

Signature.prototype.signBytes = function () {
  throw new Error('Signature not implemented in tests');
};

Signature.prototype.verifyBytesSignature = function () {
  throw new Error('Signature not implemented in tests');
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

function createDwMocks() {
  return {
    Bytes: Bytes,
    Encoding: Encoding,
    Mac: Mac,
    Signature: Signature,
    Logger: Logger,
    StringUtils: StringUtils
  };
}

module.exports = {
  createDwMocks: createDwMocks
};
