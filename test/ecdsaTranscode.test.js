const { expect } = require('chai');
const { loadJwtEcModules } = require('./helpers/jwt-ec-modules');

describe('ecdsaTranscode', function () {
  const { ecdsaTranscode, mocks } = loadJwtEcModules();

  function makeJoseSignature(partLen, opts) {
    const r = Buffer.alloc(partLen, 0);
    const s = Buffer.alloc(partLen, 0);

    if (opts && opts.highBit) {
      r[0] = 0x80;
      s[0] = 0x80;
      r[r.length - 1] = 0x01;
      s[s.length - 1] = 0x02;
    } else {
      r[r.length - 1] = 0x01;
      s[s.length - 1] = 0x02;
    }

    return new mocks.Bytes(Buffer.concat([r, s]));
  }

  function roundtrip(alg, partLen, opts) {
    const jose = makeJoseSignature(partLen, opts);
    const der = ecdsaTranscode.joseToDer(jose, alg);
    const joseBack = ecdsaTranscode.derToJose(der, alg);
    expect(mocks.Encoding.toHex(joseBack)).to.equal(mocks.Encoding.toHex(jose));
  }

  it('roundtrips ES256', function () {
    roundtrip('ES256', 32);
  });

  it('roundtrips ES384', function () {
    roundtrip('ES384', 48);
  });

  it('roundtrips ES512', function () {
    roundtrip('ES512', 66);
  });

  it('roundtrips when high bit requires INTEGER padding', function () {
    roundtrip('ES256', 32, { highBit: true });
  });

  it('throws for invalid JOSE signature length', function () {
    const bad = new mocks.Bytes(Buffer.alloc(10, 0));
    expect(function () {
      ecdsaTranscode.joseToDer(bad, 'ES256');
    }).to.throw('Invalid JOSE signature length');
  });

  it('throws for invalid DER signature', function () {
    const badDer = new mocks.Bytes(Buffer.from('010203', 'hex'));
    expect(function () {
      ecdsaTranscode.derToJose(badDer, 'ES256');
    }).to.throw('Invalid DER signature');
  });

  it('encodes ES512 DER with long-form SEQUENCE length when needed', function () {
    const partLen = 66;
    const r = Buffer.alloc(partLen, 0x01);
    const s = Buffer.alloc(partLen, 0x02);
    const jose = new mocks.Bytes(Buffer.concat([r, s]));

    const der = ecdsaTranscode.joseToDer(jose, 'ES512');
    const derHex = mocks.Encoding.toHex(der);

    // When the SEQUENCE length is > 127, DER uses the long-form length encoding.
    expect(derHex.substring(0, 4)).to.equal('3081');

    const joseBack = ecdsaTranscode.derToJose(der, 'ES512');
    expect(mocks.Encoding.toHex(joseBack)).to.equal(mocks.Encoding.toHex(jose));
  });

  it('throws for unsupported algorithms', function () {
    const jose = new mocks.Bytes(Buffer.alloc(64, 0));
    expect(function () {
      ecdsaTranscode.joseToDer(jose, 'none');
    }).to.throw('Unsupported ECDSA algorithm');
  });
});
