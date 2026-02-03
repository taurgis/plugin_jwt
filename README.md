# sfcc_jwt
An implementation of [JSON Web Tokens](https://www.rfc-editor.org/rfc/rfc7519) for Salesforce Commerce Cloud SFRA.

This repo contains two cartridges:

- `plugin_jwt`: HMAC + RSA (and RSA-PSS) JWT signing/verifying.
- `plugin_jwt_ec`: adds Elliptic Curve (ECDSA) JWT signing/verifying (`ES256/ES384/ES512`) as a separate cartridge.

# Install

Upload the cartridge(s) to your sandbox and add them to the cartridge path.

- RSA/HMAC only: add `plugin_jwt`
- ECDSA too: add `plugin_jwt_ec:plugin_jwt` (the EC cartridge depends on `plugin_jwt` for `decode()`)

Upload helpers:

```sh
npm run uploadCartridge
npm run uploadCartridge:ec
```

## Testing

Run the Node-only unit tests with Mocha and Chai:

```sh
npm test
```

References:

1. https://mochajs.org/#getting-started
2. https://www.chaijs.com/guide/installation/
3. https://www.rfc-editor.org/rfc/rfc7519
4. https://www.rfc-editor.org/rfc/rfc7515
5. https://www.rfc-editor.org/rfc/rfc7518
6. https://www.rfc-editor.org/rfc/rfc7517

# Usage

### jwt.sign(payload, options)

Returns the JsonWebToken as string.

`payload` is an object literal representing valid JSON. The library does not auto-add registered claims.

`options`:

* `privateKeyOrSecret` is a string containing either the secret for HMAC or the private key for RSA/ECDSA, or a `dw.crypto.KeyRef`.
* `algorithm` is one of:
	* `plugin_jwt`: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`
	* `plugin_jwt_ec`: all of the above plus `ES256`, `ES384`, `ES512`
* `kid` is optional and added to the JWT header.

Sign with HMAC SHA256

```js
var jwt = require('plugin_jwt');
var options = {};
options.privateKeyOrSecret = 'my_secret';
options.algorithm = 'HS256';
var token = jwt.sign({ foo: 'bar' }, options);
```

Sign with RSA SHA256
```js
var privateKey = 'my_private_key';
var options = {};
options.privateKeyOrSecret = privateKey;
options.algorithm = 'RS256';
var token = jwt.sign({ foo: 'bar' }, options);
```

Sign with RSA using a Business Manager private key alias
```js
var KeyRef = require('dw/crypto/KeyRef');
var options = {};
options.privateKeyOrSecret = new KeyRef('jwt-signing-key');
options.algorithm = 'RS256';
options.kid = 'jwt-signing-key';
var token = jwt.sign({ foo: 'bar' }, options);
```


Sign with ECDSA (ES256)

```js
var jwt = require('plugin_jwt_ec');
var privateKeyPem = '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n';

var options = {};
options.privateKeyOrSecret = privateKeyPem;
options.algorithm = 'ES256';

var token = jwt.sign({ foo: 'bar' }, options);
```

Sign with ECDSA using a Business Manager private key alias

```js
var jwt = require('plugin_jwt_ec');
var KeyRef = require('dw/crypto/KeyRef');

var options = {};
options.privateKeyOrSecret = new KeyRef('jwt-ec-signing-key');
options.algorithm = 'ES256';
options.kid = 'jwt-ec-signing-key';

var token = jwt.sign({ foo: 'bar' }, options);
```
### jwt.verify(token, options)

Returns `true` when the signature is valid and basic claims checks pass, otherwise `false`.
It may throw when an unsupported algorithm is used or when key material is missing.

`token` is the JsonWebToken string

`options`:

* `publicKeyOrSecret` is a string containing either the secret for HMAC algorithms or the public key for RSA/ECDSA, a `dw.crypto.CertificateRef`, or a function that returns a single key. For RSA keys, the function must return `{ modulus, exponential }` (base64url).
* `ignoreExpiration` skips the `exp` check.
* `audience` checks the JWT `aud` (string or array).
* `issuer` checks the JWT `iss`.
* `allowedAlgorithms` is an optional string or array to allowlist acceptable `alg` values.

Verify HMAC SHA256

```js
var jwt = require('plugin_jwt');
var token = 'my_token';
var options = {};
options.publicKeyOrSecret = 'my_secret';
var isValid = jwt.verify(token, options);
```

Verify ECDSA (ES256)

```js
var jwt = require('plugin_jwt_ec');
var publicKeyPem = '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n';
var token = 'my_token';

var options = {};
options.publicKeyOrSecret = publicKeyPem;
options.allowedAlgorithms = ['ES256'];

var isValid = jwt.verify(token, options);
```

Verify RSA SHA256
```js
var publicKey = 'my_public_key';
var token = 'my_token';
var options = {};
options.publicKeyOrSecret = publicKey;
var isValid = jwt.verify(token, options);
```

### jwt.decode(token, options)

Returns `{ header, payload, signature }` without verifying if the signature is valid.

`token` is the JsonWebToken string

```js
var decoded = jwt.decode(token);
```

## Algorithms supported

Array of supported algorithms.

### plugin_jwt

alg Parameter Value | Digital Signature or MAC Algorithm
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSA using SHA-256 hash algorithm
RS384 | RSA using SHA-384 hash algorithm
RS512 | RSA using SHA-512 hash algorithm
PS256 | RSA-PSS using SHA-256 hash algorithm
PS384 | RSA-PSS using SHA-384 hash algorithm

### plugin_jwt_ec

All `plugin_jwt` algorithms plus:

alg Parameter Value | Digital Signature Algorithm
----------------|----------------------------
ES256 | ECDSA using P-256 and SHA-256
ES384 | ECDSA using P-384 and SHA-384
ES512 | ECDSA using P-521 and SHA-512

Note: For ECDSA JWTs, the JWS signature format is the fixed-length raw `R || S` concatenation, not DER.
This cartridge converts between DER signatures (as commonly produced/consumed by crypto libraries) and the JOSE/JWS format.
See RFC 7518 §3.4.


## JWTTest controller (demo)

Three demo endpoints are available in non-production instances only:

* `JWTTest-RSA` - signs and verifies using inline RSA keys.
* `JWTTest-RSAKeyRef` - signs with `dw.crypto.KeyRef` and verifies with `dw.crypto.CertificateRef`.
* `JWTTest-HMAC` - signs and verifies with a shared secret.

The controller returns `{ decodedToken, verified, jwtToken }` and is gated by instance type (disabled in production).

## JWTECTest controller (ECDSA demo)

An ECDSA-only demo endpoint is available (non-production instances only):

* `JWTECTest-KeyRef` - signs with `dw.crypto.KeyRef` and verifies with `dw.crypto.CertificateRef` using `plugin_jwt_ec`.

Example usage:

* `/JWTECTest-KeyRef?alg=ES256&keyAlias=jwt-ec-signing-key&certAlias=jwt-ec-signing-cert`

You can generate a local ES256 keypair/cert bundle under `tmp/`:

```sh
mkdir -p tmp
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out tmp/jwt-ec-signing.key.pem
openssl req -new -x509 -key tmp/jwt-ec-signing.key.pem -sha256 -days 365 -subj "/CN=jwt-ec-signing" -out tmp/jwt-ec-signing.cert.pem
openssl pkcs12 -export -name jwt-ec-signing-key -inkey tmp/jwt-ec-signing.key.pem -in tmp/jwt-ec-signing.cert.pem -out tmp/jwt-ec-signing.p12 -passout pass:
```

## Resources

1. https://jwt.io/
2. https://jwt.io/introduction/
3. https://github.com/auth0/node-jsonwebtoken
4. https://www.rfc-editor.org/rfc/rfc7519
5. https://www.rfc-editor.org/rfc/rfc7515
6. https://www.rfc-editor.org/rfc/rfc7518
7. https://www.rfc-editor.org/rfc/rfc7517
8. https://www.rfc-editor.org/rfc/rfc4648
9. https://www.rfc-editor.org/rfc/rfc8725
10. https://www.rfc-editor.org/rfc/rfc3279
10. https://documentation.b2c.commercecloud.salesforce.com/DOC2/topic/com.demandware.dochelp/DWAPI/scriptapi/html/api/class_dw_crypto_KeyRef.html
11. https://documentation.b2c.commercecloud.salesforce.com/DOC2/topic/com.demandware.dochelp/DWAPI/scriptapi/html/api/class_dw_crypto_CertificateRef.html
12. https://documentation.b2c.commercecloud.salesforce.com/DOC2/topic/com.demandware.dochelp/DWAPI/scriptapi/html/api/class_dw_crypto_Signature.html
13. https://documentation.b2c.commercecloud.salesforce.com/DOC2/topic/com.demandware.dochelp/DWAPI/scriptapi/html/api/class_dw_crypto_Mac.html
14. https://documentation.b2c.commercecloud.salesforce.com/DOC2/topic/com.demandware.dochelp/DWAPI/scriptapi/html/api/class_dw_system_System.html

## Note

This repository is heavily inspired from node-js repo [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
