'use strict';

var server = require('server');
var System = require('dw/system/System');

/**
 * Checks if the JWT test endpoints are enabled for non-production environments.
 * @returns {boolean} True when the instance is not production.
 */
function isJWTTestEnabled() {
    return System.getInstanceType() !== System.PRODUCTION_SYSTEM;
}

/**
 * ECDSA signing/verifying using Business Manager key/certificate aliases.
 *
 * URL: /JWTECTest-KeyRef
 * Querystring:
 * - alg: ES256|ES384|ES512 (default ES256)
 * - keyAlias: private key alias in BM
 * - certAlias: certificate alias in BM
 *
 * Mini guide: generate and upload key/cert to Business Manager
 * (Administration > Operations > Private Keys and Certificates)
 *
 * ES256 (P-256) example:
 * 1) Generate EC keypair + X.509 cert:
 *    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out jwt-ec.key.pem
 *    openssl req -new -x509 -key jwt-ec.key.pem -sha256 -days 365 -subj "/CN=jwt-ec-signing" -out jwt-ec.cert.pem
 * 2) Package private key + cert as PKCS#12 for upload:
 *    openssl pkcs12 -export -name jwt-ec-signing -inkey jwt-ec.key.pem -in jwt-ec.cert.pem -out jwt-ec-signing.p12 -passout pass:
 */
server.get('KeyRef', function (req, res, next) {
    if (!isJWTTestEnabled()) {
        res.setStatusCode(404);
        res.json({ error: 'Not Found' });
        return next();
    }

    var KeyRef = require('dw/crypto/KeyRef');
    var CertificateRef = require('dw/crypto/CertificateRef');

    var algorithm = req.querystring.alg || 'ES256';
    var allowed = ['ES256', 'ES384', 'ES512'];
    if (allowed.indexOf(algorithm) === -1) {
        res.setStatusCode(400);
        res.json({ error: 'Unsupported alg', allowed: allowed });
        return next();
    }

    var privateKeyAlias = req.querystring.keyAlias || 'jwt-ec-signing-key';
    var certificateAlias = req.querystring.certAlias || 'jwt-ec-signing-cert';

    var jwt = require('plugin_jwt_ec');

    var signOptions = {
        privateKeyOrSecret: new KeyRef(privateKeyAlias),
        algorithm: algorithm,
        kid: privateKeyAlias
    };

    var payload = {
        sub: 'sample subject',
        iss: 'sample-issuer',
        aud: 'sample-audience',
        exp: Math.floor(Date.now() / 1000) + 60
    };

    var jwtToken = jwt.sign(payload, signOptions);
    var decodedToken = jwt.decode(jwtToken);

    var verifyOptions = {
        publicKeyOrSecret: new CertificateRef(certificateAlias),
        issuer: 'sample-issuer',
        audience: 'sample-audience'
    };

    var verified = jwt.verify(jwtToken, verifyOptions);

    res.json({
        algorithm: algorithm,
        keyAlias: privateKeyAlias,
        certAlias: certificateAlias,
        decodedToken: decodedToken,
        verified: verified,
        jwtToken: jwtToken
    });

    return next();
});

module.exports = server.exports();
