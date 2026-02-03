'use strict';

var jwtHelper = require('*/cartridge/scripts/jwt/jwtHelper');
var Encoding = require('dw/crypto/Encoding');
var Bytes = require('dw/util/Bytes');
var Signature = require('dw/crypto/Signature');
var StringUtils = require('dw/util/StringUtils');
var Mac = require('dw/crypto/Mac');
var KeyRef = require('dw/crypto/KeyRef');

var ecdsaTranscode = require('*/cartridge/scripts/jwt/ecdsaTranscode');

var JWTAlgoToSFCCMapping = jwtHelper.JWTAlgoToSFCCMapping;

/**
 * Signs a JWT with RSA algorithms.
 * @param {string} input - Input string to sign.
 * @param {string|dw.crypto.KeyRef} privateKey - Private key.
 * @param {string} algorithm - JWT algorithm.
 * @returns {string} Base64 signature.
 */
function signWithRSA(input, privateKey, algorithm) {
    var contentToSignInBytes = new Bytes(input);

    var apiSig = new Signature();
    var signedBytes;
    if (privateKey instanceof KeyRef) {
        signedBytes = apiSig.signBytes(contentToSignInBytes, privateKey, JWTAlgoToSFCCMapping[algorithm]);
    } else {
        signedBytes = apiSig.signBytes(contentToSignInBytes, new Bytes(privateKey), JWTAlgoToSFCCMapping[algorithm]);
    }

    return Encoding.toBase64(signedBytes);
}

/**
 * Signs a JWT with ECDSA algorithms.
 * Converts DER-encoded ECDSA signature to JOSE (raw R||S) before encoding.
 * @param {string} input - Input string to sign.
 * @param {string|dw.crypto.KeyRef} privateKey - Private key.
 * @param {string} algorithm - JWT algorithm.
 * @returns {string} Base64 signature.
 */
function signWithECDSA(input, privateKey, algorithm) {
    var contentToSignInBytes = new Bytes(input);

    var apiSig = new Signature();
    var derSignatureBytes;
    if (privateKey instanceof KeyRef) {
        derSignatureBytes = apiSig.signBytes(contentToSignInBytes, privateKey, JWTAlgoToSFCCMapping[algorithm]);
    } else {
        derSignatureBytes = apiSig.signBytes(contentToSignInBytes, new Bytes(privateKey), JWTAlgoToSFCCMapping[algorithm]);
    }

    var joseSignatureBytes = ecdsaTranscode.derToJose(derSignatureBytes, algorithm);
    return Encoding.toBase64(joseSignatureBytes);
}

/**
 * Signs a JWT with HMAC algorithms.
 * @param {string} input - Input string to sign.
 * @param {string} secret - HMAC secret.
 * @param {string} algorithm - JWT algorithm.
 * @returns {string} Base64 signature.
 */
function signWithHMAC(input, secret, algorithm) {
    var mac = new Mac(JWTAlgoToSFCCMapping[algorithm]);
    var inputInBytes = new Bytes(input);
    var secretInBytes = new Bytes(secret);

    var output = mac.digest(inputInBytes, secretInBytes);
    return Encoding.toBase64(output);
}

var JWTAlgoToSignMapping = {
    RS256: signWithRSA,
    RS384: signWithRSA,
    RS512: signWithRSA,
    HS256: signWithHMAC,
    HS384: signWithHMAC,
    HS512: signWithHMAC,
    PS256: signWithRSA,
    PS384: signWithRSA,
    ES256: signWithECDSA,
    ES384: signWithECDSA,
    ES512: signWithECDSA
};

/**
 * Signs a payload into a JWT string.
 * @param {Object} payload - JWT payload.
 * @param {Object} options - Signing options.
 * @returns {string} Signed JWT.
 */
function signJWT(payload, options) {
    if (!payload || typeof payload !== 'object') {
        throw new Error('Invalid payload passed to create JWT token');
    }

    var algorithm = options.algorithm;
    var supportedAlgorithms = jwtHelper.SUPPORTED_ALGORITHMS;
    if (supportedAlgorithms.indexOf(algorithm) === -1) {
        throw new Error(StringUtils.format('JWT Algorithm {0} not supported', algorithm));
    }

    var header = {
        alg: options.algorithm,
        typ: 'JWT',
        kid: options.kid
    };

    var headerBase64 = Encoding.toBase64(new Bytes(JSON.stringify(header)));
    var headerBase64UrlEncoded = jwtHelper.toBase64UrlEncoded(headerBase64);

    var payloadBase64 = Encoding.toBase64(new Bytes(JSON.stringify(payload)));
    var payloadBase64UrlEncoded = jwtHelper.toBase64UrlEncoded(payloadBase64);

    var signingInput = headerBase64UrlEncoded + '.' + payloadBase64UrlEncoded;

    var privateKeyOrSecret;
    if (options.privateKeyOrSecret && typeof options.privateKeyOrSecret === 'string') {
        privateKeyOrSecret = options.privateKeyOrSecret;
    } else if (options.privateKeyOrSecret instanceof KeyRef) {
        privateKeyOrSecret = options.privateKeyOrSecret;
    }

    if (!privateKeyOrSecret) {
        throw new Error('Cannot sign JWT token as private key or secret not supplied');
    }

    var signFunction = JWTAlgoToSignMapping[algorithm];
    if (!signFunction) {
        throw new Error(StringUtils.format('No sign function found for supplied algorithm {0}', algorithm));
    }

    if (signFunction === signWithHMAC && typeof privateKeyOrSecret !== 'string') {
        throw new Error('HMAC signing requires a shared secret string');
    }

    var jwtSignatureB64 = signFunction(signingInput, privateKeyOrSecret, algorithm);
    var jwtSignatureUrlEncoded = jwtHelper.toBase64UrlEncoded(jwtSignatureB64);

    return headerBase64UrlEncoded + '.' + payloadBase64UrlEncoded + '.' + jwtSignatureUrlEncoded;
}

module.exports.signJWT = signJWT;
