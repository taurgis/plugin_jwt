'use strict';

var jwtHelper = require('~/cartridge/scripts/jwt/jwtHelper');
var jwtDecode = require('plugin_jwt').decode;
var Bytes = require('dw/util/Bytes');
var Encoding = require('dw/crypto/Encoding');
var Signature = require('dw/crypto/Signature');
var StringUtils = require('dw/util/StringUtils');
var Mac = require('dw/crypto/Mac');
var CertificateRef = require('dw/crypto/CertificateRef');

var ecdsaTranscode = require('~/cartridge/scripts/jwt/ecdsaTranscode');

var JWTAlgoToSFCCMapping = jwtHelper.JWTAlgoToSFCCMapping;

/**
 * Normalizes allowed algorithms into an array.
 * @param {string|Array} algorithms - Allowed algorithms.
 * @returns {Array|null} Array of algorithms or null.
 */
function normalizeAlgorithms(algorithms) {
    if (!algorithms) {
        return null;
    }

    if (typeof algorithms === 'string') {
        return [algorithms];
    }

    if (Array.isArray(algorithms)) {
        return algorithms;
    }

    return null;
}

/**
 * Compares two strings with minimal timing differences.
 * @param {string} a - First string.
 * @param {string} b - Second string.
 * @returns {boolean} True when equal.
 */
function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') {
        return false;
    }

    var maxLen = Math.max(a.length, b.length);
    var diff = a.length === b.length ? 0 : 1;

    for (var i = 0; i < maxLen; i++) {
        var codeA = i < a.length ? a.charCodeAt(i) : 0;
        var codeB = i < b.length ? b.charCodeAt(i) : 0;
        diff += Math.abs(codeA - codeB);
    }

    return diff === 0;
}

/**
 * Verifies RSA signatures.
 * @param {string} signature - Base64url signature.
 * @param {string} input - Signed input.
 * @param {string|dw.crypto.CertificateRef} publicKey - Public key.
 * @param {string} algorithm - JWT algorithm.
 * @returns {boolean} True when verified.
 */
function createRSAVerifier(signature, input, publicKey, algorithm) {
    var jwtSignatureInBytes = jwtHelper.fromBase64Url(signature);
    if (!jwtSignatureInBytes) {
        return false;
    }

    var contentToVerifyInBytes = new Bytes(input);
    var apiSig = new Signature();
    if (publicKey instanceof CertificateRef) {
        return apiSig.verifyBytesSignature(jwtSignatureInBytes, contentToVerifyInBytes, publicKey, JWTAlgoToSFCCMapping[algorithm]);
    }

    return apiSig.verifyBytesSignature(jwtSignatureInBytes, contentToVerifyInBytes, new Bytes(publicKey), JWTAlgoToSFCCMapping[algorithm]);
}

/**
 * Verifies ECDSA signatures.
 * Converts JOSE (raw R||S) signature to DER before verification.
 * @param {string} signature - Base64url signature.
 * @param {string} input - Signed input.
 * @param {string|dw.crypto.CertificateRef} publicKey - Public key.
 * @param {string} algorithm - JWT algorithm.
 * @returns {boolean} True when verified.
 */
function createECDSAVerifier(signature, input, publicKey, algorithm) {
    var joseSignatureBytes = jwtHelper.fromBase64Url(signature);
    if (!joseSignatureBytes) {
        return false;
    }

    var derSignatureBytes;
    try {
        derSignatureBytes = ecdsaTranscode.joseToDer(joseSignatureBytes, algorithm);
    } catch (e) {
        return false;
    }
    var contentToVerifyInBytes = new Bytes(input);

    var apiSig = new Signature();
    if (publicKey instanceof CertificateRef) {
        return apiSig.verifyBytesSignature(derSignatureBytes, contentToVerifyInBytes, publicKey, JWTAlgoToSFCCMapping[algorithm]);
    }

    return apiSig.verifyBytesSignature(derSignatureBytes, contentToVerifyInBytes, new Bytes(publicKey), JWTAlgoToSFCCMapping[algorithm]);
}

/**
 * Verifies HMAC signatures.
 * @param {string} signature - Base64url signature.
 * @param {string} input - Signed input.
 * @param {string} secret - HMAC secret.
 * @param {string} algorithm - JWT algorithm.
 * @returns {boolean} True when verified.
 */
function createHMACVerifier(signature, input, secret, algorithm) {
    var mac = new Mac(JWTAlgoToSFCCMapping[algorithm]);
    var inputInBytes = new Bytes(input);
    var secretInBytes = new Bytes(secret);

    var outputInBytes = mac.digest(inputInBytes, secretInBytes);
    var outputInString = Encoding.toBase64(outputInBytes);
    var urlEncodedOutput = jwtHelper.toBase64UrlEncoded(outputInString);

    return timingSafeEqual(signature, urlEncodedOutput);
}

var JWTAlgoToVerifierMapping = {
    RS256: createRSAVerifier,
    RS384: createRSAVerifier,
    RS512: createRSAVerifier,
    HS256: createHMACVerifier,
    HS384: createHMACVerifier,
    HS512: createHMACVerifier,
    PS256: createRSAVerifier,
    PS384: createRSAVerifier,
    PS512: createRSAVerifier,
    ES256: createECDSAVerifier,
    ES384: createECDSAVerifier,
    ES512: createECDSAVerifier
};

/**
 * Verifies a JWT and validates basic claims.
 * @param {string} jwt - JWT token.
 * @param {Object} options - Verification options.
 * @returns {boolean} True when verified and valid.
 */
function verifyJWT(jwt, options) {
    var config = options || {};

    if (!jwtHelper.isValidJWT(jwt)) {
        return false;
    }

    var decodedToken = jwtDecode(jwt);
    if (!decodedToken) {
        return false;
    }

    var algorithm = decodedToken.header.alg;
    var parts = jwt.split('.');

    if (!algorithm) {
        return false;
    }

    var allowedAlgorithms = normalizeAlgorithms(config.allowedAlgorithms) || jwtHelper.SUPPORTED_ALGORITHMS;
    if (allowedAlgorithms.indexOf(algorithm) === -1) {
        throw new Error(StringUtils.format('JWT Algorithm {0} not supported', algorithm));
    }

    var header = parts[0];
    var payloadSegment = parts[1];
    var jwtSig = parts[2];
    var contentToVerify = header + '.' + payloadSegment;

    var publicKeyOrSecret;
    if (config.publicKeyOrSecret && typeof config.publicKeyOrSecret === 'string') {
        publicKeyOrSecret = config.publicKeyOrSecret;
    } else if (config.publicKeyOrSecret instanceof CertificateRef) {
        publicKeyOrSecret = config.publicKeyOrSecret;
    } else if (config.publicKeyOrSecret && typeof config.publicKeyOrSecret === 'function') {
        var jsonWebKey = config.publicKeyOrSecret(decodedToken);

        // Optional: support RSA and EC JWKs when running in SFCC.
        if (jsonWebKey && jsonWebKey.modulus && jsonWebKey.exponential) {
            var keyHelper = require('plugin_jwt/cartridge/scripts/helpers/rsaToDer');
            publicKeyOrSecret = keyHelper.getRSAPublicKey(jsonWebKey.modulus, jsonWebKey.exponential);
        } else if (jsonWebKey && jsonWebKey.kty === 'EC' && jsonWebKey.x && jsonWebKey.y && jsonWebKey.crv) {
            try {
                var CertificateUtils = require('dw/crypto/CertificateUtils');
                publicKeyOrSecret = CertificateUtils.parsePublicKeyFromJWK(JSON.stringify(jsonWebKey));
            } catch (e) {
                // Ignore and fall through to error below.
            }
        }
    }

    if (!publicKeyOrSecret) {
        throw new Error('Cannot verify JWT token as public key or secret not supplied');
    }

    var verifier = JWTAlgoToVerifierMapping[algorithm];
    if (!verifier) {
        throw new Error(StringUtils.format('No verifier function found for supplied algorithm {0}', algorithm));
    }

    if (verifier === createHMACVerifier && typeof publicKeyOrSecret !== 'string') {
        throw new Error('HMAC verification requires a shared secret string');
    }

    var verified = verifier(jwtSig, contentToVerify, publicKeyOrSecret, algorithm);
    if (!verified) {
        return false;
    }

    var payload = decodedToken.payload;
    if (!config.ignoreExpiration) {
        var jwtExp = payload.exp;
        var expirationDate = new Date(jwtExp * 1000);
        var currentDate = new Date();
        if (expirationDate < currentDate) {
            return false;
        }
    }

    if (config.audience) {
        var aud = payload.aud;
        if (Array.isArray(aud)) {
            if (aud.indexOf(config.audience) === -1) {
                return false;
            }
        } else if (config.audience !== aud) {
            return false;
        }
    }

    if (config.issuer) {
        var iss = payload.iss;
        if (iss !== config.issuer) {
            return false;
        }
    }

    return true;
}

module.exports.verifyJWT = verifyJWT;
