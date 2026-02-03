'use strict';

var JWT_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;
var SUPPORTED_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'HS256', 'HS384', 'HS512', 'PS256', 'PS384', 'ES256', 'ES384', 'ES512'];
var Mac = require('dw/crypto/Mac');
var Encoding = require('dw/crypto/Encoding');

/**
 * Validates JWT format (three dot-separated segments).
 * @param {string} jwt - JWT token.
 * @returns {boolean} True when format is valid.
 */
function isValidJWT(jwt) {
    return JWT_REGEX.test(jwt);
}

var JWTAlgoToSFCCMapping = {
    RS256: 'SHA256withRSA',
    RS512: 'SHA512withRSA',
    RS384: 'SHA384withRSA',
    HS256: Mac.HMAC_SHA_256,
    HS384: Mac.HMAC_SHA_384,
    HS512: Mac.HMAC_SHA_512,
    PS256: 'SHA256withRSA/PSS',
    PS384: 'SHA384withRSA/PSS',
    ES256: 'SHA256withECDSA',
    ES384: 'SHA384withECDSA',
    ES512: 'SHA512withECDSA'
};

/**
 * Encodes a base64 string into base64url.
 * @param {string} input - Base64 string.
 * @returns {string} Base64url string.
 */
function toBase64UrlEncoded(input) {
    return input.replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/m, '');
}

/**
 * Converts a base64url string to base64.
 * @param {string} input - Base64url string.
 * @returns {string|null} Base64 string or null when invalid.
 */
function base64UrlToBase64(input) {
    if (!input || typeof input !== 'string') {
        return null;
    }

    var base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    var pad = base64.length % 4;
    if (pad === 2) {
        base64 += '==';
    } else if (pad === 3) {
        base64 += '=';
    } else if (pad === 1) {
        return null;
    }

    return base64;
}

/**
 * Decodes base64url into bytes.
 * @param {string} input - Base64url string.
 * @returns {dw.util.Bytes|null} Decoded bytes or null.
 */
function fromBase64Url(input) {
    var base64 = base64UrlToBase64(input);
    if (!base64) {
        return null;
    }

    return Encoding.fromBase64(base64);
}

/**
 * Decodes base64url into a string.
 * @param {string} input - Base64url string.
 * @returns {string|null} Decoded string or null.
 */
function decodeBase64UrlToString(input) {
    var bytes = fromBase64Url(input);
    return bytes ? bytes.toString() : null;
}

module.exports.isValidJWT = isValidJWT;
module.exports.toBase64UrlEncoded = toBase64UrlEncoded;
module.exports.fromBase64Url = fromBase64Url;
module.exports.decodeBase64UrlToString = decodeBase64UrlToString;
module.exports.SUPPORTED_ALGORITHMS = SUPPORTED_ALGORITHMS;
module.exports.JWTAlgoToSFCCMapping = JWTAlgoToSFCCMapping;
