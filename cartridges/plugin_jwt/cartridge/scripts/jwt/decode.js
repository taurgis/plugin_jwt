'use strict';

var jwtHelper = require('~/cartridge/scripts/jwt/jwtHelper');
var Logger = require('dw/system/Logger');

/**
 * Extracts the JWT header.
 * @param {string} jwt - JWT token.
 * @returns {Object|null} Parsed header or null.
 */
function getHeaderFromJWT(jwt) {
    var encodedHeader = jwt.split('.')[0];
    var decodedHeader = jwtHelper.decodeBase64UrlToString(encodedHeader);
    var jwtHeaderObj = {};

    if (!decodedHeader) {
        Logger.error('Error decoding jwt token header');
        return null;
    }

    try {
        jwtHeaderObj = JSON.parse(decodedHeader);
    } catch (error) {
        Logger.error('Error parsing jwt token header');
        return null;
    }

    return jwtHeaderObj;
}

/**
 * Extracts the JWT payload.
 * @param {string} jwt - JWT token.
 * @returns {Object|null} Parsed payload or null.
 */
function getPayloadFromJWT(jwt) {
    var encodedPayload = jwt.split('.')[1];
    var decodedPayload = jwtHelper.decodeBase64UrlToString(encodedPayload);
    var jwtPayloadObj = {};

    if (!decodedPayload) {
        Logger.error('Error decoding jwt token payload');
        return null;
    }

    try {
        jwtPayloadObj = JSON.parse(decodedPayload);
    } catch (error) {
        Logger.error('Error parsing jwt token payload');
        return null;
    }

    return jwtPayloadObj;
}

/**
 * Extracts the JWT signature.
 * @param {string} jwt - JWT token.
 * @returns {string} Signature segment.
 */
function getSignatureFromJWT(jwt) {
    return jwt.split('.')[2];
}

/**
 * Decodes a JWT without verifying the signature.
 * @param {string} jwt - JWT token.
 * @returns {Object|null} Decoded parts or null.
 */
function decodeJWT(jwt) {
    if (!jwtHelper.isValidJWT(jwt)) {
        return null;
    }

    var header = getHeaderFromJWT(jwt);
    if (!header) {
        return null;
    }

    var payload = getPayloadFromJWT(jwt);
    if (!payload) {
        return null;
    }

    var signature = getSignatureFromJWT(jwt);
    if (!signature) {
        return null;
    }

    return {
        header: header,
        payload: payload,
        signature: signature
    };
}

module.exports.decodeJWT = decodeJWT;
