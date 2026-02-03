'use strict';

/**
 * Normalizes allowed algorithms. Returns supported algorithms when not provided.
 * @param {string|Array|null|undefined} algorithms - Allowed algorithms.
 * @param {Array} supportedAlgorithms - Supported algorithms.
 * @returns {Array|null} Normalized algorithms or null when invalid.
 */
function normalizeAlgorithms(algorithms, supportedAlgorithms) {
    if (algorithms === null || typeof algorithms === 'undefined') {
        return supportedAlgorithms;
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
 * Parses a NumericDate claim (seconds since epoch).
 * @param {string|number} value - Claim value.
 * @returns {number|null} Parsed value or null when invalid.
 */
function parseNumericDate(value) {
    if (typeof value === 'number' && Number.isFinite(value)) {
        return value;
    }

    if (typeof value === 'string' && value !== '' && /^[0-9]+$/.test(value)) {
        return parseInt(value, 10);
    }

    return null;
}

/**
 * Returns clock tolerance in seconds.
 * @param {Object} options - Verification options.
 * @returns {number} Clock tolerance in seconds.
 */
function getClockToleranceSeconds(options) {
    if (!options || options.clockTolerance === null || typeof options.clockTolerance === 'undefined') {
        return 0;
    }

    if (typeof options.clockTolerance !== 'number' || !Number.isFinite(options.clockTolerance) || options.clockTolerance < 0) {
        throw new Error('clockTolerance must be a non-negative number');
    }

    return options.clockTolerance;
}

/**
 * Validates time-based claims (exp, nbf, iat).
 * @param {Object} payload - JWT payload.
 * @param {Object} options - Verification options.
 * @returns {boolean} True when time claims are valid.
 */
function validateTimeClaims(payload, options) {
    var nowSeconds = Math.floor(Date.now() / 1000);
    var clockTolerance = getClockToleranceSeconds(options);

    if (!options || !options.ignoreExpiration) {
        var hasExp = payload && payload.exp !== undefined && payload.exp !== null;
        var exp = hasExp ? parseNumericDate(payload.exp) : null;
        if (hasExp && exp === null) {
            return false;
        }
        if (!hasExp) {
            if (options && options.requireExpiration) {
                return false;
            }
        } else if (nowSeconds >= exp + clockTolerance) {
            return false;
        }
    }

    if (payload && payload.nbf !== undefined && payload.nbf !== null) {
        var nbf = parseNumericDate(payload.nbf);
        if (nbf === null) {
            return false;
        }
        if (nowSeconds + clockTolerance < nbf) {
            return false;
        }
    }

    if (payload && payload.iat !== undefined && payload.iat !== null) {
        var iat = parseNumericDate(payload.iat);
        if (iat === null) {
            return false;
        }
        if (iat - clockTolerance > nowSeconds) {
            return false;
        }
    }

    return true;
}

module.exports.normalizeAlgorithms = normalizeAlgorithms;
module.exports.validateTimeClaims = validateTimeClaims;
