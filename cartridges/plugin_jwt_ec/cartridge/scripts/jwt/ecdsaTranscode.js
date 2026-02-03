'use strict';

var Encoding = require('dw/crypto/Encoding');
var StringUtils = require('dw/util/StringUtils');

var ALGO_TO_PART_LEN = {
    ES256: 32,
    ES384: 48,
    ES512: 66
};

/**
 * Gets the byte length for each ECDSA signature component (R and S).
 * @param {string} algorithm - JWT alg: ES256/ES384/ES512.
 * @returns {number|null} Component length in bytes or null.
 */
function getPartLength(algorithm) {
    return ALGO_TO_PART_LEN[algorithm] || null;
}

/**
 * Returns the number of bytes represented by a hex string.
 * @param {string} hex - Hex string.
 * @returns {number} Byte length.
 */
function hexByteLength(hex) {
    return hex.length / 2;
}

/**
 * Left-pads a hex string with zero bytes.
 * @param {string} hex - Hex string.
 * @param {number} targetBytes - Target length in bytes.
 * @returns {string|null} Padded hex or null if input exceeds target.
 */
function leftPadHex(hex, targetBytes) {
    var targetHexLen = targetBytes * 2;
    if (hex.length > targetHexLen) {
        return null;
    }

    var padded = hex;
    while (padded.length < targetHexLen) {
        padded = '00' + padded;
    }

    return padded;
}

/**
 * Removes leading zero bytes from a hex string.
 * @param {string} hex - Hex string.
 * @returns {string} Trimmed hex.
 */
function trimLeadingZeros(hex) {
    var trimmed = hex;
    while (trimmed.length > 2 && trimmed.indexOf('00') === 0) {
        trimmed = trimmed.substring(2);
    }
    return trimmed;
}

/**
 * Reads an ASN.1 DER length value.
 * @param {string} hex - Full DER payload as hex.
 * @param {number} offset - Offset in hex string.
 * @returns {{length:number, offset:number}|null} Parsed length and new offset.
 */
function readDerLength(hex, offset) {
    var first = parseInt(hex.substring(offset, offset + 2), 16);
    if (first < 0x80) {
        return { length: first, offset: offset + 2 };
    }

    var numBytes = first - 0x80;
    if (numBytes === 0) {
        return null;
    }

    var lengthHex = hex.substring(offset + 2, offset + 2 + (numBytes * 2));
    if (lengthHex.length !== numBytes * 2) {
        return null;
    }

    var length = parseInt(lengthHex, 16);
    return { length: length, offset: offset + 2 + (numBytes * 2) };
}

/**
 * Encodes a length value into ASN.1 DER length bytes.
 * @param {number} length - Length to encode.
 * @returns {string} DER length as hex.
 */
function encodeDerLength(length) {
    if (length < 128) {
        var hex = length.toString(16);
        return hex.length === 1 ? '0' + hex : hex;
    }

    var lenHex = length.toString(16);
    if (lenHex.length % 2 === 1) {
        lenHex = '0' + lenHex;
    }

    var numBytes = lenHex.length / 2;
    var first = (0x80 + numBytes).toString(16);
    return first + lenHex;
}

/**
 * Parses a DER INTEGER from a hex payload.
 * @param {string} hex - Full DER payload as hex.
 * @param {number} offset - Offset in hex string.
 * @returns {{valueHex:string, offset:number}|null} Integer value and new offset.
 */
function parseDerInteger(hex, offset) {
    var tag = hex.substring(offset, offset + 2);
    if (tag !== '02') {
        return null;
    }

    var lenInfo = readDerLength(hex, offset + 2);
    if (!lenInfo) {
        return null;
    }

    var len = lenInfo.length;
    var valueStart = lenInfo.offset;
    var valueEnd = valueStart + (len * 2);
    var valueHex = hex.substring(valueStart, valueEnd);
    if (valueHex.length !== len * 2) {
        return null;
    }

    return { valueHex: valueHex, offset: valueEnd };
}

/**
 * Converts DER-encoded ECDSA signature into JOSE (raw R||S) signature bytes.
 * @param {dw.util.Bytes} derSignatureBytes - DER signature bytes.
 * @param {string} algorithm - JWT alg: ES256/ES384/ES512.
 * @returns {dw.util.Bytes} JOSE signature bytes.
 */
function derToJose(derSignatureBytes, algorithm) {
    var partLen = getPartLength(algorithm);
    if (!partLen) {
        throw new Error(StringUtils.format('Unsupported ECDSA algorithm {0}', algorithm));
    }

    var hex = Encoding.toHex(derSignatureBytes);
    var offset = 0;

    if (hex.substring(offset, offset + 2) !== '30') {
        throw new Error('Invalid DER signature (expected SEQUENCE)');
    }

    var seqLenInfo = readDerLength(hex, offset + 2);
    if (!seqLenInfo) {
        throw new Error('Invalid DER signature (bad length)');
    }
    offset = seqLenInfo.offset;

    var rInfo = parseDerInteger(hex, offset);
    if (!rInfo) {
        throw new Error('Invalid DER signature (missing r)');
    }
    offset = rInfo.offset;

    var sInfo = parseDerInteger(hex, offset);
    if (!sInfo) {
        throw new Error('Invalid DER signature (missing s)');
    }

    var rHex = trimLeadingZeros(rInfo.valueHex);
    var sHex = trimLeadingZeros(sInfo.valueHex);

    var rPadded = leftPadHex(rHex, partLen);
    var sPadded = leftPadHex(sHex, partLen);
    if (!rPadded || !sPadded) {
        throw new Error('Invalid DER signature (r/s length)');
    }

    return Encoding.fromHex(rPadded + sPadded);
}

/**
 * Converts JOSE (raw R||S) signature bytes to DER-encoded ECDSA signature bytes.
 * @param {dw.util.Bytes} joseSignatureBytes - Raw signature bytes.
 * @param {string} algorithm - JWT alg: ES256/ES384/ES512.
 * @returns {dw.util.Bytes} DER signature bytes.
 */
function joseToDer(joseSignatureBytes, algorithm) {
    var partLen = getPartLength(algorithm);
    if (!partLen) {
        throw new Error(StringUtils.format('Unsupported ECDSA algorithm {0}', algorithm));
    }

    var joseHex = Encoding.toHex(joseSignatureBytes);
    var expectedBytes = partLen * 2;
    if (hexByteLength(joseHex) !== expectedBytes) {
        throw new Error('Invalid JOSE signature length');
    }

    var rHex = joseHex.substring(0, partLen * 2);
    var sHex = joseHex.substring(partLen * 2);

    rHex = trimLeadingZeros(rHex);
    sHex = trimLeadingZeros(sHex);

    // If the high bit is set, prefix 00 to keep INTEGER positive.
    if (parseInt(rHex.substring(0, 2), 16) >= 0x80) {
        rHex = '00' + rHex;
    }
    if (parseInt(sHex.substring(0, 2), 16) >= 0x80) {
        sHex = '00' + sHex;
    }

    var rLen = hexByteLength(rHex);
    var sLen = hexByteLength(sHex);

    var rInt = '02' + encodeDerLength(rLen) + rHex;
    var sInt = '02' + encodeDerLength(sLen) + sHex;
    var seqBody = rInt + sInt;

    var seq = '30' + encodeDerLength(hexByteLength(seqBody)) + seqBody;
    return Encoding.fromHex(seq);
}

module.exports.derToJose = derToJose;
module.exports.joseToDer = joseToDer;
