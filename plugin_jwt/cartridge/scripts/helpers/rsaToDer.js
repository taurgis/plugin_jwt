/**
 * Highly custom logic to create public key.
 * Return public key as DER
 * https://stackoverflow.com/questions/18835132/xml-to-pem-in-node-js
 * https://github.com/tracker1/node-rsa-pem-from-mod-exp
 */

'use strict';

var Encoding = require('dw/crypto/Encoding');

/**
 * Builds a DER-encoded RSA public key from base64url modulus and exponent.
 * @param {string} modulusB64 - Base64url modulus.
 * @param {string} exponentB64 - Base64url exponent.
 * @returns {string|null} Base64 DER public key or null when inputs are invalid.
 */
function getRSAPublicKey(modulusB64, exponentB64) {
    var jwtHelper = require('*/cartridge/scripts/jwt/jwtHelper');

    /**
     * Pads a hex string to preserve sign.
     * @param {string} hexStr - Hex string.
     * @returns {string} Padded hex string.
     */
    function prepadSigned(hexStr) {
        var msb = hexStr[0];
        if (
            (msb >= '8' && msb <= '9')
            || (msb >= 'a' && msb <= 'f')
            || (msb >= 'A' && msb <= 'F')
        ) {
            return '00' + hexStr;
        }

        return hexStr;
    }

    /**
     * Converts a number to hex.
     * @param {number} number - Number to convert.
     * @returns {string} Hex string.
     */
    function toHex(number) {
        var nstr = number.toString(16);
        if (nstr.length % 2 === 0) {
            return nstr;
        }

        return '0' + nstr;
    }

    /**
     * Encodes ASN.1 DER length field.
     * @param {number} length - Field length.
     * @returns {string} Hex-encoded length.
     */
    function encodeLengthHex(length) {
        if (length <= 127) {
            return toHex(length);
        }

        var nHex = toHex(length);
        var lengthOfLengthByte = 128 + (nHex.length / 2); // 0x80 + numbytes
        return toHex(lengthOfLengthByte) + nHex;
    }

    var modulus = jwtHelper.fromBase64Url(modulusB64);
    var exponent = jwtHelper.fromBase64Url(exponentB64);

    if (!modulus || !exponent) {
        return null;
    }

    var modulusHex = Encoding.toHex(modulus);
    var exponentHex = Encoding.toHex(exponent);

    modulusHex = prepadSigned(modulusHex);
    exponentHex = prepadSigned(exponentHex);

    var modlen = modulusHex.length / 2;
    var explen = exponentHex.length / 2;

    var encodedModlen = encodeLengthHex(modlen);
    var encodedExplen = encodeLengthHex(explen);
    var encodedPubkey = '30'
        + encodeLengthHex(
            modlen
            + explen
            + (encodedModlen.length / 2)
            + (encodedExplen.length / 2)
            + 2
        )
        + '02' + encodedModlen + modulusHex
        + '02' + encodedExplen + exponentHex;

    var seq2 = '30 0d '
        + '06 09 2a 86 48 86 f7 0d 01 01 01'
        + '05 00 '
        + '03' + encodeLengthHex((encodedPubkey.length / 2) + 1)
        + '00' + encodedPubkey;

    seq2 = seq2.replace(/ /g, '');

    var derHex = '30' + encodeLengthHex(seq2.length / 2) + seq2;

    derHex = derHex.replace(/ /g, '');

    var derB64 = Encoding.toBase64(Encoding.fromHex(derHex));

    // var pem = '-----BEGIN PUBLIC KEY-----\n'
    //     + derB64.match(/.{1,64}/g).join('\n')
    //     + '\n-----END PUBLIC KEY-----\n';

    return derB64;
}

module.exports.getRSAPublicKey = getRSAPublicKey;
