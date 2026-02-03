'use strict';

var sign = require('~/cartridge/scripts/jwt/sign.js');
var verify = require('~/cartridge/scripts/jwt/verify.js');

// Reuse decode implementation from base plugin.
var base = require('plugin_jwt');

module.exports.sign = sign.signJWT;
module.exports.verify = verify.verifyJWT;
module.exports.decode = base.decode;
