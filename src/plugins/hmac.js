'use strict';

var BaseKDF = require('./basekdf');
var hashes = require('../hashes');
var crypto = require('crypto');
var util = require('util');

function makeSpec(spec) {
  var newSpec = {};

  // Normalize algorithm to upper case
  newSpec.algorithm = (spec.algorithm || 'HMAC').toUpperCase();

  // Normalize and validate the hash name
  newSpec.hash = hashes.validate(spec.hash || 'SHA256');

  // Normalize derived key length
  if (spec.derived_key_length && Number.isNaN(Number(spec.derived_key_length)))
    throw new TypeError('Derived key length is not a number');
  newSpec.derived_key_length = Number(spec.derived_key_length)
                            || null;

  // Make sure we have the correct algorithm
  if (newSpec.algorithm != 'HMAC') throw new Error('Algorithm must be HMAC');

  // Check or default derived key length to hash length
  if (newSpec.derived_key_length == null) {
    newSpec.derived_key_length = crypto.createHash(newSpec.hash).digest().length;
  } else if (newSpec.derived_key_length < 1) {
    throw new Error('Derived key length must be a number greater than zero');
  } else if (newSpec.derived_key_length > crypto.createHash(newSpec.hash).digest().length) {
    throw new Error('Derived key length must be a number greater less than ' + crypto.createHash(newSpec.hash).digest().length);
  }

  // Return the new spec
  return newSpec;
}

// Our HMAC shared function
function deriveKey(secret, salt, spec, callback) {
  try {
    var hmac = crypto.createHmac(spec.hash, salt);
    hmac.write(secret);
    var hash = hmac.digest();
    if (spec.derived_key_length < hash.length) {
      hash = hash.slice(0, spec.derived_key_length);
    }
    callback(null, hash);
  } catch (error) {
    callback(error);
  }
}

// Our HMAC class
util.inherits(HMAC, BaseKDF);
function HMAC(kdfSpec) {
  if (!(this instanceof HMAC)) return new HMAC();

  var spec = makeSpec(kdfSpec || {});
  var saltLength = hashes.digestLength(spec.hash);
  BaseKDF.call(this, spec, saltLength, deriveKey);
}

// Default spec, always clone
var defaultSpec = makeSpec({});
Object.defineProperty(HMAC, 'defaultSpec', {
  configurable: false,
  enumerable: true,
  get: function() {
    return JSON.parse(JSON.stringify(defaultSpec));
  }
});

// Export our class
exports = module.exports = HMAC;
