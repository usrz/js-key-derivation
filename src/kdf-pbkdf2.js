'use strict';

var hashes = require('./kdf-hashes');
var BaseKDF = require('./kdf-base');
var crypto = require('crypto');
var util = require('util');

function makeSpec(defaultSpec, spec) {
  var newSpec = {};

  // Normalize algorithm to upper case
  newSpec.algorithm = (spec.algorithm || defaultSpec.algorithm || 'PBKDF2').toUpperCase();

  // Normalize and validate the hash name
  newSpec.hash = hashes.validate(spec.hash || defaultSpec.hash || 'SHA256');

  // Normalize iterations
  if (spec.iterations && Number.isNaN(Number(spec.iterations)))
    throw new TypeError('Iterations is not a number');
  newSpec.iterations = Number(spec.iterations)
                    || Number(defaultSpec.iterations)
                    || 4096;

  // Normalize derived key length
  if (spec.derived_key_length && Number.isNaN(Number(spec.derived_key_length)))
    throw new TypeError('Derived key length is not a number');
  newSpec.derived_key_length = Number(spec.derived_key_length)
                            || Number(defaultSpec.derived_key_length)
                            || null;

  // Make sure we have the correct algorithm
  if (newSpec.algorithm != 'PBKDF2') throw new Error('Algorithm must be PBKDF2');

  // Check iterations (at least 4096)
  if (newSpec.iterations < 1) throw new Error('Iterations must be a number greater than zero');

  // Check or default derived key length to hash length
  if (newSpec.derived_key_length == null) {
    newSpec.derived_key_length = crypto.createHash(newSpec.hash).digest().length;
  } else if (newSpec.derived_key_length < 1) {
    throw new Error('Derived key length must be a number greater than zero');
  }

  // Return the new spec
  return newSpec;
}

// Our PBKDF2 shared function
function deriveKey(secret, salt, spec, callback) {
  crypto.pbkdf2(secret,
                salt,
                spec.iterations,
                spec.derived_key_length,
                spec.hash,
                callback);
}

// Our PBKDF2 class
function PBKDF2(kdfSpec) {
  if (!(this instanceof PBKDF2)) return new PBKDF2();

  var spec = makeSpec({}, kdfSpec || {});
  var saltLength = hashes.digestLength(spec.hash);
  BaseKDF.call(this, spec, saltLength, deriveKey);
}

// Default spec, always clone
var defaultSpec = makeSpec({}, {});
Object.defineProperty(PBKDF2, 'defaultSpec', {
  configurable: false,
  enumerable: true,
  get: function() {
    return JSON.parse(JSON.stringify(defaultSpec));
  }
});

// Inherit from base KDF
util.inherits(PBKDF2, BaseKDF);

// Export our class
exports = module.exports = PBKDF2;
