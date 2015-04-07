'use strict';

var BaseKDF = require('./basekdf');
var hashes = require('../hashes');
var scrypt = require('scrypt');
var util = require('util');

function makeSpec(defaultSpec, spec) {
  var newSpec = {};

  // Normalize algorithm and hash to upper case
  newSpec.algorithm = (spec.algorithm || defaultSpec.algorithm || 'SCRYPT').toUpperCase();
  newSpec.hash = hashes.validate(spec.hash || defaultSpec.hash || 'SHA256');

  // Normalize cpu/memory cost
  if (spec.cpu_memory_cost && Number.isNaN(Number(spec.cpu_memory_cost)))
    throw new TypeError('CPU/Memory cost is not a number');
  newSpec.cpu_memory_cost = Number(spec.cpu_memory_cost)
                         || Number(defaultSpec.cpu_memory_cost)
                         || 32768;

  // Normalize block size
  if (spec.block_size && Number.isNaN(Number(spec.block_size)))
    throw new TypeError('Block size is not a number');
  newSpec.block_size = Number(spec.block_size)
                    || Number(defaultSpec.block_size)
                    || 8;

  // Normalize parallelization
  if (spec.parallelization && Number.isNaN(Number(spec.parallelization)))
    throw new TypeError('Parallelization is not a number');
  newSpec.parallelization = Number(spec.parallelization)
                         || Number(defaultSpec.parallelization)
                         || 1;


  // Normalize parallelization
  if (spec.derived_key_length && Number.isNaN(Number(spec.derived_key_length)))
    throw new TypeError('Derived key length is not a number');
  newSpec.derived_key_length = Number(spec.derived_key_length)
                            || Number(defaultSpec.derived_key_length)
                            || 32;

  // Make sure we have the correct algorithm and hash
  if (newSpec.algorithm != 'SCRYPT') throw new Error('Algorithm must be SCRYPT');
  if (newSpec.hash != 'SHA256') throw new Error('Only SHA256 hashing supported: ' + newSpec.hash);

  // Validate block size and parallelization
  if (newSpec.block_size < 1) throw new Error('Block size must be a number greater than zero');
  if (newSpec.parallelization < 1) throw new Error('Parallelization must be a number greater than zero');
  if (newSpec.derived_key_length < 1) throw new Error('Derived key length must be a number greater than zero');

  // Validate parameters
  if (newSpec.cpu_memory_cost < 2 || (newSpec.cpu_memory_cost & (newSpec.cpu_memory_cost - 1)) != 0)
    throw new Error("CPU/Memory cost must be a power of 2 greater than 1");

  if (newSpec.cpu_memory_cost > 16777216 / newSpec.block_size)
  throw new Error("CPU/Memory cost is too large for given block size");

  if (newSpec.block_size > 16777216 / newSpec.parallelization)
    throw new Error("Block size too large for given parallelization");

  return newSpec;
}

function deriveKey(secret, salt, spec, callback) {
  scrypt.kdf(secret, {
               N: spec.cpu_memory_cost,
               r: spec.block_size,
               p: spec.parallelization
             },
             spec.derived_key_length,
             salt,
    function(error, result) {
      if (error) return callback(error);
      if (! result) return callback(new Error('No result from SCrypt function'));
      if (! result.hash) return callback(new Error('No hash from SCrypt function'));
      callback(null, result.hash);
    });
}

// Our Scrypt class
util.inherits(Scrypt, BaseKDF);
function Scrypt(kdfSpec) {
  if (!(this instanceof Scrypt)) return new Scrypt();

  var spec = makeSpec({}, kdfSpec || {});
  var saltLength = hashes.digestLength(spec.hash);
  BaseKDF.call(this, spec, saltLength, deriveKey);
}

// Default spec, always clone
var defaultSpec = makeSpec({}, {});
Object.defineProperty(Scrypt, 'defaultSpec', {
  configurable: false,
  enumerable: true,
  get: function() {
    return JSON.parse(JSON.stringify(defaultSpec));
  }
});

// Export our class
exports = module.exports = Scrypt;
