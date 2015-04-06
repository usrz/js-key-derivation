'use strict';

var hashes = require('./kdf-hashes');
var BaseKDF = require('./kdf-base');
var bcrypt = require('bcrypt');
var util = require('util');

/* ========================================================================== */
/* Bcrypt's "own" base 64 madness                                             */
/* ========================================================================== */

var bcrypt_alphabet = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
var base64_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var bcrypt_values = new Array(256);
var base64_values = new Array(256);

(function() {
  for (var i = 0; i < 64; i++) {
    bcrypt_values[bcrypt_alphabet.charCodeAt(i)] = base64_alphabet.charAt(i);
    base64_values[base64_alphabet.charCodeAt(i)] = bcrypt_alphabet.charAt(i);
  }
})();

// ..CA.uOD/eaGAOmJB.yMBv.PCfKSDPWVE/iYEvubFf6eGQGhHASkHwenIgqqJQ2tKBCwKxOzLha2MRm5NBy8Ny//OiLCPSXFQCjIQyvLRi7OSTHRTDTUTzfXUjraVT3dWEDgW0PjXkbmYUnpZEzsZ1/valLybVX1cFj4c1v7dl8.eWIBfGUEf2gHgmsKhW4NiHEQi3QTjncWkXoZlH0cl4AfmoMinYYloIkoo4wrpo8uqZIxrJU0r5g3sps6tZ49uKFAu6RDvqdGwapJxK1Mx7BPyrNSzbZV0LlY07xb1r9e2cJh3MVk38hn4stq5c5t6NFw69Rz7td28dp59N189u
// AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==

function bufferToString(buffer) {
  var string = buffer.toString('base64').replace(/=*$/g, '');
  var result = [];
  for (var i = 0; i < string.length; i++) {
    result.push(base64_values[string.charCodeAt(i)]);
  }
  return result.join('');
}

function stringToBuffer(string) {
  var result = [];
  for (var i = 0; i < string.length; i++) {
    result.push(bcrypt_values[string.charCodeAt(i)]);
  }
  return new Buffer(result.join(''), 'base64');
}

/* ========================================================================== */

function makeSpec(defaultSpec, spec) {
  var newSpec = {};

  // Normalize algorithm to upper case
  newSpec.algorithm = (spec.algorithm || defaultSpec.algorithm || 'BCRYPT').toUpperCase();

  // Normalize and validate the hash name
  var hash = spec.hash || defaultSpec.hash || null;
  if (hash) newSpec.hash = hashes.validate(hash);

  // Normalize rounds
  if (spec.rounds && Number.isNaN(Number(spec.rounds)))
    throw new TypeError('Rounds is not a number');
  newSpec.rounds = Number(spec.rounds)
                || Number(defaultSpec.rounds)
                || 10;

  // Make sure we have the correct algorithm
  if (newSpec.algorithm != 'BCRYPT') throw new Error('Algorithm must be BCRYPT');

  // Check rounds (between 4 and 31)
  if ((newSpec.rounds < 4) || (newSpec.rounds > 31)) throw new Error('Rounds must be a number between 4 and 31');

  // Return the new spec
  return newSpec;
}

// Our BCrypt shared function
function deriveKey(secret, salt, spec, callback) {
  var rounds = spec.rounds;
  var prefix = '$2a$' + (rounds < 10 ? '0' + rounds : rounds) + '$' + bufferToString(salt);
  var password = secret.toString('utf8');

  if (salt.length != 16) throw new Error('Salt must be precisely 16 bytes');

  bcrypt.hash(password, prefix, function(err, key) {
    if (err) return callback(err);
    if (key.startsWith(prefix)) {
      var buffer = stringToBuffer(key.substring(prefix.length));
      if (buffer.length != 23) callback(new Error('Internal bcrypt error: invalid derived key size'));
      callback(null, buffer);
    } else {
      callback(new Error('Internal bcrypt error: no prefix match'));
    }
  });
}

// Our   class
function Bcrypt(kdfSpec) {
  if (!(this instanceof Bcrypt)) return new Bcrypt();

  var spec = makeSpec({}, kdfSpec || {});
  var saltLength = 16;
  BaseKDF.call(this, spec, saltLength, deriveKey);
}

// Default spec, always clone
var defaultSpec = makeSpec({}, {});
Object.defineProperties(Bcrypt, {
  'defaultSpec': {
    configurable: false,
    enumerable: true,
    get: function() {
      return JSON.parse(JSON.stringify(defaultSpec));
    }
  },
  'bufferToString': {
    configurable: false,
    enumerable: false,
    value: bufferToString
  },
  'stringToBuffer': {
    configurable: false,
    enumerable: false,
    value: stringToBuffer
  }
});

// Inherit from base KDF
util.inherits(Bcrypt, BaseKDF);

// Export our class
exports = module.exports = Bcrypt;
