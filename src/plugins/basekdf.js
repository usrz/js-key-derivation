'use strict';

var crypto = require('crypto');

function BaseKDF(kdfSpec, saltLength, deriveKeyFn) {

  // On the plugin only!
  var useSecureRandom = false;

  Object.defineProperties(this, {
    'useSecureRandom': {
      configurable: false,
      enumerable: true,
      get: function() {
        return useSecureRandom;
      },
      set: function(secure) {
        useSecureRandom = secure ? true : false;
      }
    },
    'kdfSpec': {
      configurable: false,
      enumerable: true,
      get: function() {
        return JSON.parse(JSON.stringify(kdfSpec));
      }
    },
    'deriveKey': {
      configurable: false,
      enumerable: true,
      value: function deriveKey(secret, salt, callback) {
        var secret = null, salt = null, callback = null, index = 0;

        // First argument must be a string or Buffer
        if (typeof(arguments[index]) === 'string') {
          secret = new Buffer(arguments[index ++], 'utf8');
        } else if (arguments[index] instanceof Buffer) {
          secret = arguments[index ++];
        } else {
          throw new TypeError('Secret must be a string or a Buffer');
        }

        // Next argument could be a salt (string or buffer)
        if (index < arguments.length) {
          if (typeof(arguments[index]) === 'string') {
            salt = new Buffer(arguments[index ++], 'utf8');
          } else if (arguments[index] instanceof Buffer) {
            salt = arguments[index ++];
          } else if (arguments[index] === null) {
            index ++; // specifically set "salt" to null
          } else if (typeof(arguments[index]) !== 'function') {
            throw new TypeError('Argument ' + (index + 1) + ' must be a salt string, Buffer or a callback function');
          }
        }

        // Last argument could be a callback
        if (index < arguments.length) {
          if (typeof(arguments[index]) === 'function') {
            callback = arguments[index ++];
          } else {
            throw new TypeError('Argument ' + (index + 1) + ' should be a callback function (' + typeof(arguments[index]) + ')');
          }
        }

        // Verify that we have a callback
        if (! callback) throw new TypeError('No callback specified');

        // Our wrapper function
        var wrapper = function(err, salt) {
          if (err) return callback(err);
          try {
            deriveKeyFn(secret, salt, kdfSpec, function(err, key) {
              if (err) return callback(err);
              callback(null, { salt: salt, derived_key: key, kdf_spec: kdfSpec });
            });
          } catch (error) {
            callback(error);
          }
        }

        // If we have no salt, calculate it
        if (salt) {
          return wrapper(null, salt);
        } else if (useSecureRandom) {
          crypto.randomBytes(saltLength, wrapper);
        } else {
          crypto.pseudoRandomBytes(saltLength, wrapper);
        }
      }
    }
  });
}

exports = module.exports = BaseKDF;
