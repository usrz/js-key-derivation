'use strict';

var Promise = global.Promise || require('promise');
var util = require('util');

var pluginClasses = {
  'bcrypt': require('./plugins/bcrypt'),
  'pbkdf2': require('./plugins/pbkdf2'),
  'scrypt': require('./plugins/scrypt')
}

var defaultClass = pluginClasses.scrypt;
var defaultSpec = defaultClass.defaultSpec;

function KeyDerivator(spec) {
  if (!(this instanceof KeyDerivator)) return new KeyDerivator();

  var plugin = null;

  // Default?
  if (!spec) {
    plugin = new defaultClass();
  }

  // The spec is a string (algo name)
  else if (util.isString(spec)) {
    var pluginClass = pluginClasses[spec.toLowerCase()];
    if (! pluginClass) throw new Error('Unsupported algorithm ' + spec);
    plugin = new pluginClass();

  }

  // The spec is an object, must have an algorithm
  else if (util.isObject(spec)) {
    var pluginAlgorithm = spec.algorithm;
    if (! pluginAlgorithm) throw new Error('KDF spec does not define the algorithm');
    var pluginClass = pluginClasses[pluginAlgorithm.toLowerCase()];
    if (! pluginClass) throw new Error('Unsupported algorithm ' + pluginAlgorithm);
    plugin = new pluginClass(spec);
  }

  // Anything else will badly fail!
  else throw new Error('Can not construct with ' + typeof(spec));

  // Define our properties: "spec" and "deriveKey" delegating to the plugin
  Object.defineProperties(this, {
    'kdfSpec': {
      configurable: false,
      enumerable: true,
      get: function() {
        return plugin.kdfSpec;
      }
    },
    'deriveKey': {
      configurable: false,
      enumerable: true,
      value: function(secret, salt, callback) {
        return plugin.deriveKey(secret, salt, callback);
      }
    },
    'promiseKey': {
      configurable: false,
      enumerable: true,
      value: function(secret, salt) {
        return new Promise(function(resolve, reject) {
          try {
            plugin.deriveKey(secret, salt, function(err, result) {
              if (err) reject(err);
              else resolve(result);
            });
          } catch (error) {
            return Promise.reject(error);
          }
        });
      }
    }
  });
}

Object.defineProperty(KeyDerivator, 'defaultSpec', {
  configurable: false,
  enumerable: true,
  get: function() {
    return JSON.parse(JSON.stringify(defaultSpec));
  }
});

exports = module.exports = KeyDerivator;

