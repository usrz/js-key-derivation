'use strict';

var crypto = require('crypto');

var hashes = {};
var lengths = {};
var names = crypto.getHashes();
for (var i in names) {
  var name = names[i];
  var hash = name.toUpperCase();
  lengths[hash] = crypto.createHash(name).digest().length;
  hashes[hash] = name;
}

function validate(hash) {
  var normalized = String(hash).toUpperCase();
  if (hashes[normalized]) return normalized;
  throw new Error('Unknown hash ' + hash);
}

function create(hash) {
  var original = hashes[validate(hash)];
  return crypto.createHash(original);
}

function digestLength(hash) {
  return lengths[validate(hash)];
}

module.exports.validate = validate;
module.exports.create = create;
module.exports.digestLength = digestLength;
