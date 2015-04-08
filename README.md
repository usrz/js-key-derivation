Key Derivation Functions
========================

This package is a wrapper around different key derivation functions (password
hashing functions, for the unintiated) presenting a single and consistent API
around different ways to "hash" secrets.

* [Install and use](#install-and-use)
* [API Description](#api-description)
  * [Key derivation with callbacks](#key-derivation-with-callbacks)
  * [Key derivation with promises](#key-derivation-with-promises)
  * [Other properties an methods](#other-properties-and-methods)
  * [String encoding](string-encoding)
  * [Result structure](result-structure)
* [Algorithms and KDF specs](#algorithms-and-kdf-specs)
  * [Bcrypt](#bcrypt)
  * [PBKDF2](#pbkdf2)
  * [Scrypt](#scrypt)
* [License (MIT)](#license-mit-)



Install and use
---------------

Install as usual with _NPM_:

```bash
npm install --save key-derivation
```

You can use it with callbacks...

```javascript
var KDF = require('key-derivation');

// Create a KDF and derive a key
new KDF(spec).deriveKey(secret, salt, callback(err, result) {
  // Look, ma! We hashed the secret
});
```

... or with a `Promise`:

```javascript
var KDF = require('key-derivation');

// Create a KDF and derive a key
new KDF(spec).promiseKey(secret, salt).then(function(result) {
  // Look, ma! We hashed the secret
  })
});
```


API Description
---------------

A `KDF` can be constructed in three ways:

* Using defaults, by just calling `new KDF()`
* Using an algorithm identifier (one of
  [`BCRYPT`](http://en.wikipedia.org/wiki/Bcrypt)
  [`PBKDF2`](http://tools.ietf.org/html/rfc2898) or
  [`SCRYPT`](http://www.tarsnap.com/scrypt.html) case insensitive).
* Using a [_KDF spec_](#kdf-spec) enclosing the algorithm and its parameters.


#### Key derivation with callbacks

```javascript
kdf.deriveKey(secret, salt, function callback(error, result) {
  ...
})
```

The `deriveKey(...)` function takes three arguments:

* `secret`: a `string` or `Buffer` containing the data to be hashed.
* `salt`: the **optional** salt for the computation; if unspecified a _random_
  one will be generated (again a `string` or `Buffer`).
* `callback`: a callback function invoked with the two usual `error` and
  `result` arguments.


#### Key derivation with promises

```javascript
kdf.promiseKey(secret, salt)
  .then(function(result) { ... })
  .catch(function(error) { ... })
```

The `deriveKey(...)` function takes two arguments:

* `secret`: a `string` or `Buffer` containing the data to be hashed.
* `salt`: the **optional** salt for the computation; if unspecified a _random_
  one will be generated (again a `string` or `Buffer`).


#### Other properties and methods

```javascript
var KDF = require('key-derivation');
KDF.defaultSpec;
```

The **static** immutable `defaultSpec` property of the `KDF` class contains
the base _KDF spec_ that will be used when invoking the constructor without
(or only partial) arguments.

```javascript
var kdf = new KDF(spec);
console.log(kdf.kdfSpec);
```

The `kdfSpec` _immutable_ property of each `KDF` **instance** will contain the
full _KDF spec_ used by the `deriveKey(...)` and `promiseKey(...)` functions.

```javascript
var kdf = new KDF(spec).withSecureRandom();
```

`KDF` instances are constructed by default with a non-failing pseudo random
number generation (as secure random number generations might generate errors).

The `withSecureRandom()` function invked without parameters will instruct the
`KDF` instance to use a (potentially failing) cryptographically secure random
number generator.

The optional boolean parameter to this method allows specific enabling or
disabling of this feature.

See the documentation for Node's `crypto` module, and the difference between
its `randomBytes(...)` and `pseudoRandomBytes(...)` for the difference.


This function always returns the same `KDF` instance it was called on.


#### String encoding

Both the `secret` and `salt` can be specified as `Buffer` or `string`.

When using a `string`, its value will be converted internally into a `Buffer`
using the **UTF8** encoding.


#### Result structure

The `result` produced by the key derivation operations described above will
be an object containing the following keys:

* `derived_key`: the `Buffer` containing the bytes of the derived key
* `salt`: the `Buffer` containing the bytes of the salt, either the specified
   one or the randomly generated one.
* `kdf_spec`: a complete _KDF spec_ describing the key derivation computation.

For example:

```javascript
{
  'derived_key': Buffer([ ... ]),
  'salt': Buffer([ ... ]),
  'kdf_spec': {
    'algorithm': 'SCRYPT',
    'hash': 'SHA256',
    'cpu_memory_cost': 32768,
    'block_size': 8,
    'parallelization': 1,
    'derived_key_length': 32
  }
}
```


Algorithms and KDF specs
------------------------


#### Bcrypt

> **PLEASE NOTE** that due to the current limitations of Node's
> [`bcrypt`](https://www.npmjs.com/package/bcrypt) library we are
> currently unable to support _reliable_ pre-hashing of secrets,
> henceforth the input will _always_ be limited to 72 characters.
>
> Furthermore _extreme care_ should be used when using this method, as
> internally the extensive use of `string` does not allow processing
> of non-UTF8 sequence of bytes.

Defaults:

```json
{
  "algorithm": "BCRYPT",
  "rounds": 10
}
```

The `BCRYPT` algorithm _KDF spec_ contains two keys:

* `algorithm`: always `BCRYPT`
* `rounds`: the usual Blowfish `log2(iterations)` (between 4 and 31)

The `BCRYPT` requirements dictate a `salt` of precisely 16 bytes, and the
`derived_key` will always be precisely 23 bytes. Any secret whose length
(the number of bytes, take this into consideration with UTF8 strings) is
greater than 72 characters will be truncated.


#### PBKDF2

Defaults:

```json
{
  "algorithm": "PBKDF2",
  "hash": "SHA256",
  "iterations": 65536,
  "derived_key_length": 32
}
```

The `PBKDF2` algorithm _KDF spec_ contains four keys:

* `algorithm`: always `PBKDF2`
* `hash`: the hasing function to use for deriving the key
* `iterations`: the number of iterations
* `derived_key_length`: the desired number of bytes in the output key (defaults
  to the number of bytes produced by the hasing function).

When unspecified, the number of bytes randomly generated for the `salt` will
be equal to the number of bytes produced by the hashing function.

See [`RFC 2898`](http://tools.ietf.org/html/rfc2898) for more information.


#### Scrypt

> **PLEASE NOTE** that due to the current limitations of Node's
> [`scrypt`](https://www.npmjs.com/package/scrypt) library we are
> currently only able to support `SHA256` as a hashing function.

Defaults:

```json
{
  "algorithm": "SCRYPT",
  "hash": "SHA256",
  "cpu_memory_cost": 32768,
  "parallelization": 1,
  "block_size": 8,
  "derived_key_length": 32
}
```

The `PBKDF2` algorithm _KDF spec_ contains four keys:

* `algorithm`: always `SCRYPT`
* `hash`: the hasing function to use for deriving the key
* `cpu_memory_cost`: the CPU/memory cost parameter `N`
* `parallelization`: the parallelization factor `p`
* `block_size`: the block size parameter `b`
* `derived_key_length`: the desired number of bytes in the output key (defaults
  to the number of bytes produced by the hasing function).

When unspecified, the number of bytes randomly generated for the `salt` will
be equal to the number of bytes produced by the hashing function.

See [`TarSnap`](http://www.tarsnap.com/scrypt.html) for more information.

License (MIT)
-------------

Copyright (c) 2015 USRZ.com and Pier Paolo Fumagalli

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
