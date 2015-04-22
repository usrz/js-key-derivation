var expect = require('chai').expect;
var KDF = require('../src/kdf');

describe('Key Derivation', function() {

  it('should expose the default spec (scrypt\'s)', function() {
    expect(KDF.defaultSpec).to.eql({
      algorithm: 'SCRYPT',
      hash: "SHA256",
      cpu_memory_cost: 32768,
      parallelization: 1,
      block_size: 8,
      derived_key_length: 32
    });
  });

  it('should support empty construction', function() {
    expect(new KDF().kdfSpec).to.eql({
      algorithm: 'SCRYPT',
      hash: "SHA256",
      cpu_memory_cost: 32768,
      parallelization: 1,
      block_size: 8,
      derived_key_length: 32
    });
  });

  it('should construct with an algorithm name', function() {
    expect(new KDF('PbKdF2').kdfSpec).to.eql({
      algorithm: 'PBKDF2',
      hash: "SHA256",
      iterations: 65536,
      derived_key_length: 32
    });
  });

  it('should construct with an full KDF spec', function() {
    expect(new KDF({
      algorithm: 'bcrYpt',
      rounds: 31
    }).kdfSpec).to.eql({
      algorithm: 'BCRYPT',
      rounds: 31
    });
  });

  it('should not construct without specifying an algorithm', function() {
    expect(function() {
      new KDF({});
    }).to.throw('KDF spec does not define the algorithm');
  });

  it('should not construct an unknown algorithm', function() {
    expect(function() {
      new KDF('random');
    }).to.throw('Unsupported algorithm random');
  });

  it('should not construct with garbage', function() {
    expect(function() {
      new KDF(123);
    }).to.throw('Can not construct with number');
  });

  describe('Random security', function() {

    it('should work with a secure random', function(done) {
      new KDF({ algorithm: 'pbkdf2', iterations: 1024 })
        .withSecureRandom(true)
        .deriveKey("password", null, function(err, result) {
          done(err);
        });
    })

    it('should work with a pseudo random', function(done) {
      new KDF({ algorithm: 'pbkdf2', iterations: 1024 })
        .withSecureRandom(false)
        .deriveKey("password", null, function(err, result) {
          done(err);
        });
    })
  });

  describe('Callback operation', function() {

    it('should work with Bcrypt', function(done) {
      new KDF('bcrypt').deriveKey("password", "saltsaltsaltsalt", function(err, result) {
        if (err) return done(err);

        try {
          expect(result).to.eql({
            derived_key: new Buffer('2ab47f39e9a03ebd57d61ba4bc71250a12e11bf48bcc8f', 'hex'),
            salt: new Buffer('saltsaltsaltsalt', 'utf8'),
            kdf_spec: {
              algorithm: 'BCRYPT',
              rounds: 10
            }
          });
          done();
        } catch (error) {
          done(error);
        }
      });
    });

    it('should work with PBKDF2', function(done) {
      new KDF('pbkdf2').deriveKey("password", "salt", function(err, result) {
        if (err) return done(err);

        try {
          expect(result).to.eql({
            derived_key: new Buffer('4156f668bb31db3a17f4d1b91424ef0d417ad1f35d055aceaebd8da0f6a44b7e', 'hex'),
            salt: new Buffer('salt', 'utf8'),
            kdf_spec: {
              algorithm: 'PBKDF2',
              hash: 'SHA256',
              iterations: 65536,
              derived_key_length: 32
            }
          });
          done();
        } catch (error) {
          done(error);
        }
      });
    });

    it('should work with Scrypt', function(done) {
      new KDF('scrypt').deriveKey("password", "salt", function(err, result) {
        if (err) return done(err);

        try {
          expect(result).to.eql({
            derived_key: new Buffer('4bc0fd507e93a600768021341ec726c57c00cb55a4702a1650131365500cf471', 'hex'),
            salt: new Buffer('salt', 'utf8'),
            kdf_spec: {
              algorithm: 'SCRYPT',
              hash: 'SHA256',
              cpu_memory_cost: 32768,
              block_size: 8,
              parallelization: 1,
              derived_key_length: 32
            }
          });
          done();
        } catch (error) {
          done(error);
        }
      });
    });

    it('should work with HMAC', function(done) {
      new KDF('hmac').deriveKey("password", "salt", function(err, result) {
        if (err) return done(err);

        try {
          expect(result).to.eql({
            derived_key: new Buffer('84ec44c7d6fc41917953a1dafca3c7d7856f7a9d0328b991b76f0d36be1224b9', 'hex'),
            salt: new Buffer('salt', 'utf8'),
            kdf_spec: {
              algorithm: 'HMAC',
              hash: 'SHA256',
              derived_key_length: 32
            }
          });
          done();
        } catch (error) {
          done(error);
        }
      });
    });
  });

  describe('Promises operation', function() {

    it('should work with Bcrypt', function(done) {
      new KDF('bcrypt').promiseKey("password", "saltsaltsaltsalt").then(function(result) {
        try {
          expect(result).to.eql({
            derived_key: new Buffer('2ab47f39e9a03ebd57d61ba4bc71250a12e11bf48bcc8f', 'hex'),
            salt: new Buffer('saltsaltsaltsalt', 'utf8'),
            kdf_spec: {
              algorithm: 'BCRYPT',
              rounds: 10
            }
          });
          done();
        } catch (error) {
          done(error);
        }
      }, function(error) {
        done(err);
      });
    });

    it('should work with PBKDF2', function(done) {
      new KDF('pbkdf2').promiseKey("password", "salt").then(function(result) {
        try {
          expect(result).to.eql({
            derived_key: new Buffer('4156f668bb31db3a17f4d1b91424ef0d417ad1f35d055aceaebd8da0f6a44b7e', 'hex'),
            salt: new Buffer('salt', 'utf8'),
            kdf_spec: {
              algorithm: 'PBKDF2',
              hash: 'SHA256',
              iterations: 65536,
              derived_key_length: 32
            }
          });
          done();
        } catch (error) {
          done(error);
        }
      }, function(error) {
        done(err);
      });
    });

    it('should work with SCRYPT', function(done) {
      new KDF('scrypt').promiseKey("password", "salt").then(function(result) {
        try {
          expect(result).to.eql({
            derived_key: new Buffer('4bc0fd507e93a600768021341ec726c57c00cb55a4702a1650131365500cf471', 'hex'),
            salt: new Buffer('salt', 'utf8'),
            kdf_spec: {
              algorithm: 'SCRYPT',
              hash: 'SHA256',
              cpu_memory_cost: 32768,
              block_size: 8,
              parallelization: 1,
              derived_key_length: 32
            }
          });
          done();
        } catch (error) {
          done(error);
        }
      }, function(error) {
        done(err);
      });
    });

    it('should work with HMAC', function(done) {
      new KDF('hmac').promiseKey("password", "salt").then(function(result) {
        try {
          expect(result).to.eql({
            derived_key: new Buffer('84ec44c7d6fc41917953a1dafca3c7d7856f7a9d0328b991b76f0d36be1224b9', 'hex'),
            salt: new Buffer('salt', 'utf8'),
            kdf_spec: {
              algorithm: 'HMAC',
              hash: 'SHA256',
              derived_key_length: 32
            }
          });
          done();
        } catch (error) {
          done(error);
        }
      }, function(error) {
        done(err);
      });
    });
  });
});
