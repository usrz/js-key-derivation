var expect = require('chai').expect;
var PBKDF2 = require('../src/kdf-pbkdf2.js');

describe('PBKDF2', function() {
  describe('KDF Spec', function() {

    it('should expose the default spec', function() {
      expect(PBKDF2.defaultSpec).to.eql({
        algorithm: 'PBKDF2',
        hash: "SHA256",
        iterations: 4096,
        derived_key_length: 32
      });
    });

    it('should construct with a different spec', function() {
      expect(new PBKDF2({
        hash: "SHA512",
        iterations: 65535,
        derived_key_length: 128
      }).kdfSpec).to.eql({
        algorithm: 'PBKDF2',
        hash: 'SHA512',
        iterations: 65535,
        derived_key_length: 128
      });
    });

    it('should fail with a wrong algorithm', function() {
      expect(function() {
        new PBKDF2({ algorithm: 'PBKDF' });
      }).to.throw("Algorithm must be PBKDF2");
    });

    it('should fail with a wrong hash', function() {
      expect(function() {
        new PBKDF2({ hash: 'sillyhash' });
      }).to.throw("Unknown hash sillyhash");
    });

    it('should fail with the wrong number of iterations', function() {
      expect(function() {
        new PBKDF2({ iterations: 'not a number' });
      }).to.throw("Iterations is not a number");
      expect(function() {
        new PBKDF2({ iterations: -1 });
      }).to.throw("Iterations must be a number greater than zero");
    });

    it('should fail with the wrong derived key length', function() {
      expect(function() {
        new PBKDF2({ derived_key_length: 'not a number' });
      }).to.throw("Derived key length is not a number");
      expect(function() {
        new PBKDF2({ derived_key_length: -1 });
      }).to.throw("Derived key length must be a number greater than zero");
    });

  });

  describe('simple key derivation', function() {

    it('should hash and verify a password', function(done) {
      var spec = { algorithm: 'PBKDF2', hash: 'SHA512', iterations: 12345, derived_key_length: 123 };

      new PBKDF2(spec).deriveKey('password', function(err, key1) {
        if (err) return done(err);
        try {
          expect(key1.kdf_spec).to.eql(spec);
          new PBKDF2(key1.kdf_spec).deriveKey('password', key1.salt, function(err, key2) {
            if (err) done(err);
            try {
              expect(key2).to.eql(key1);
              done(err);
            } catch (error) {
              return done(error);
            }
          });
        } catch(error) {
          return done(error);
        }
      });
    })

  });

  describe('known values', function() {

    /* From http://packages.python.org/passlib/lib/passlib.hash.cta_pbkdf2_sha1.html */
    it('should pass Python test 1', function(done) {
      new PBKDF2({ hash: 'SHA1', iterations: 10000 })
        .deriveKey('password', new Buffer('oX9ZZOcNgYoAsYL+8bqxKg', 'base64'), function(err, key) {
          try {
            expect(key.derived_key.toString('base64')).to.equal('AU2JLf2rNxWoZxWxRCluY0u6h6c=');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })

    /* From http://packages.python.org/passlib/lib/passlib.hash.pbkdf2_digest.html */
    it('should pass Python test 2', function(done) {
      new PBKDF2({ iterations: 6400 })
        .deriveKey('password', new Buffer('0ZrzXitFSGltTQnBWOsdAw', 'base64'), function(err, key) {
          try {
            expect(key.derived_key.toString('base64')).to.equal('Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M=');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })

    /* From http://packages.python.org/passlib/lib/passlib.hash.pbkdf2_digest.html */
    it('should pass Python test 3', function(done) {
      new PBKDF2({ iterations: 8000 })
        .deriveKey('password', new Buffer('XAuBMIYQQogxRg', 'base64'), function(err, key) {
          try {
            expect(key.derived_key.toString('base64')).to.equal('tRRlz8hYn63B9LYiCd6PRo6FMiunY9ozmMMI3srxeRE=');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })

    /* From http://packages.python.org/passlib/lib/passlib.hash.pbkdf2_digest.html */
    it('should pass Python test 4', function(done) {
      new PBKDF2({ iterations: 6400 })
        .deriveKey('password', new Buffer('+6UI/S+nXIk8jcbdHx3Fhg', 'base64'), function(err, key) {
          try {
            expect(key.derived_key.toString('base64')).to.equal('98jZicV16ODfEsEZeYPGHU3kbrUrvUEXOPimVSQDD44=');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })

    /* From http://packages.python.org/passlib/lib/passlib.hash.grub_pbkdf2_sha512.html */
    it('should pass Python test 5', function(done) {
      new PBKDF2({ hash: 'SHA512', iterations: 10000 })
        .deriveKey('password', new Buffer('4483972AD2C52E1F590B3E2260795FDA9CA0B07B96FF492814CA9775F08C4B59CD1707F10B269E09B61B1E2D11729BCA8D62B7827B25B093EC58C4C1EAC23137', 'hex'), function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('df4fcb5dd91340d6d31e33423e4210ad47c7a4df9fa16f401663bf288c20bf973530866178fe6d134256e4dbefbd984b652332eed3acaed834fea7b73cae851d');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })

  })

  describe('RFC test vectors', function() {

    it('should validate vector 1', function(done) {
      new PBKDF2({ hash: 'SHA1', iterations: 1 })
        .deriveKey('password', 'salt', function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('0c60c80f961f0e71f3a9b524af6012062fe037a6');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })

    it('should validate vector 2', function(done) {
      new PBKDF2({ hash: 'SHA1', iterations: 2 })
        .deriveKey('password', 'salt', function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })

    it('should validate vector 3', function(done) {
      new PBKDF2({ hash: 'SHA1', iterations: 4096 })
        .deriveKey('password', 'salt', function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('4b007901b765489abead49d926f721d065a429c1');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })

    it('should validate vector 4', function(done) {
      this.timeout(20000);
      new PBKDF2({ hash: 'SHA1', iterations: 16777216 })
        .deriveKey('password', 'salt', function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('eefe3d61cd4da4e4e9945b3d6ba2158c2634e984');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })

    it('should validate vector 5', function(done) {
      new PBKDF2({ hash: 'SHA1', iterations: 4096, derived_key_length: 25 })
        .deriveKey('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })

    it('should validate vector 6', function(done) {
      new PBKDF2({ hash: 'SHA1', iterations: 4096, derived_key_length: 16 })
        .deriveKey('pass\0word', 'sa\0lt', function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('56fa6aa75548099dcc37d7f03425e0c3');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    })
  });
});

