var expect = require('chai').expect;
var Scrypt = require('../src/plugins/scrypt.js');

describe('Scrypt', function() {
  describe('KDF Spec', function() {

    it('should expose the default spec', function() {
      expect(Scrypt.defaultSpec).to.eql({
        algorithm: 'SCRYPT',
        hash: "SHA256",
        cpu_memory_cost: 32768,
        parallelization: 1,
        block_size: 8,
        derived_key_length: 32
      });
    });

    it('should construct with a different spec', function() {
      expect(new Scrypt({
        cpu_memory_cost: 1024,
        parallelization: 16,
        block_size: 16,
        derived_key_length: 64
      }).kdfSpec).to.eql({
        algorithm: 'SCRYPT',
        hash: "SHA256",
        cpu_memory_cost: 1024,
        parallelization: 16,
        block_size: 16,
        derived_key_length: 64
      });
    });

    it('should fail with a wrong algorithm', function() {
      expect(function() {
        new Scrypt({ algorithm: 'SCRYP' });
      }).to.throw("Algorithm must be SCRYPT");
    });

    it('should fail with a wrong hash', function() {
      expect(function() {
        new Scrypt({ hash: 'SHA512' });
      }).to.throw("Only SHA256 hashing supported: SHA512");
    });

    it('should fail with the wrong CPU/Memory cost', function() {
      expect(function() {
        new Scrypt({ cpu_memory_cost: 'not a number' });
      }).to.throw("CPU/Memory cost is not a number");
      expect(function() {
        new Scrypt({ cpu_memory_cost: 1 });
      }).to.throw("CPU/Memory cost must be a power of 2 greater than 1");
      expect(function() {
        new Scrypt({ cpu_memory_cost: 7 });
      }).to.throw("CPU/Memory cost must be a power of 2 greater than 1");
    });

    it('should fail with the wrong block size', function() {
      expect(function() {
        new Scrypt({ block_size: 'not a number' });
      }).to.throw("Block size is not a number");
      expect(function() {
        new Scrypt({ block_size: -1 });
      }).to.throw("Block size must be a number greater than zero");
    });

    it('should fail with the wrong parallelization', function() {
      expect(function() {
        new Scrypt({ parallelization: 'not a number' });
      }).to.throw("Parallelization is not a number");
      expect(function() {
        new Scrypt({ parallelization: -1 });
      }).to.throw("Parallelization must be a number greater than zero");
    });

    it('should fail with the wrong parameters combinations', function() {
      expect(function() {
        new Scrypt({ cpu_memory_cost: 262144, block_size: 128 });
      }).to.throw("CPU/Memory cost is too large for given block size");
      expect(function() {
        new Scrypt({ cpu_memory_cost: 262144, block_size: 262144, parallelization: 128 });
      }).to.throw("CPU/Memory cost is too large for given block size");
    });


    it('should fail with the wrong derived key length', function() {
      expect(function() {
        new Scrypt({ derived_key_length: 'not a number' });
      }).to.throw("Derived key length is not a number");
      expect(function() {
        new Scrypt({ derived_key_length: -1 });
      }).to.throw("Derived key length must be a number greater than zero");
    });
  });

  describe('IETF test vectors', function() {

    it('should validate vector 1', function(done) {
      new Scrypt({ cpu_memory_cost: 16, block_size: 1, derived_key_length: 64 })
        .deriveKey('', '', function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    });

    it('should validate vector 2', function(done) {
      new Scrypt({ cpu_memory_cost: 1024, parallelization: 16, derived_key_length: 64 })
        .deriveKey('password', 'NaCl', function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    });

    it('should validate vector 3', function(done) {
      new Scrypt({ cpu_memory_cost: 16384, derived_key_length: 64 })
        .deriveKey('pleaseletmein', 'SodiumChloride', function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    });

    it('should validate vector 4', function(done) {
      this.timeout(10000);
      new Scrypt({ cpu_memory_cost: 1048576, derived_key_length: 64 })
        .deriveKey('pleaseletmein', 'SodiumChloride', function(err, key) {
          try {
            expect(key.derived_key.toString('hex')).to.equal('2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4');
            done(err);
          } catch (error) {
            done(error);
          }
        });
    });
  })
});
