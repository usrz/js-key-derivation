var expect = require('chai').expect;
var Bcrypt = require('../src/kdf-bcrypt.js');
var bcrypt = require('bcrypt');

var tests = [
  // from https://bitbucket.org/vadim/bcrypt.net/src/464c41416dc92363ec8aa599ef327971d555b998/BCrypt.Net.Test/TestBCrypt.cs?at=default
  [ "A-01", "$2a$06$DCq7YPn5Rq63x1Lad4cll.", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.", ""                                    ],
  [ "A-02", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye", ""                                    ],
  [ "A-03", "$2a$10$k1wbIrmNyFAPwPVPSVa/ze", "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW", ""                                    ],
  [ "A-04", "$2a$12$k42ZFHFWqBp3vWli.nIn8u", "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO", ""                                    ],
  [ "A-05", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe", "a"                                   ],
  [ "A-06", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V.", "a"                                   ],
  [ "A-07", "$2a$10$k87L/MF28Q673VKh8/cPi.", "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u", "a"                                   ],
  [ "A-08", "$2a$12$8NJH3LsPrANStV6XtBakCe", "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS", "a"                                   ],
  [ "A-09", "$2a$06$If6bvum7DFjUnE9p2uDeDu", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i", "abc"                                 ],
  [ "A-10", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm", "abc"                                 ],
  [ "A-11", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi", "abc"                                 ],
  [ "A-12", "$2a$12$EXRkfkdmXn2gzds2SSitu.", "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q", "abc"                                 ],
  [ "A-13", "$2a$06$.rCVZVOThsIa97pEDOxvGu", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC", "abcdefghijklmnopqrstuvwxyz"          ],
  [ "A-14", "$2a$08$aTsUwsyowQuzRrDqFflhge", "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz.", "abcdefghijklmnopqrstuvwxyz"          ],
  [ "A-15", "$2a$10$fVH8e28OQRj9tqiDXs1e1u", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq", "abcdefghijklmnopqrstuvwxyz"          ],
  [ "A-16", "$2a$12$D4G5f18o7aMMfwasBL7Gpu", "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG", "abcdefghijklmnopqrstuvwxyz"          ],
  [ "A-17", "$2a$06$fPIsBO8qRqkjj273rfaOI.", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD"  ],
  [ "A-18", "$2a$08$Eq2r4G/76Wv39MzSX262hu", "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD"  ],
  [ "A-19", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD"  ],
  [ "A-20", "$2a$12$WApznUOJfkEGSmYRfnkrPO", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD"  ],

  // from http://cvsweb.openwall.com/cgi/cvsweb.cgi/Owl/packages/john/john/src/BF_fmt.c?rev=HEAD
  [ "B-01", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", "U*U" ],
  [ "B-02", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK", "U*U*" ],
  [ "B-03", "$2a$05$XXXXXXXXXXXXXXXXXXXXXO", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a", "U*U*U" ],
  [ "B-04", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy", "" ],
  [ "B-05", "$2a$05$abcdefghijklmnopqrstuu", "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ],
  [ "B-06", "$2a$05$abcdefghijklmnopqrstuu", "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored" ],
  [ "B-07", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy", "" ],

  // generated from python's own "bcrypt" for UTF-8 encoding compatibility
  [ "C-01", "$2a$05$RVSWIArjLf6rs0x3pZq34e", "$2a$05$RVSWIArjLf6rs0x3pZq34eQYeA33FpILVm0p7FxeVc2Ehcy6Hdude", "\u6771\u4eac" ], // Tokyo in kanji (below, repeated 12 and 20 times - 72 and 12 bytes)
  [ "C-02", "$2a$05$RVSWIArjLf6rs0x3pZq34e", "$2a$05$RVSWIArjLf6rs0x3pZq34eHor2TfuOzMbWXjx52ViU5aQhgB9LvnG", "\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac" ],
  [ "C-02", "$2a$05$RVSWIArjLf6rs0x3pZq34e", "$2a$05$RVSWIArjLf6rs0x3pZq34eHor2TfuOzMbWXjx52ViU5aQhgB9LvnG", "\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac\u6771\u4eac" ]

];


describe('Bcrypt', function() {
  describe('KDF Spec', function() {

    it('should expose the default spec', function() {
      expect(Bcrypt.defaultSpec).to.eql({
        algorithm: 'BCRYPT',
        rounds: 10
      });
    });

    it('should construct with a different spec', function() {
      expect(new Bcrypt({
        hash: "SHA512",
        rounds: 31
      }).kdfSpec).to.eql({
        algorithm: 'BCRYPT',
        hash: 'SHA512',
        rounds: 31
      });
    });

    it('should fail with a wrong algorithm', function() {
      expect(function() {
        new Bcrypt({ algorithm: 'BCRYP' });
      }).to.throw("Algorithm must be BCRYPT");
    });

    it('should fail with a wrong hash', function() {
      expect(function() {
        new Bcrypt({ hash: 'silly-hash' });
      }).to.throw("Unknown hash silly-hash");
    });

    it('should fail with the wrong rounds count', function() {
      expect(function() {
        new Bcrypt({ rounds: 3 });
      }).to.throw("Rounds must be a number between 4 and 31");
      expect(function() {
        new Bcrypt({ rounds: 32 });
      }).to.throw("Rounds must be a number between 4 and 31");
    });
  });

  describe('Bcrypt\'s own mad base64 variant', function() {
    // Base64 equivalent: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w

    it('should convert a buffer to a string', function() {
      var buffer = new Buffer(256);
      for (var i = 0; i < 256; i ++) buffer[i] = i;
      var string = Bcrypt.bufferToString(buffer);
      expect(string).to.equal('..CA.uOD/eaGAOmJB.yMBv.PCfKSDPWVE/iYEvubFf6eGQGhHASkHwenIgqqJQ2tKBCwKxOzLha2MRm5NBy8Ny//OiLCPSXFQCjIQyvLRi7OSTHRTDTUTzfXUjraVT3dWEDgW0PjXkbmYUnpZEzsZ1/valLybVX1cFj4c1v7dl8.eWIBfGUEf2gHgmsKhW4NiHEQi3QTjncWkXoZlH0cl4AfmoMinYYloIkoo4wrpo8uqZIxrJU0r5g3sps6tZ49uKFAu6RDvqdGwapJxK1Mx7BPyrNSzbZV0LlY07xb1r9e2cJh3MVk38hn4stq5c5t6NFw69Rz7td28dp59N189u');
    });

    it('should convert a string to a buffer', function() {
      var buffer = Bcrypt.stringToBuffer('..CA.uOD/eaGAOmJB.yMBv.PCfKSDPWVE/iYEvubFf6eGQGhHASkHwenIgqqJQ2tKBCwKxOzLha2MRm5NBy8Ny//OiLCPSXFQCjIQyvLRi7OSTHRTDTUTzfXUjraVT3dWEDgW0PjXkbmYUnpZEzsZ1/valLybVX1cFj4c1v7dl8.eWIBfGUEf2gHgmsKhW4NiHEQi3QTjncWkXoZlH0cl4AfmoMinYYloIkoo4wrpo8uqZIxrJU0r5g3sps6tZ49uKFAu6RDvqdGwapJxK1Mx7BPyrNSzbZV0LlY07xb1r9e2cJh3MVk38hn4stq5c5t6NFw69Rz7td28dp59N189u');
      for (var i = 0; i < 256; i ++) expect(buffer[i]).to.equal(i);
    });
  });

  describe('simple key derivation', function() {

    it('should hash and verify a password', function(done) {
      var spec = ({ algorithm: 'BCRYPT', rounds : 5 });
      new Bcrypt(spec).deriveKey('password', function(err, key1) {
        if (err) return done(err);
        try {
          expect(key1.kdf_spec).to.eql(spec);
          new Bcrypt(key1.kdf_spec).deriveKey('password', key1.salt, function(err, key2) {
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

  describe('Test Bcrypt own test vectors internally', function() {
    for (var index in tests) (function(vector) {
      it('should validate test vector ' + vector[0], function(done) {
        var salt = vector[1], hash = vector[2], password = vector[3];

        bcrypt.hash(password, salt, function(error, result) {
          if (error) return done(error);
          try {
            expect(result).to.equal(hash);
            done();
          } catch (exception) {
            done(exception);
          }
        });
      });
    })(tests[index]);
  });

  describe('Test Bcrypt own test vectors as a key derivation function', function() {
    for (var index in tests) (function(vector) {
      it('should validate test vector ' + vector[0], function(done) {
        var salt = vector[1], hash = vector[2], password = vector[3];

        var bsalt = Bcrypt.stringToBuffer(salt.substring(7));
        var rounds = Number(salt.substring(4, 6));

        new Bcrypt({rounds: rounds}).deriveKey(password, bsalt, function(err, key) {
          if (err) return done(err);

          try {
            expect(key.kdf_spec.rounds).to.equal(rounds);
            var skey = Bcrypt.bufferToString(key.derived_key);
            var ssalt = Bcrypt.bufferToString(key.salt);
            var string = '$2a$' + (rounds < 10 ? '0' + rounds : rounds) + '$' + ssalt + skey;
            expect(string).to.equal(hash);
            done();
          } catch (exception) {
            done(exception);
          }
        });
      });
    })(tests[index]);
  });

});
