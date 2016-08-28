'use strict';

const assert = require('chai').assert;

const CryptoGcm = require('./');
const validator = require('./validator');

const Base64 = 'YWRhc2Rhc2RkdmRhZGNlY2FjYWZmZHM=';
const Hex = 'aaa16e24ba4';
const Bytes = Buffer.alloc(12);
const Ascii = 'my string';
const Utf8 = 'this is utf8 text, 指事字, it really is';
const Key = Buffer.alloc(32);

// minimum payload length is 12 + 16 + 1 = 29 bytes,
// Array(Number) needs to be one more than 29, so 30!

const PayloadTooSmall_hex = Buffer.from(Array(25).join('a'), 'utf8').toString('hex');
const PayloadCorrect_hex = Buffer.from(Array(30).join('a'), 'utf8').toString('hex');
const PayloadTooSmall_b64 = Buffer.from(Array(25).join('a'), 'utf8').toString('base64');
const PayloadCorrect_b64 = Buffer.from(Array(30).join('a'), 'utf8').toString('base64');
const PayloadTooSmall_buf = Buffer.from(Array(25).join('a'), 'utf8');
const PayloadCorrect_buf = Buffer.from(Array(30).join('a'), 'utf8');

describe('crypto-gcm', () => {

  describe('instantiation', () => {
    it('should return false since options missing', () => {
      assert.throws(() => new CryptoGcm(), Error, 'missing options');
    });
    it('should return false since empty options', () => {
      assert.throws(() => new CryptoGcm({}), Error, 'missing options');
    });
    it('should return false since key missing', () => {
      assert.throws(() => new CryptoGcm({
        encoding : {}
      }), Error, 'missing options');
    });
    it('should return false since key invalid length', () => {
      assert.throws(() => new CryptoGcm({
        key : Bytes,
        encoding : {}
      }), Error, 'key should be a buffer of 32 bytes');
    });
    it('should return false since key invalid type', () => {
      assert.throws(() => new CryptoGcm({
        key : Ascii,
        encoding : {}
      }), Error, 'key should be a buffer of 32 bytes');
    });
    it('should return false since encoding is missing', () => {
      assert.throws(() => new CryptoGcm({
        key : Bytes,
      }), Error, 'missing options');
    });
    it('should return false since encoding.plaintext is missing', () => {
      assert.throws(() => new CryptoGcm({
        key : Key,
        encoding : { payload : 'hex' }
      }), Error, 'plaintext encoding should be ascii, utf8 or buffer');
    });
    it('should return false since encoding.payload is missing', () => {
      assert.throws(() => new CryptoGcm({
        key : Key,
        encoding : { plaintext : 'utf8' }
      }), Error, 'payload encoding should be base64, hex or buffer');
    });
    it('should return false since encoding.plaintext is invalid', () => {
      assert.throws(() => new CryptoGcm({
        key : Key,
        encoding : { plaintext : Ascii, payload : 'hex'}
      }), Error, 'plaintext encoding should be ascii, utf8 or buffer');
    });
    it('should return false since encoding.payload is invalid', () => {
      assert.throws(() => new CryptoGcm({
        key : Key,
        encoding : { plaintext : 'buffer', payload : Ascii}
      }), Error, 'payload encoding should be base64, hex or buffer');
    });
    it('should be instance of CryptoGcm', () => {
      assert.instanceOf(new CryptoGcm({
        key : Key,
        encoding : { plaintext : 'buffer', payload : 'buffer'}
      }), CryptoGcm, 'Instance should be of type CryptoGcm');
    });
  });

  describe('main', () => {
    ['ascii', 'utf8', 'buffer'].forEach(plaintext => {
      ['base64', 'hex', 'buffer'].forEach(payload => {

        describe(`plaintext: ${plaintext}\tpayload: ${payload}`, () => {

          let cg, _plaintext, _encrypted, _decrypted;

          before(() => {
            cg = new CryptoGcm({
              key : Key,
              encoding : { plaintext, payload }
            });
          });

          describe('encryption of invalid plaintext should return false', () => {
            it(`should return false since plaintext is empty string`, () => {
              assert.isFalse(cg.encrypt(''));
            });
            it(`should return false since plaintext is zero (number)`, () => {
              assert.isFalse(cg.encrypt(0));
            });
            it(`should return false since plaintext is number`, () => {
              assert.isFalse(cg.encrypt(7));
            });
            it(`should return false since plaintext is empty array`, () => {
              assert.isFalse(cg.encrypt([]));
            });
            it(`should return false since plaintext is empty object`, () => {
              assert.isFalse(cg.encrypt({}));
            });
            it(`should return false since plaintext is array`, () => {
              assert.isFalse(cg.encrypt([1]));
            });
            it(`should return false since plaintext is object`, () => {
              assert.isFalse(cg.encrypt({a:1}));
            });
            it(`should return false since plaintext is NaN`, () => {
              assert.isFalse(cg.encrypt(NaN));
            });
            it(`should return false since plaintext is Infinity`, () => {
              assert.isFalse(cg.encrypt(Infinity));
            });
            it(`should return false since plaintext is Function`, () => {
              assert.isFalse(cg.encrypt(function(){}));
            });
            if (plaintext === 'ascii'){
              it(`should return false since plaintext is Buffer`, () => {
                assert.isFalse(cg.encrypt(Bytes));
              });
              it(`should return false since plaintext is utf8`, () => {
                assert.isFalse(cg.encrypt(Utf8));
              });
            } else if (plaintext === 'utf8') {
              it(`should return false since plaintext is Buffer`, () => {
                assert.isFalse(cg.encrypt(Bytes));
              });
            } else if (plaintext === 'buffer') {
              it(`should return false since plaintext is string`, () => {
                assert.isFalse(cg.encrypt(Ascii));
              });
            }
          });

          describe('decryption of invalid payload should return false', () => {
            it(`should return false since payload is empty string`, () => {
              assert.isFalse(cg.decrypt(''));
            });
            it(`should return false since payload is zero (number)`, () => {
              assert.isFalse(cg.decrypt(0));
            });
            it(`should return false since payload is number`, () => {
              assert.isFalse(cg.decrypt(7));
            });
            it(`should return false since payload is empty array`, () => {
              assert.isFalse(cg.decrypt([]));
            });
            it(`should return false since payload is empty object`, () => {
              assert.isFalse(cg.decrypt({}));
            });
            it(`should return false since payload is array`, () => {
              assert.isFalse(cg.decrypt([1]));
            });
            it(`should return false since payload is object`, () => {
              assert.isFalse(cg.decrypt({a:1}));
            });
            it(`should return false since payload is NaN`, () => {
              assert.isFalse(cg.decrypt(NaN));
            });
            it(`should return false since payload is Infinity`, () => {
              assert.isFalse(cg.decrypt(Infinity));
            });
            it(`should return false since payload is Function`, () => {
              assert.isFalse(cg.decrypt(function(){}));
            });
            if (payload === 'hex'){
              it(`should return false since payload is base64`, () => {
                assert.isFalse(cg.decrypt(PayloadCorrect_b64));
              });
              it(`should return false since payload is Buffer`, () => {
                assert.isFalse(cg.decrypt(PayloadCorrect_buf));
              });
              it(`should return false since payload is hex but too short`, () => {
                assert.isFalse(cg.decrypt(PayloadTooSmall_hex));
              });
            } else if (payload === 'base64') {
              it(`should return false since payload is Buffer`, () => {
                assert.isFalse(cg.decrypt(PayloadCorrect_buf));
              });
              it(`should return false since payload is base64 but too short`, () => {
                assert.isFalse(cg.decrypt(PayloadTooSmall_b64));
              });
            } else if (payload === 'buffer') {
              it(`should return false since payload is string`, () => {
                assert.isFalse(cg.decrypt(PayloadCorrect_hex));
              });
              it(`should return false since payload is Buffer but too short`, () => {
                assert.isFalse(cg.decrypt(PayloadTooSmall_buf));
              });
            }
          });

          describe('encryption/decryption should work and correct encoding', () => {
            before(() => {
              _plaintext = (plaintext === 'buffer') ? Bytes :
                           (plaintext === 'utf8')   ? Utf8 :
                                                      Ascii;
              _encrypted = cg.encrypt(_plaintext);
              _decrypted = cg.decrypt(_encrypted);
            });
            it(`plaintext should be encoded as ${plaintext}`, () => {
              assert.isTrue(validator[plaintext](_plaintext));
            });
            it(`payload should be encoded as ${payload}`, () => {
              assert.isTrue(validator[payload](_encrypted));
            });
            it(`decrypted should be encoded as ${plaintext}`, () => {
              assert.isTrue(validator[plaintext](_decrypted));
            });
            it(`decrypted should equal plaintext`, () => {
              if (plaintext === 'buffer')
                assert.deepEqual(_plaintext, _decrypted);
              else if (plaintext === 'utf8' || plaintext === 'ascii')
                assert.equal(_plaintext, _decrypted)
            });
            it('should throw since instance has already been destroyed', () => {
              cg.destroy();

              assert.throws(() => cg.encrypt(plaintext), Error, 'instance has been destroyed');
            });
            after(() => {
              _plaintext = _encrypted = _decrypted = null;
            });
          });
          after(() => {
            cg = null;
          })
        });
      });
    });
  });
});
