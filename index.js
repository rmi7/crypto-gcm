'use strict';

const crypto = require('crypto');
const validator = require('./validator');

const ALGORITHM = 'aes-256-gcm';

const IV_SIZE          = 12;
const TAG_SIZE         = 16;
const KEY_SIZE         = 32;
const HEADER_SIZE      = IV_SIZE + TAG_SIZE;
const PAYLOAD_MIN_SIZE = HEADER_SIZE + 1;

const VALID_PLAINTEXT_ENCODING = [ 'ascii', 'utf8', 'buffer' ];
const VALID_PAYLOAD_ENCODING   = [ 'base64', 'hex', 'buffer' ];

// one _encryptionKey WeakMap entry per instance!
let _encryptionKey = new WeakMap();

class CryptoGcm {

  constructor(options){
    if (!options || !options.key || !options.encoding)
      throw new Error('missing options');

    const { key, encoding } = options;

    if (!validator.buffer(key) || key.length !== KEY_SIZE)
      throw new Error('key should be a buffer of 32 bytes')

    if (!encoding.plaintext || (VALID_PLAINTEXT_ENCODING.indexOf(encoding.plaintext) === -1))
      throw new Error('plaintext encoding should be ascii, utf8 or buffer');

    if (!encoding.payload || (VALID_PAYLOAD_ENCODING.indexOf(encoding.payload) === -1))
      throw new Error('payload encoding should be base64, hex or buffer');

    this.encoding = Object.freeze(encoding);

    // - save encryption key in WeakMap at key = THIS INSTANCE
    //   when this instance is destroyed, and encryption key was not deleted
    //   from the WeakMap, the key will be set for garbage collection, so will
    //   be deleted, so no private key leak!
    //
    // - this could happen if destroy() is not called but this instance goes out
    //   of scope and thus is garbage collected
    _encryptionKey.set(this, key);
  }

  destroy(){
    if (!_encryptionKey.has(this))
      throw new Error('instance has been destroyed');

    _encryptionKey.delete(this);
  }

  _createBufferWithEncoding(input, inputType){
    const encoding = this.encoding[inputType];

    if (!input)
      return false;

    if (!validator[encoding](input))
      return false;

    if (encoding !== 'buffer')
      input = Buffer.from(input, encoding);

    return input;
  }

  encrypt(plaintext){
    if (!_encryptionKey.has(this))
      throw new Error('instance has been destroyed');

    plaintext = this._createBufferWithEncoding(plaintext, 'plaintext');

    if (!plaintext)
      return false;

    const iv         = crypto.randomBytes(IV_SIZE);
    const cipher     = crypto.createCipheriv(ALGORITHM, _encryptionKey.get(this), iv);
    cipher.end(plaintext);
    const ciphertext = cipher.read();
    const tag        = cipher.getAuthTag();

    const payload = Buffer.concat([iv, tag, ciphertext]);

    const encoding = this.encoding.payload;

    return (encoding === 'buffer')
      ? payload // buffer
      : payload.toString(encoding); // hex or base64
  }

  decrypt(payload){
    if (!_encryptionKey.has(this))
      throw new Error('instance has been destroyed');

    payload = this._createBufferWithEncoding(payload, 'payload')

    if (!payload)
      return false;

    if (payload.length < PAYLOAD_MIN_SIZE)
      return false;

    const iv         = payload.slice(0, IV_SIZE);
    const tag        = payload.slice(IV_SIZE, HEADER_SIZE);
    const ciphertext = payload.slice(HEADER_SIZE);

    const decipher = crypto.createDecipheriv(ALGORITHM, _encryptionKey.get(this), iv);
    decipher.setAuthTag(tag);
    try { decipher.end(ciphertext) } catch(e) { return false; }

    const plaintext = decipher.read();

    const encoding = this.encoding.plaintext;

    return (encoding === 'buffer')
      ? plaintext // buffer
      : plaintext.toString(encoding); // utf8 or ascii
  }
}

module.exports = CryptoGcm;
