# crypto-gcm

Encrypt / Decrypt data with `AES-256-GCM`.

Different encodings for plaintext and payload are supported.

No dependencies! Just a *shell* around `crypto` to make it easier to use.

Everything happens synchronously, so no callbacks/promises/async.

## WeakMap

To store the encryption key, a `WeakMap` is used.

If you forget to call `cg.destroy()` and `cg` goes out of scope, the saved encryption key inside `cg` would still reference itself, and so will not be set for garbage collection, leading to a memory leak.

Since we are using a `WeakMap`, each dictionary entry of
`cg` inside the `WeakMap` does not hold a reference to itself, so in the above situation, there would be no more references to the `cg` instance, and so the entry would be set for garbage collection, and be removed, preventing a memory leak of the private key if you forget to call `cg.destroy()`.

## Usage

```javascript

'use strict';

const crypto = require('crypto');
const CryptoGcm = require('crypto-gcm');

// create key
const key = crypto.randomBytes(32);

// create instance (you can create multiple instances)
const cg = new CryptoGcm({
    key,
    encoding : {
      plaintext : 'utf8', // also supported: ascii, buffer
      payload : 'base64'  // also supported: base64, hex
    }
})

// ut8 string
const plaintext = 'my plaintext';

// will be base64 string
const payload = cg.encrypt(plaintext);

// check if encryption failed
if (!payload) {
  // encryption failed, invalid plaintext (encoding)
}

// will be utf8 string
const decrypted = cg.decrypt(encrypted);

// check if decryption failed
if (!decrypted) {
  // decryption failed, invalid payload (encoding)
}

// will be true
decrypted === plaintext;

// when you're done with this instance
cg.destroy();

```

## Tests

`npm test`

## Todo

- [ ] deal with large plaintext inputs, which will consist of chunks
- [ ] add Base64 as a valid plaintext encoding
- [ ] make sure decrypted payload is correct type (= plainext encoding)

## Compatibility

tested on `node v6.2.2`

## License

MIT
