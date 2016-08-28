# crypto-gcm

Encrypt / Decrypt data with `AES-256-GCM`.

Different encodings for plaintext and payload are supported.

No dependencies! Just a *shell* around `crypto` to make it easier to use.

Everything happens synchronously, so no callbacks/promises/async.

## WeakMap

To store the encryption key, a `WeakMap` is used.

If you forget to call `kg.destroy()` and `kg` goes out of scope, `kg` will be
garbage collected. Since we are using a `WeakMap`, the dictionary entry of
`kg` inside the `WeakMap` will be automatically set for garbage collection, and
thus be deleted!

**Preventing a memory leak of the private key if you forget to call `destroy()`.**

## Usage

```javascript

'use strict';

const crypto = require('crypto');
const CryptoGcm = require('crypto-gcm');

// create key
const key = crypto.randomBytes(32);

// create instance (you can create multiple instances)
const kg = new CryptoGcm({
    key,
    encoding : {
      plaintext : 'utf8', // also supported: ascii, buffer
      payload : 'base64'  // also supported: base64, hex
    }
})

// ut8 string
const plaintext = 'my plaintext';

// will be base64 string
const payload = kg.encrypt(plaintext);

// will be utf8 string
const decrypted = kg.decrypt(encrypted);

// will be true
decrypted === plaintext;

// when you're done with this instance
kg.destroy();

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
