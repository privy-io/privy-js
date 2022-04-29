# @privy-io/crypto

JavaScript library for encrypting and decrypting data with Privy.

This library is intended to be used by the privy-js and privy-node libraries to handle all cryptographic operations.

## Installation

```
npm install --save @privy-io/crypto
```

## Usage

```typescript
import {CryptoEngine, CryptoVersion} from '@privy-io/crypto';

// Crypto module expects and returns Uint8Arrays. These help with conversion.
const toBuffer = (str: string) => new TextEncoder().encode(str);
const toString = (buf: Uint8Array) => new TextDecoder().decode(buf);

// Grab the engine (implementation) corresponding to the version
const x0 = CryptoEngine(CryptoVersion.x0);

const plaintext = toBuffer('{"ssn": "123-45-6789"}');

// Encryption
const privyEncryption = new x0.Encryption(plaintext, {
  wrapperKey: wrapperKey, // RSA public key from privy server
  wrapperKeyId: wrapperKeyId, // Metadata id of RSA public key from Privy's KMS
});
const encryptionResult = await privyEncryption.encrypt();
const ciphertext = encryptionResult.ciphertext();
// Commitment id's are computed from the hash of a nonce concatenated with the
// plaintext. Can be used for an optional data integrity check.
const commitmentId = encryptionResult.commitmentId();

// Decryption
const privyDecryption = new x0.Decryption(ciphertext);

// This is where Privy would decrypt the encrypted data
// key against the Privy server, ultimately doing so in an HSM.
const decryptedDataKey = decryptDataKey(
  privyDecryption.wrapperKeyId(),
  privyDecryption.encryptedDataKey(),
);

const decryptionResult = await privyDecryption.decrypt(decryptedDataKey);
// Optional data integrity check.
if (!(await privyDecryption.verify(decryptionResult, commitmentId))) {
  throw 'Data integrity check failed.';
}

// {"ssn": "123-45-6789"}
console.log(toString(decryptionResult.plaintext()));
```

## Running tests

To test the module interfaces, run:

```
npm test
```

To test the node crypto operations against the browser ones (which use the webcrypto standard), run:

```bash
# Requires node >= 15
npm run test-webcrypto
```
