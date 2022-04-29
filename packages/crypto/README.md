# @privy-io/crypto

JavaScript library for encrypting and decrypting data with Privy.

This library is intended to be used by the `@privy-io/privy-browser` and `@privy-io/node` libraries to handle all cryptographic operations.

[![npm version](https://badge.fury.io/js/@privy-io%2Fcrypto.svg)](https://www.npmjs.com/package/@privy-io/crypto)

## Installation

```
npm install --save @privy-io/crypto
```

## Usage

```typescript
import {CryptoEngine, CryptoVersion} from '@privy-io/crypto';

// Grab the engine (implementation) corresponding to the version
const x0 = CryptoEngine(CryptoVersion.x0);

// Crypto module expects Uint8Arrays.
const plaintext = new TextEncoder().encode('{"ssn": "123-45-6789"}');

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

// Crypto module returns Uint8Arrays.
const decryptedPlaintext = new TextDecoder().decode(decryptionResult.plaintext());
console.log(decryptedPlaintext); // {"ssn": "123-45-6789"}
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
