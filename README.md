# @privy-io/crypto

JavaScript library for encrypting and decrypting data with Privy.

This library is intended to be used by the privy-js and privy-node libraries to handle all cryptographic operations.

## Installation

```
npm install --save @privy-io/crypto
```

## Usage

```typescript
import {CryptoEngine, CryptoVersion} from 'privy-crypto-js';

// Grab the engine (implementation) corresponding to the version
const x0 = CryptoEngine(CryptoVersion.x0);

const plaintext = Buffer.from('{"ssn": "123-45-6789"}');

// Encryption
const privyEncryption = new x0.Encryption(plaintext, {
  wrapperKey: wrapperKey, // RSA public key from privy server
  wrapperKeyId: wrapperKeyId, // Metadata id of RSA public key from Privy's KMS
});
const encryptionResult = await privyEncryption.encrypt();
const ciphertext = encryptionResult.ciphertext();

// Decryption
const privyDecryption = new x0.Decryption(ciphertext);

// This is where Privy would decrypt the encrypted data
// key against the Privy server, ultimately doing so in an HSM.
const decryptedDataKey = decryptDataKey(
  privyDecryption.wrapperKeyId('utf8'),
  privyDecryption.encryptedDataKey('base64')
);

const decryptionResult = await privyDecryption.decrypt(decryptedDataKey);

// {"ssn": "123-45-6789"}
console.log(decryptionResult.plaintext('utf8'));
```

## Running tests

```
npm test
```
