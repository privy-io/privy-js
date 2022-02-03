# privy-crypto-js

JavaScript library for encrypting and decrypting data with Privy.

## Usage

```typescript
const plaintext = Buffer.from('{"ssn": "123-45-6789"}');

// Encryption
const privyEncryption = PrivyCrypto.Encryption(plaintext, {
  wrapperKey: wrapperKey, // RSA public key from privy server
  wrapperKeyId: wrapperKeyId, // Metadata ID of RSA public key from privy server
});
const encryptionResult = await privyEncryption.encrypt();
const ciphertext = encryptionResult.ciphertext();

// Decryption
const privyDecryption = PrivyCrypto.Decryption(ciphertext);

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
