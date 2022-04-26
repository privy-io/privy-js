# 2022-03-02 - 0.0.2

### Breaking Changes

* No longer exports MD5 hash capabilities
* No longer supports encoding arguments (e.g., 'utf8', 'base64', etc.)
* No longer uses Node buffer objects, instead expects and returns Uint8Arrays

### New functionality

* Adds integrity functionality (`commitmentId`), i.e., returns SHA256 hash of plaintext data.
  * EncryptionResult objects have a `.commitmentId()` method to get the commitment
  * DecryptionResult objects have a `.verify()` method to verify the commitment

### Improvements

* Switch to using the Webcrypto standard
  * 100x performance improvements for encrypting/decrypting large objects
  * Removes all third-party dependencies
