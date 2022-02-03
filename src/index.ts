import {Decryption, Encryption, EncryptConfig} from './engines/x0';

// Expose errors
export {PrivyCryptoError} from './errors';

// Expose md5 utility
export {md5Hash} from './crypto';

// Expose encryption and decryption objects for typing
export {
  Decryption,
  DecryptionResult,
  Encryption,
  EncryptionResult,
  EncryptConfig,
} from './engines/x0';

// Currently hardcoding version x0
export default {
  /**
   * Instantiates a new Encryption instance.
   *
   * @param {Buffer} plaintext - The plaintext data to encrypt.
   * @param {EncryptConfig} config - An object to configure encryption.
   *   * wrapperKey - (Buffer) The wrapper key (RSA public key in PEM format).
   *   * wrapperKeyId - (Buffer) The metadata ID of the RSA public key.
   */
  Encryption(plaintext: Buffer, config: EncryptConfig) {
    return new Encryption(plaintext, config);
  },

  /**
   * Instantiates a new Decryption instance.
   *
   * @param {Buffer} serialized - The serialized encrypted data to decrypt.
   */
  Decryption(serialized: Buffer) {
    return new Decryption(serialized);
  },
};
