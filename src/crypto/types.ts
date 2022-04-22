export interface CryptoOperations {
  /**
   * Cryptographically-secure pseudo-random number generator.
   *
   * @param {number} byteLength the number of random bytes to return.
   * @returns {Uint8Array} random bytes as Uint8Array.
   */
  csprng(byteLength: number): Uint8Array;

  /**
   * Hashes data using SHA256.
   *
   * @param {Uint8Array} data data to hash.
   * @returns {Promise<Uint8Array>} promise resolving to hashed bytes.
   */
  sha256(data: Uint8Array): Promise<Uint8Array>;

  /**
   * Performs AES-GCM encryption on the given plaintext
   * using the given initialization vector and key.
   *
   * @param {Uint8Array} pt the plaintext data to encrypt.
   * @param {Uint8Array} iv the initialization vector.
   * @param {Uint8Array} key the secret encryption key.
   * @returns {Promise<Uint8Array>} promise resolving to the encrypted bytes.
   */
  aesGCMEncrypt(pt: Uint8Array, iv: Uint8Array, key: Uint8Array): Promise<Uint8Array>;

  /**
   * Performs AES-GCM decryption on the given ciphertext
   * using the given initialization vector and key.
   *
   * @param {Uint8Array} ct the ciphertext data to decrypt.
   * @param {Uint8Array} iv the initialization vector.
   * @param {Uint8Array} key the secret encryption key.
   * @returns {Promise<Uint8Array>} promise resolving to the decrypted bytes.
   */
  aesGCMDecrypt(ct: Uint8Array, iv: Uint8Array, key: Uint8Array): Promise<Uint8Array>;

  /**
   * Generates a new 256 bit key for AES-GCM encryption.
   *
   * @returns {Promise<Uint8Array>} promise resolving to a Uint8Array.
   */
  aesGCMEncryptionKey(): Promise<Uint8Array>;

  /**
   * Performs RSA-OAEP encryption.
   *
   * @param {Uint8Array} pt Plaintext to encrypt.
   * @param {Uint8Array} key RSA public key.
   * @returns {Promise<Uint8Array>} promise resolving to the encrypted bytes.
   */
  rsaOAEPEncrypt(pt: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
}
