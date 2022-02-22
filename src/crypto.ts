import {CryptoError} from './errors';
import {crypto} from './webcrypto';

/**
 * The following key, nonce, and IV constants
 * refer to NIST-recommended lengths.
 */

// Used for serialization / deserialization logic.
export const IV_LENGTH_12_BYTES = 12;
export const COMMITMENT_NONCE_LENGTH_32_BYTES = 32;
export const AUTH_TAG_LENGTH_16_BYTES = 16;

// https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey
// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
const RAW_FORMAT = 'raw';
const SPKI_FORMAT = 'spki';
const EXTRACTABLE = true;
const NOT_EXTRACTABLE = false;
const ENCRYPT_ONLY: KeyUsage[] = ['encrypt'];
const DECRYPT_ONLY: KeyUsage[] = ['decrypt'];
const WRAP_KEY_ONLY: KeyUsage[] = ['wrapKey'];

// https://developer.mozilla.org/en-US/docs/Web/API/AesKeyGenParams
// https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
const AES_GCM = 'AES-GCM';
const AES_KEY_LENGTH_256_BITS = 256;
const AUTH_TAG_LENGTH_128_BITS = 128;

// https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedKeyGenParams
const RSA_OAEP = 'RSA-OAEP';
const RSA_OAEP_ALGORITHM: RsaHashedKeyGenParams = Object.freeze({
  name: RSA_OAEP,
  hash: 'SHA-1',
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
});

// https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
function aesGCMParams(iv: BufferSource): AesGcmParams {
  return {
    iv: iv,
    name: AES_GCM,
    tagLength: AUTH_TAG_LENGTH_128_BITS,
  };
}

/**
 * Cryptographically-secure pseudo-random number generator.
 *
 * @param {number} byteLength the number of random bytes to return
 * @returns {Uint8Array} random bytes as Uint8Array
 */
export function csprng(byteLength: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(byteLength));
}

/**
 * Generates a new 256 bit key for AES-GCM encryption.
 *
 * @returns {Promise<CryptoKey>} promise resolving to a CryptoKey
 */
export function generateAESGCMEncryptionKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    {
      name: AES_GCM,
      length: AES_KEY_LENGTH_256_BITS,
    },
    EXTRACTABLE,
    ENCRYPT_ONLY,
  );
}

/**
 * Imports a 256 bit key for AES-GCM decryption.
 *
 * @param {BufferSource} key Uint8Array of the AES key
 * @returns {Promise<CryptoKey>} promise resolving to the imported CryptoKey
 */
export function importAESGCMDecryptionKey(key: BufferSource): Promise<CryptoKey> {
  const AES_KEY_LENGTH_32_BYTES = 32;

  if (key.byteLength !== AES_KEY_LENGTH_32_BYTES) {
    throw new CryptoError(`key must be 32 bytes but was ${key.byteLength} bytes`);
  }

  return crypto.subtle.importKey(RAW_FORMAT, key, AES_GCM, NOT_EXTRACTABLE, DECRYPT_ONLY);
}

/**
 * Imports a 2048 bit public key in DER format for AES-GCM decryption.
 *
 * @param {BufferSource} key Uint8Array of the RSA public key in DER format
 * @returns {Promise<CryptoKey>} promise resolving to the imported CryptoKey
 */
export function importRSAOAEPEncryptionKey(key: BufferSource): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    SPKI_FORMAT,
    key,
    RSA_OAEP_ALGORITHM,
    NOT_EXTRACTABLE,
    WRAP_KEY_ONLY,
  );
}

/**
 * Performs AES-GCM encryption on the given plaintext
 * using the given initialization vector and key.
 *
 * @param {BufferSource} pt the plaintext data to encrypt
 * @param {BufferSource} iv the initialization vector
 * @param {CryptoKey} key the secret encryption key
 * @returns {Promise<Uint8Array>} promise resolving to the encrypted bytes
 */
export async function aesGCMEncrypt(
  pt: BufferSource,
  iv: BufferSource,
  key: CryptoKey,
): Promise<Uint8Array> {
  const ct = await crypto.subtle.encrypt(aesGCMParams(iv), key, pt);
  return new Uint8Array(ct);
}

/**
 * Performs AES-GCM decryption on the given ciphertext
 * using the given initialization vector and key.
 *
 * @param {BufferSource} ct the ciphertext data to decrypt
 * @param {BufferSource} iv the initialization vector
 * @param {CryptoKey} key the secret encryption key
 * @returns {Promise<Uint8Array>} promise resolving to the decrypted bytes
 */
export async function aesGCMDecrypt(
  ct: BufferSource,
  iv: BufferSource,
  key: CryptoKey,
): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt(aesGCMParams(iv), key, ct);
  return new Uint8Array(pt);
}

/**
 * Performs RSA-OAEP encryption of key with a wrapping key (i.e., RSA public key).
 *
 * @param {CryptoKey} key key to encrypt
 * @param {CryptoKey} wrappingKey RSA public key to use for encrypting key
 * @returns {Promise<Uint8Array>} promise resolving to the encrypted bytes
 */
export async function rsaOaepWrapKey(key: CryptoKey, wrappingKey: CryptoKey): Promise<Uint8Array> {
  const ct = await crypto.subtle.wrapKey(RAW_FORMAT, key, wrappingKey, {name: RSA_OAEP});
  return new Uint8Array(ct);
}

/**
 * Hashes data using SHA256.
 *
 * @param {BufferSource} data data to hash
 * @returns {Promise<Uint8Array>} promise resolving to hashed bytes
 */
export async function sha256(data: BufferSource): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}
