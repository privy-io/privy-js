import * as webcrypto from 'webcrypto';
import {concatBuffers} from './buffers';

const AES_256_GCM = 'aes-256-gcm';
const SHA1 = 'sha1';

/**
 * Utility function to create md5 hashes of data.
 * Useful for hashing encrypted file contents when
 * uploading to the cloud for integrity checks.
 *
 * @param {Buffer} data - Data to hash
 * @returns {string} Hex representation of md5 hash
 */
export function md5Hash(data: Uint8Array): string {
  // In the browser, createHash uses the hash-base library, which uses Buffer.isBuffer() to check for a _isBuffer prop.
  // But it doesn't actually use any of the extra methods in Buffer.
  // https://github.com/crypto-browserify/hash-base/blob/master/index.js#L7
  // TODO: This is a hack and we should use a different library.
  const buffer = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  (buffer as any)._isBuffer = true;
  return webcrypto.createHash('md5').update(buffer).digest('hex');
}

export function csprng(lengthInBytes: number): Uint8Array {
  // In node, this will be crypto.randomBytes, which is a CSPRNG.
  //
  //     https://nodejs.org/api/crypto.html#cryptorandombytessize-callback
  //
  // In the browser, this will be crypto.getRandomValues, which
  // MDN recommends against using to generate keys, preferring
  // instead to use SubtleCrypto.generateKey.
  //
  //     https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
  //
  return webcrypto.randomBytes(lengthInBytes);
}

interface AESEncryptConfig {
  ivLengthInBytes: number;
  authTagLengthInBytes: number;
}

export function aes256gcmEncrypt(
  plaintext: Uint8Array,
  dataKey: Uint8Array,
  config: AESEncryptConfig,
): {ciphertext: Uint8Array; initializationVector: Uint8Array; authenticationTag: Uint8Array} {
  const initializationVector = csprng(config.ivLengthInBytes);
  const cipher = webcrypto.createCipheriv(AES_256_GCM, dataKey, initializationVector);
  const ciphertext = concatBuffers(cipher.update(plaintext), cipher.final());
  const authenticationTag = cipher.getAuthTag();
  return {ciphertext, initializationVector, authenticationTag};
}

export function aes256gcmDecrypt(
  ciphertext: Uint8Array,
  dataKey: Uint8Array,
  initializationVector: Uint8Array,
  authenticationTag: Uint8Array,
): Uint8Array {
  const decipher = webcrypto.createDecipheriv(AES_256_GCM, dataKey, initializationVector);
  decipher.setAuthTag(authenticationTag);
  return concatBuffers(decipher.update(ciphertext), decipher.final());
}

/**
 * This is only used to encrypt the AES secret key so that
 * the only way to decrypt it is with the RSA private key.
 * The RSA private key is stored in an HSM and is thus never
 * exposed to the Privy server or any clients.
 *
 * The next iteration of Privy's crypto code will be using ECC
 * and thus moving away from the less secure RSA+SHA1.
 */
export function rsaOaepSha1Encrypt(plaintext: Uint8Array, publicKey: string): Uint8Array {
  return webcrypto.publicEncrypt(
    {
      key: publicKey,
      oaepHash: SHA1,
    },
    plaintext,
  );
}
