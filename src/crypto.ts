import {CryptoError} from './errors';
import {crypto} from './webcrypto';

// https://developer.mozilla.org/en-US/docs/Web/API/AesKeyGenParams
// https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
const AES_GCM = 'AES-GCM';
const AES_KEY_LENGTH_256_BITS = 256;
const IV_LENGTH_12_BYTES = 12;
const AUTH_TAG_LENGTH_128_BITS = 128;

// https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedKeyGenParams
const RSA_OAEP = 'RSA-OAEP';
const RSA_OAEP_MODULUS_LENGTH_2048_BITS = 2048;
const RSA_OAEP_PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01]);
const SHA1 = 'SHA-1';

export function csprng(byteLength: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(byteLength));
}

export function generateAESGCMEncryptionKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    {
      name: AES_GCM,
      length: AES_KEY_LENGTH_256_BITS,
    },
    true,
    ['encrypt'],
  );
}

export function generateAESGCMInitializationVector(): Uint8Array {
  return csprng(IV_LENGTH_12_BYTES);
}

export function importAESGCMDecryptionKey(key: BufferSource): Promise<CryptoKey> {
  const bitLength = key.byteLength * 8;

  if (bitLength !== AES_KEY_LENGTH_256_BITS) {
    throw new CryptoError(`key must be 256 bits but was ${bitLength}`);
  }

  return crypto.subtle.importKey('raw', key, AES_GCM, false, ['decrypt']);
}

// https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
function aesGCMParams(iv: BufferSource): AesGcmParams {
  return {
    iv: iv,
    name: AES_GCM,
    tagLength: AUTH_TAG_LENGTH_128_BITS,
  };
}

export function aesGCMEncrypt(
  pt: BufferSource,
  iv: BufferSource,
  key: CryptoKey,
): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt(aesGCMParams(iv), key, pt);
}

export function aesGCMDecrypt(
  ct: BufferSource,
  iv: BufferSource,
  key: CryptoKey,
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(aesGCMParams(iv), key, ct);
}

export function importRSAOAEPEncryptionKey(key: BufferSource) {
  const algorithm: RsaHashedKeyGenParams = {
    name: RSA_OAEP,
    hash: SHA1,
    modulusLength: RSA_OAEP_MODULUS_LENGTH_2048_BITS,
    publicExponent: RSA_OAEP_PUBLIC_EXPONENT,
  };

  return crypto.subtle.importKey('raw', key, algorithm, false, ['encrypt']);
}

export function rsaOaepEncrypt(pt: BufferSource, key: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt({name: RSA_OAEP}, key, pt);
}
