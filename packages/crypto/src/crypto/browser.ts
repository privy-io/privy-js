import {CryptoError} from '../errors';
import {crypto} from '../webcrypto';
import {CryptoOperations} from './types';
import {AES_KEY_LENGTH_32_BYTES, AUTH_TAG_LENGTH_16_BYTES} from './constants';

// https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey
// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
const RAW_FORMAT = 'raw';
const SPKI_FORMAT = 'spki';
const EXTRACTABLE = true;
const NOT_EXTRACTABLE = false;
const ENCRYPT_ONLY: KeyUsage[] = ['encrypt'];
const DECRYPT_ONLY: KeyUsage[] = ['decrypt'];

// https://developer.mozilla.org/en-US/docs/Web/API/AesKeyGenParams
// https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
const AES_GCM = 'AES-GCM';
const AES_KEY_LENGTH_256_BITS = AES_KEY_LENGTH_32_BYTES * 8;
const AUTH_TAG_LENGTH_128_BITS = AUTH_TAG_LENGTH_16_BYTES * 8;

// https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedKeyGenParams
const RSA_OAEP = 'RSA-OAEP';
const RSA_OAEP_ALGORITHM: RsaHashedKeyGenParams = {
  name: RSA_OAEP,
  hash: 'SHA-1',
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
};

// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
function importAESGCMKey(key: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (key.byteLength !== AES_KEY_LENGTH_32_BYTES) {
    throw new CryptoError(`key must be 32 bytes but was ${key.byteLength} bytes`);
  }

  return crypto.subtle.importKey(RAW_FORMAT, key, AES_GCM, NOT_EXTRACTABLE, usages);
}

// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
function importRSAOAEPKey(key: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey(SPKI_FORMAT, key, RSA_OAEP_ALGORITHM, NOT_EXTRACTABLE, usages);
}

// https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
function aesGCMParams(iv: Uint8Array): AesGcmParams {
  return {
    iv: iv,
    name: AES_GCM,
    tagLength: AUTH_TAG_LENGTH_128_BITS,
  };
}

function csprng(byteLength: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(byteLength));
}

async function aesGCMEncryptionKey(): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.generateKey(
    {
      name: AES_GCM,
      length: AES_KEY_LENGTH_256_BITS,
    },
    EXTRACTABLE,
    ENCRYPT_ONLY,
  );

  const arrayBuffer = await crypto.subtle.exportKey(RAW_FORMAT, cryptoKey);

  return new Uint8Array(arrayBuffer);
}

async function aesGCMEncrypt(
  pt: Uint8Array,
  iv: Uint8Array,
  rawKey: Uint8Array,
): Promise<Uint8Array> {
  const key = await importAESGCMKey(rawKey, ENCRYPT_ONLY);
  const ct = await crypto.subtle.encrypt(aesGCMParams(iv), key, pt);
  return new Uint8Array(ct);
}

async function aesGCMDecrypt(
  ct: Uint8Array,
  iv: Uint8Array,
  rawKey: Uint8Array,
): Promise<Uint8Array> {
  const key = await importAESGCMKey(rawKey, DECRYPT_ONLY);
  const pt = await crypto.subtle.decrypt(aesGCMParams(iv), key, ct);
  return new Uint8Array(pt);
}

async function rsaOAEPEncrypt(pt: Uint8Array, rawKey: Uint8Array): Promise<Uint8Array> {
  const key = await importRSAOAEPKey(rawKey, ENCRYPT_ONLY);
  const ct = await crypto.subtle.encrypt(RSA_OAEP_ALGORITHM, key, pt);
  return new Uint8Array(ct);
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

export const Crypto: CryptoOperations = {
  csprng,
  sha256,
  aesGCMEncrypt,
  aesGCMDecrypt,
  aesGCMEncryptionKey,
  rsaOAEPEncrypt,
};
