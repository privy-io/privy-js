import crypto from 'crypto';
import {CryptoOperations} from './types';
import {concatBuffers} from '../buffers';
import {AES_KEY_LENGTH_32_BYTES, AUTH_TAG_LENGTH_16_BYTES} from './constants';

const AES_256_GCM = 'aes-256-gcm';

const PEM_HEADER = '-----BEGIN PUBLIC KEY-----';
const PEM_FOOTER = '-----END PUBLIC KEY-----';

function derToPEMEncodedString(key: Uint8Array): string {
  // 1. Convert DER Uint8Array to base64-encoded string.
  const base64 = Buffer.from(key.buffer).toString('base64');

  // 2. Split base64 string into chunks according to PEM format.
  const chunks = base64.match(/.{1,64}/g) as string[];

  // 3. Join chunks with newlines.
  const contents = chunks.join('\n');

  // 4. Create key in PEM format
  const pem = `${PEM_HEADER}\n${contents}\n${PEM_FOOTER}`;

  // 5. Return key in PEM format
  return pem;
}

function csprng(byteLength: number): Uint8Array {
  const buffer = crypto.randomBytes(byteLength);
  return new Uint8Array(buffer);
}

function aesGCMEncryptionKey(): Promise<Uint8Array> {
  return Promise.resolve(csprng(AES_KEY_LENGTH_32_BYTES));
}

function aesGCMEncrypt(pt: Uint8Array, iv: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const cipher = crypto.createCipheriv(AES_256_GCM, key, iv);
  const encrypted = concatBuffers(cipher.update(pt), cipher.final());
  const authTag = cipher.getAuthTag();
  return Promise.resolve(concatBuffers(encrypted, authTag));
}

function aesGCMDecrypt(ct: Uint8Array, iv: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const encrypted = ct.slice(0, ct.length - AUTH_TAG_LENGTH_16_BYTES);
  const authTag = ct.slice(ct.length - AUTH_TAG_LENGTH_16_BYTES, ct.length);
  const decipher = crypto.createDecipheriv(AES_256_GCM, key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = concatBuffers(decipher.update(encrypted), decipher.final());
  return Promise.resolve(decrypted);
}

function rsaOAEPEncrypt(pt: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const encrypted = crypto.publicEncrypt(
    {
      key: derToPEMEncodedString(key),
      oaepHash: 'sha1',
    },
    pt,
  );

  return Promise.resolve(new Uint8Array(encrypted));
}

function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = crypto.createHash('sha256').update(data).digest();
  return Promise.resolve(new Uint8Array(hash));
}

export const Crypto: CryptoOperations = {
  csprng,
  sha256,
  aesGCMEncrypt,
  aesGCMDecrypt,
  aesGCMEncryptionKey,
  rsaOAEPEncrypt,
};
