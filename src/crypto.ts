import * as webcrypto from 'webcrypto';

const AES_256_GCM = 'aes-256-gcm';
const SHA1 = 'sha1';

export function csprng(lengthInBytes: number): Buffer {
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

export function aes256gcmEncrypt(plaintext: Buffer, dataKey: Buffer, config: AESEncryptConfig) {
  const initializationVector = csprng(config.ivLengthInBytes);
  const cipher = webcrypto.createCipheriv(AES_256_GCM, dataKey, initializationVector);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authenticationTag = cipher.getAuthTag();

  if (!authenticationTag || authenticationTag.length !== config.authTagLengthInBytes) {
    throw new Error('Authentication tag error');
  }

  return {
    ciphertext: ciphertext,
    initializationVector: initializationVector,
    authenticationTag: authenticationTag,
  };
}

export function aes256gcmDecrypt(
  ciphertext: Buffer,
  dataKey: Buffer,
  initializationVector: Buffer,
  authenticationTag: Buffer,
): Buffer {
  const decipher = webcrypto.createDecipheriv(AES_256_GCM, dataKey, initializationVector);
  decipher.setAuthTag(authenticationTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function rsaOaepSha1Encrypt(plaintext: Buffer, publicKey: Buffer): Buffer {
  return webcrypto.publicEncrypt(
    {
      key: publicKey,
      oaepHash: SHA1,
    },
    plaintext,
  );
}
