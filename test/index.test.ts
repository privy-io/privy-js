import PrivyCrypto from '../src';
import crypto from 'crypto';

let publicKey: Buffer;
let privateKey: crypto.KeyObject;

const wrapperKeyId = Buffer.from('8ebdc958-f2cb-47c6-a6a4-a083e6ce1fb2');

beforeAll(function () {
  const keys = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  // The privy API sends the public key as a base64-encoded PEM string
  const pem = keys.publicKey.export({
    type: 'spki',
    format: 'pem',
  });
  publicKey = Buffer.from(pem);

  privateKey = keys.privateKey;
});

test('encrypt and decrypt some data', async () => {
  const plaintext = Buffer.from('{"ssn": "123-45-6789"}');

  const privyEncryption = PrivyCrypto.Encryption(plaintext, {
    wrapperKey: publicKey,
    wrapperKeyId: wrapperKeyId,
  });

  const encryptionResult = await privyEncryption.encrypt();
  const ciphertext = encryptionResult.ciphertext();
  const contentHash = encryptionResult.contentHash();
  expect(encryptionResult.wrapperKeyId()).toEqual(wrapperKeyId);

  const privyDecryption = PrivyCrypto.Decryption(ciphertext);
  expect(privyDecryption.wrapperKeyId()).toEqual(wrapperKeyId);

  const decryptedDataKey = crypto.privateDecrypt(
    {
      key: privateKey,
      oaepHash: 'sha1',
    },
    privyDecryption.encryptedDataKey(),
  );

  const decryptionResult = await privyDecryption.decrypt(decryptedDataKey, contentHash);
  expect(decryptionResult.plaintext('utf8')).toEqual('{"ssn": "123-45-6789"}');
});
