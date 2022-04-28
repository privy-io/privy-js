import crypto from 'crypto';
import {CryptoEngine, CryptoVersion} from '../src/node';
import {toBuffer, toString} from './encoding';
import {generateRSAKeyPair, rsaOAEPDecrypt} from './rsa';

describe('x0', () => {
  const x0 = CryptoEngine(CryptoVersion.x0);

  const wrapperKeyId = toBuffer('8ebdc958-f2cb-47c6-a6a4-a083e6ce1fb2');

  let publicKey: Uint8Array;
  let privateKey: crypto.KeyObject;

  beforeAll(async function () {
    const keyPair = generateRSAKeyPair();
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;
  });

  test('exposes wrapper key algorithm', () => {
    expect(x0.WRAPPER_KEY_ALGORITHM).toEqual('RSA_2048');
  });

  test('can encrypt and decrypt some data', async () => {
    const plaintext = toBuffer('{"ssn": "123-45-6789"}');

    const privyEncryption = new x0.Encryption(plaintext, {
      wrapperKey: publicKey,
      wrapperKeyId: wrapperKeyId,
    });

    const encryptionResult = await privyEncryption.encrypt();
    const ciphertext = encryptionResult.ciphertext();
    const commitmentId = encryptionResult.commitmentId();
    expect(encryptionResult.wrapperKeyId()).toEqual(wrapperKeyId);

    const privyDecryption = new x0.Decryption(ciphertext);
    expect(privyDecryption.wrapperKeyId()).toEqual(wrapperKeyId);

    // In real settings, this would instead be a call to the KMS with the
    // encrypted data key and have the KMS return the decrypted data key.
    const decryptedDataKey = rsaOAEPDecrypt(privyDecryption.encryptedDataKey(), privateKey);

    const decryptionResult = await privyDecryption.decrypt(decryptedDataKey);
    const plaintextResult = toString(decryptionResult.plaintext());
    expect(plaintextResult).toEqual('{"ssn": "123-45-6789"}');
    const integritySuccess = await privyDecryption.verify(decryptionResult, commitmentId);
    expect(integritySuccess).toBeTruthy();
  });
});
