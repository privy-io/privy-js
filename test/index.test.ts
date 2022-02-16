import {CryptoEngine, CryptoVersion} from '../src';
import crypto from 'crypto';

describe('x0', () => {
  const x0 = CryptoEngine(CryptoVersion.x0);

  const wrapperKeyId = Buffer.from('8ebdc958-f2cb-47c6-a6a4-a083e6ce1fb2');

  let publicKey: Buffer;
  let privateKey: crypto.KeyObject;

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

  test('exposes wrapper key algorithm', () => {
    expect(x0.WRAPPER_KEY_ALGORITHM).toEqual('RSA_2048');
  });

  test('can encrypt and decrypt some data', async () => {
    const plaintext = Buffer.from('{"ssn": "123-45-6789"}');

    const privyEncryption = new x0.Encryption(plaintext, {
      wrapperKey: publicKey,
      wrapperKeyId: wrapperKeyId,
    });

    const encryptionResult = await privyEncryption.encrypt();
    const ciphertext = encryptionResult.ciphertext();
    const commitmentHash = encryptionResult.commitmentHash('hex');
    expect(encryptionResult.wrapperKeyId()).toEqual(wrapperKeyId);

    const privyDecryption = new x0.Decryption(ciphertext);
    expect(privyDecryption.wrapperKeyId()).toEqual(wrapperKeyId);

    const decryptedDataKey = crypto.privateDecrypt(
      {
        key: privateKey,
        oaepHash: 'sha1',
      },
      privyDecryption.encryptedDataKey(),
    );

    const decryptionResult = await privyDecryption.decrypt(
      decryptedDataKey,
      Buffer.from(commitmentHash, 'hex'),
    );
    expect(decryptionResult.plaintext('utf8')).toEqual('{"ssn": "123-45-6789"}');
  });
});
