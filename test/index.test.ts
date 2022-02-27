import {CryptoEngine, CryptoVersion} from '../src';
import {crypto} from '../src/webcrypto';

function stringToBuffer(str: string) {
  return new TextEncoder().encode(str);
}

function bufferToString(buffer: BufferSource) {
  return new TextDecoder().decode(buffer);
}

async function exportKey(pubKey: CryptoKey): Promise<Uint8Array> {
  const key = await crypto.subtle.exportKey('spki', pubKey);
  return new Uint8Array(key);
}

async function rsaOAEPDecrypt(ct: Uint8Array, key: CryptoKey): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt({name: 'RSA-OAEP'}, key, ct);
  return new Uint8Array(pt);
}

describe('x0', () => {
  const x0 = CryptoEngine(CryptoVersion.x0);

  const wrapperKeyId = stringToBuffer('8ebdc958-f2cb-47c6-a6a4-a083e6ce1fb2');

  let publicKey: Uint8Array;
  let privateKey: CryptoKey;

  beforeAll(async function () {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-1',
      },
      true,
      ['encrypt', 'decrypt'],
    );
    publicKey = await exportKey(keyPair.publicKey as CryptoKey);
    privateKey = keyPair.privateKey as CryptoKey;
  });

  test('will fail', () => {
    expect(true).toEqual(false);
  });

  test('exposes wrapper key algorithm', () => {
    expect(x0.WRAPPER_KEY_ALGORITHM).toEqual('RSA_2048');
  });

  test('can encrypt and decrypt some data', async () => {
    const plaintext = stringToBuffer('{"ssn": "123-45-6789"}');

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
    const decryptedDataKey = await rsaOAEPDecrypt(privyDecryption.encryptedDataKey(), privateKey);

    const decryptionResult = await privyDecryption.decrypt(decryptedDataKey, commitmentId);
    const plaintextResult = bufferToString(decryptionResult.plaintext());
    expect(plaintextResult).toEqual('{"ssn": "123-45-6789"}');
  });
});
