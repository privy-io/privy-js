import {IV_LENGTH_12_BYTES} from '../../src/crypto/constants';
import {Crypto as node} from '../../src/crypto/node';
import {Crypto as browser} from '../../src/crypto/browser';
import {toBuffer, toString, toHex} from './../encoding';
import {generateRSAKeyPair, rsaOAEPDecrypt} from './../rsa';

/**
 * These tests require the Web Crypto implementation in Node.js, which
 * is available in Node v15.x and above. However, we run tests in
 * all versions we support, which includes Node 14. Therefore, this
 * file must be excluded from normal test runs (which are run in Node 14)
 * and run separately using more recent Node versions.
 */

describe('browser', () => {
  describe('aes', () => {
    it('can encrypt and decrypt', async () => {
      const key = await browser.aesGCMEncryptionKey();
      const iv = browser.csprng(IV_LENGTH_12_BYTES);
      const pt = toBuffer('123-45-6789');
      const ct = await browser.aesGCMEncrypt(pt, iv, key);

      // Browser decrypt
      const decrypted = await browser.aesGCMDecrypt(ct, iv, key);

      expect(decrypted).toEqual(pt);
      expect(toString(decrypted)).toEqual('123-45-6789');
    });

    it('can be decrypted by node implementation', async () => {
      const key = await browser.aesGCMEncryptionKey();
      const iv = browser.csprng(IV_LENGTH_12_BYTES);
      const pt = toBuffer('123-45-6789');
      const ct = await browser.aesGCMEncrypt(pt, iv, key);

      // Node decrypt
      const decrypted = await node.aesGCMDecrypt(ct, iv, key);

      expect(decrypted).toEqual(pt);
      expect(toString(decrypted)).toEqual('123-45-6789');
    });
  });

  describe('sha256', () => {
    it('correctly computes the sha256 hash', async () => {
      const hash = await browser.sha256(toBuffer('123-45-6789'));
      expect(toHex(hash)).toEqual(
        '01a54629efb952287e554eb23ef69c52097a75aecc0e3a93ca0855ab6d7a31a0',
      );
    });
  });

  describe('rsa', () => {
    it('can encrypt', async () => {
      const keyPair = generateRSAKeyPair();
      const publicKey = keyPair.publicKey;
      const privateKey = keyPair.privateKey;

      const pt = toBuffer('secret-key');

      const encrypted = await browser.rsaOAEPEncrypt(pt, publicKey);
      const decrypted = rsaOAEPDecrypt(encrypted, privateKey);

      expect(decrypted).toEqual(pt);
      expect(toString(decrypted)).toEqual('secret-key');
    });
  });
});

describe('node', () => {
  describe('aes', () => {
    it('can encrypt and decrypt', async () => {
      const key = await node.aesGCMEncryptionKey();
      const iv = node.csprng(IV_LENGTH_12_BYTES);
      const pt = toBuffer('123-45-6789');
      const ct = await node.aesGCMEncrypt(pt, iv, key);

      // Node decrypt
      const decrypted = await node.aesGCMDecrypt(ct, iv, key);

      expect(decrypted).toEqual(pt);
      expect(toString(decrypted)).toEqual('123-45-6789');
    });

    it('can be decrypted by browser implementation', async () => {
      const key = await node.aesGCMEncryptionKey();
      const iv = node.csprng(IV_LENGTH_12_BYTES);
      const pt = toBuffer('123-45-6789');
      const ct = await node.aesGCMEncrypt(pt, iv, key);

      // Browser decrypt
      const decrypted = await browser.aesGCMDecrypt(ct, iv, key);

      expect(decrypted).toEqual(pt);
      expect(toString(decrypted)).toEqual('123-45-6789');
    });
  });

  describe('sha256', () => {
    it('correctly computes the sha256 hash', async () => {
      const hash = await node.sha256(toBuffer('123-45-6789'));
      expect(toHex(hash)).toEqual(
        '01a54629efb952287e554eb23ef69c52097a75aecc0e3a93ca0855ab6d7a31a0',
      );
    });
  });

  describe('rsa', () => {
    it('can encrypt', async () => {
      const keyPair = generateRSAKeyPair();
      const publicKey = keyPair.publicKey;
      const privateKey = keyPair.privateKey;

      const pt = toBuffer('secret-key');

      const encrypted = await node.rsaOAEPEncrypt(pt, publicKey);
      const decrypted = rsaOAEPDecrypt(encrypted, privateKey);

      expect(decrypted).toEqual(pt);
      expect(toString(decrypted)).toEqual('secret-key');
    });
  });
});
