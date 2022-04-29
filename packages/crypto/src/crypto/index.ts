import {CryptoOperations} from './types';

/**
 * Creates a proxy to an underlying implementation of crypto operations.
 *
 * This is used to create a stable object by which callers can operate
 * against while allowing the underlying implementation to be configured.
 * It is used to configure the implementation depending on whether the
 * environment is node or the browser.
 *
 * @internal
 */
function createCryptoProxy(): [CryptoOperations, (impl: CryptoOperations) => void] {
  let crypto: CryptoOperations | void = undefined;

  function setCrypto(impl: CryptoOperations) {
    crypto = impl;
  }

  const proxy: CryptoOperations = {
    get csprng() {
      return crypto!.csprng;
    },

    get sha256() {
      return crypto!.sha256;
    },

    get aesGCMEncrypt() {
      return crypto!.aesGCMEncrypt;
    },

    get aesGCMDecrypt() {
      return crypto!.aesGCMDecrypt;
    },

    get aesGCMEncryptionKey() {
      return crypto!.aesGCMEncryptionKey;
    },

    get rsaOAEPEncrypt() {
      return crypto!.rsaOAEPEncrypt;
    },
  };

  return [proxy, setCrypto];
}

const [crypto, _setCrypto] = createCryptoProxy();

export default crypto;
export const setCrypto = _setCrypto;
