const isNode = !!(typeof process !== 'undefined' && process.versions && process.versions.node);

function getCrypto(): Crypto {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
    // Both (newish) browsers and Node define the globalThis object.
    //
    // Latest node versions (>=17.6.0) add a browser-compatible
    // implementation of the Crypto module to the global scope.
    //
    // https://nodejs.org/api/globals.html#crypto
    //
    return globalThis.crypto;
  } else if (isNode) {
    // Older node versions need to require webcrypto from crypto.
    // However, using require breaks client bundlers unless extra
    // configuration is added. This avoids the need to do so.
    return eval('require')('crypto').webcrypto;
  } else if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    // Crypto module is older than globalThis, so this may apply to older browsers.
    return window.crypto;
  } else {
    throw new Error('crypto is not supported in this environment');
  }
}

export const crypto = getCrypto();
