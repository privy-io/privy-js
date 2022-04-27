import {CryptoOperations} from './types';

const isNode = !!(typeof process !== 'undefined' && process.versions && process.versions.node);

function getCryptoOperations(): CryptoOperations {
  if (isNode) {
    // eval('require') here so that browser bundlers
    // DO NOT try to package and bundle Node.js libraries.
    return eval('require')('./node').Crypto;
  } else {
    // require('module') here so that browser bundlers
    // DO package and bundle this code.
    return require('./crypto/browser').Crypto;
  }
}

export default getCryptoOperations();
