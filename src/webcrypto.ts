import {isNode} from './env';

export const crypto: Crypto = isNode ? require('crypto').webcrypto : globalThis.crypto;
