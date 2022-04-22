import crypto from 'crypto';

export function generateRSAKeyPair() {
  const keys = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  const publicKeyBuffer = keys.publicKey.export({
    type: 'spki',
    format: 'der',
  });

  return {
    publicKey: new Uint8Array(publicKeyBuffer),
    privateKey: keys.privateKey,
  };
}

export function rsaOAEPDecrypt(pt: Uint8Array, privateKey: crypto.KeyObject) {
  return crypto.privateDecrypt(
    {
      key: privateKey,
      oaepHash: 'sha1',
    },
    pt,
  );
}
