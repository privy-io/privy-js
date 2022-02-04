import {CryptoError} from './errors';

export const CRYPTO_VERSION_LENGTH_IN_BYTES = 2;

// Over time, there will likely be multiple iterations
// of the crypto algorithm for securely encrypting data.
// In order for decryption to work even after new iterations
// have been released, this library must keep track of the
// version used to encrypt the data so that it knows which
// algorithm to use during decryption.
export enum CryptoVersion {
  x0 = 0x0000,
}

export function cryptoVersionFromBuffer(serialized: Buffer): CryptoVersion {
  const versionBuffer = serialized.slice(0, CRYPTO_VERSION_LENGTH_IN_BYTES);
  const version = versionBuffer.readUInt16BE();

  switch (version) {
    case CryptoVersion.x0:
      return CryptoVersion.x0;
    default:
      throw new CryptoError(`Invalid Privy crypto version: ${version} is not a valid version`);
  }
}

export function cryptoVersionToBuffer(version: CryptoVersion): Buffer {
  const cryptoVersionBuffer = Buffer.alloc(CRYPTO_VERSION_LENGTH_IN_BYTES);
  cryptoVersionBuffer.writeUInt16BE(version);
  return cryptoVersionBuffer;
}
