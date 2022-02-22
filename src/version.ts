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

export function cryptoVersionFromBuffer(serialized: Uint8Array): CryptoVersion {
  const versionDataView = new DataView(
    serialized.buffer,
    serialized.byteOffset,
    serialized.byteLength,
  );
  const version = versionDataView.getUint16(0, false); // Big endian.

  switch (version) {
    case CryptoVersion.x0:
      return CryptoVersion.x0;
    default:
      throw new CryptoError(`Invalid Privy crypto version: ${version} is not a valid version`);
  }
}

export function cryptoVersionToBuffer(version: CryptoVersion): Uint8Array {
  const cryptoVersionBuffer = new ArrayBuffer(CRYPTO_VERSION_LENGTH_IN_BYTES);
  new DataView(cryptoVersionBuffer).setUint16(0, version, false); // Big endian.
  return new Uint8Array(cryptoVersionBuffer);
}
