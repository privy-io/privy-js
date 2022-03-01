import {
  CryptoVersion,
  cryptoVersionToBuffer,
  cryptoVersionFromBuffer,
  CRYPTO_VERSION_LENGTH_IN_BYTES,
} from '../version';
import {CryptoError} from '../errors';
import {bufferFromUInt64, buffersEqual, concatBuffers, uint64FromBuffer} from '../buffers';
import {
  aesGCMEncrypt,
  aesGCMDecrypt,
  AUTH_TAG_LENGTH_16_BYTES,
  COMMITMENT_NONCE_LENGTH_32_BYTES,
  csprng,
  generateAESGCMEncryptionKey,
  importRSAOAEPEncryptionKey,
  IV_LENGTH_12_BYTES,
  rsaOaepWrapKey,
  importAESGCMDecryptionKey,
  sha256,
} from '../crypto';

/**
 * This is only used to encrypt the AES secret key so that
 * the only way to decrypt it is with the RSA private key.
 * The RSA private key is stored in an HSM and is thus never
 * exposed to the Privy server or any clients.
 *
 * The next iteration of Privy's crypto code will be using ECC
 * and thus moving away from the less secure RSA+SHA1.
 */
export const WRAPPER_KEY_ALGORITHM = 'RSA_2048';

export class EncryptionResult {
  /**
   * Ciphertext buffer
   * @internal
   */
  _ciphertext: Uint8Array;

  /**
   * Wrapper key id buffer
   * @internal
   */
  _wrapperKeyId: Uint8Array;

  /**
   * Hash of (nonce || plaintext) used for content addressing.
   * @internal
   */
  _commitmentId: Uint8Array;

  /**
   * Constructor
   * @internal
   */
  constructor(ciphertext: Uint8Array, wrapperKeyId: Uint8Array, commitmentId: Uint8Array) {
    this._ciphertext = ciphertext;
    this._wrapperKeyId = wrapperKeyId;
    this._commitmentId = commitmentId;
  }

  /**
   * Returns the ciphertext.
   */
  ciphertext(): Uint8Array {
    return this._ciphertext;
  }

  /**
   * Returns the wrapper key id.
   */
  wrapperKeyId(): Uint8Array {
    return this._wrapperKeyId;
  }

  /**
   * Returns the commitment id which is (a sha256 hash).
   */
  commitmentId(): Uint8Array {
    return this._commitmentId;
  }
}

export interface EncryptConfig {
  // The wrapper key (RSA public key in DER format).
  wrapperKey: Uint8Array;

  // The metadata ID of the RSA public key.
  wrapperKeyId: Uint8Array;
}

export class Encryption {
  /**
   * Plaintext buffer
   * @internal
   */
  _plaintext: Uint8Array;

  /**
   * Config object
   * @internal
   */
  _config: EncryptConfig;

  /**
   * Instantiates a new Encryption instance.
   *
   * @param plaintext - The plaintext data to encrypt.
   * @param {EncryptConfig} config - An object to configure encryption.
   *   * wrapperKey - (Uint8Array) The wrapper key (RSA public key in DER format).
   *   * wrapperKeyId - (Uint8Array) The metadata ID of the RSA public key.
   */
  constructor(plaintext: Uint8Array, config: EncryptConfig) {
    this._plaintext = plaintext;
    this._config = config;
  }

  /**
   * Serialize creates a buffer with the following
   * components concatenated together:
   *
   *     cryptoVersionBuf (UInt16BE)
   *     || wrapperKeyIdLengthInBytes (BigUint64)
   *     || wrapperKeyId (Uint8Array)
   *     || encryptedDataKeyLengthInBytes (BigUint64)
   *     || encryptedDataKey (Uint8Array)
   *     || initializationVector (Uint8Array) (12 bytes)
   *     || encryptedDataLengthInBytes (BigUint64)
   *     || encryptedData (Uint8Array)
   *     || dataAuthenticationTag (Uint8Array) (16 bytes)
   *     || encryptedNonce (32 bytes)
   *     || nonceAuthenticationTag (Uint8Array) (16 bytes)
   *
   * @internal
   */
  _serialize(
    encryptedData: Uint8Array,
    encryptedDataKey: Uint8Array,
    encryptedNonce: Uint8Array,
    dataInitializationVector: Uint8Array,
    nonceInitializationVector: Uint8Array,
    wrapperKeyId: Uint8Array,
  ): Uint8Array {
    return concatBuffers(
      cryptoVersionToBuffer(CryptoVersion.x0),
      bufferFromUInt64(wrapperKeyId.byteLength),
      wrapperKeyId,
      bufferFromUInt64(encryptedDataKey.byteLength),
      encryptedDataKey,
      dataInitializationVector,
      bufferFromUInt64(encryptedData.byteLength - AUTH_TAG_LENGTH_16_BYTES),
      encryptedData,
      nonceInitializationVector,
      encryptedNonce,
    );
  }

  /**
   * Encrypts the given plaintext data.
   *
   * At a high level, the encryption algorithm is implemented as follows:
   *
   *     1. Generate a secret key (aka, data key) and initialization vector
   *     2. Encrypt (AES-256-GCM) plaintext data using data key
   *     3. Generate and encrypt a nonce used for data integrity checks
   *     4. Encrypt (RSA-OAEP-SHA1) data key with wrapper key (RSA public key)
   *     5. Serialize the following components into a single buffer:
   *         * Privy crypto version (0x0001 in this case)
   *         * wrapper key id
   *         * encrypted data key
   *         * initialization vector for AES-256-GCM
   *         * encrypted data
   *         * encrypted nonce
   *     6. Generate the commitment id (sha256 hash) for (nonce || plaintext)
   *     7. Return an EncryptionResult object
   *
   * @returns a Promise that resolves to an EncryptionResult
   */
  async encrypt(): Promise<EncryptionResult> {
    try {
      // 1. Generate a secret key (aka, data key) and initialization vector
      const dataKey = await generateAESGCMEncryptionKey();
      const dataInitializationVector = csprng(IV_LENGTH_12_BYTES);

      // 2. Encrypt (AES-256-GCM) plaintext data using data key
      const encryptedData = await aesGCMEncrypt(this._plaintext, dataInitializationVector, dataKey);

      // 3. Generate and encrypt a nonce used for data integrity checks
      const nonce = csprng(IV_LENGTH_12_BYTES);
      const nonceInitializationVector = csprng(IV_LENGTH_12_BYTES);
      const encryptedNonce = await aesGCMEncrypt(nonce, nonceInitializationVector, dataKey);

      // 4. Encrypt (RSA-OAEP-SHA1) data key with wrapper key (RSA public key in DER format)
      const wrapperKey = await importRSAOAEPEncryptionKey(this._config.wrapperKey);
      const encryptedDataKey = await rsaOaepWrapKey(dataKey, wrapperKey);

      // 5. Serialize the following components into a single buffer
      const serialized = this._serialize(
        encryptedData,
        encryptedDataKey,
        encryptedNonce,
        dataInitializationVector,
        nonceInitializationVector,
        this._config.wrapperKeyId,
      );

      // 6. Generate the commitment id (sha256 hash) for (nonce || plaintext)
      const commitmentId = await sha256(concatBuffers(nonce, this._plaintext));

      // 7. Return an EncryptionResult object
      return new EncryptionResult(serialized, this._config.wrapperKeyId, commitmentId);
    } catch (error) {
      throw new CryptoError('Failed to encrypt plaintext', error);
    }
  }
}

export class DecryptionResult {
  /**
   * Plaintext buffer
   * @internal
   */
  _plaintext: Uint8Array;

  /**
   * Constructor
   * @internal
   */
  constructor(plaintext: Uint8Array) {
    this._plaintext = plaintext;
  }

  /**
   * Returns the plaintext.
   */
  plaintext(): Uint8Array {
    return this._plaintext;
  }
}

export class Decryption {
  /**
   * Wrapper key id buffer
   * @internal
   */
  _wrapperKeyId: Uint8Array;

  /**
   * Encrypted data key buffer
   * @internal
   */
  _encryptedDataKey: Uint8Array;

  /**
   * Initialization vector buffer for the encrypted data.
   * @internal
   */
  _dataInitializationVector: Uint8Array;

  /**
   * Initialization vector buffer for the encrypted nonce.
   * @internal
   */
  _nonceInitializationVector: Uint8Array;

  /**
   * Ciphertext buffer
   * @internal
   */
  _ciphertext: Uint8Array;

  /**
   * Encrypted nonce buffer
   * @internal
   */
  _encryptedNonce: Uint8Array;

  /**
   * Instantiates a new Decryption instance.
   *
   * @param serialized - The serialized encrypted data to decrypt.
   */
  constructor(serialized: Uint8Array) {
    const {
      cryptoVersion: cryptoVersion,
      wrapperKeyId: wrapperKeyId,
      encryptedDataKey: encryptedDataKey,
      dataInitializationVector: dataInitializationVector,
      ciphertext: ciphertext,
      nonceInitializationVector: nonceInitializationVector,
      encryptedNonce: encryptedNonce,
    } = this._deserializeEncryptedData(serialized);

    if (cryptoVersion !== CryptoVersion.x0) {
      throw new CryptoError(
        `Invalid PrivyCrypto version for engine: expected ${CryptoVersion.x0} but got ${cryptoVersion}`,
      );
    }

    if (dataInitializationVector.length !== IV_LENGTH_12_BYTES) {
      throw new CryptoError(
        `Invalid initialization vector length: expected ${IV_LENGTH_12_BYTES} but got ${dataInitializationVector.length}`,
      );
    }

    this._wrapperKeyId = wrapperKeyId;
    this._encryptedDataKey = encryptedDataKey;
    this._dataInitializationVector = dataInitializationVector;
    this._ciphertext = ciphertext;
    this._nonceInitializationVector = nonceInitializationVector;
    this._encryptedNonce = encryptedNonce;
  }

  /**
   * Deserialize the encrypted data components
   * @internal
   */
  _deserializeEncryptedData(serializedEncryptedData: Uint8Array) {
    const cryptoVersion = cryptoVersionFromBuffer(serializedEncryptedData);

    let offset = CRYPTO_VERSION_LENGTH_IN_BYTES;

    // Read wrapperKeyId length.
    const [wrapperKeyIdLength, wrapperKeyIdOffset] = uint64FromBuffer(
      serializedEncryptedData,
      offset,
    );
    offset = wrapperKeyIdOffset;

    // Read wrapperKeyId.
    const wrapperKeyId = serializedEncryptedData.slice(offset, offset + wrapperKeyIdLength);
    offset += wrapperKeyIdLength;

    // Read encrypted data key length.
    const [encryptedDataKeyLength, dataKeyOffset] = uint64FromBuffer(
      serializedEncryptedData,
      offset,
    );
    offset = dataKeyOffset;

    // Read encrypted data key.
    const encryptedDataKey = serializedEncryptedData.slice(offset, offset + encryptedDataKeyLength);
    offset += encryptedDataKeyLength;

    // Read data initialization vector.
    const dataInitializationVector = serializedEncryptedData.slice(
      offset,
      offset + IV_LENGTH_12_BYTES,
    );
    offset += IV_LENGTH_12_BYTES;

    // Read encrypted data length.
    const [encryptedDataLength, encryptedDataOffset] = uint64FromBuffer(
      serializedEncryptedData,
      offset,
    );
    offset = encryptedDataOffset;

    const encryptedDataAndAuthTagLength = encryptedDataLength + AUTH_TAG_LENGTH_16_BYTES;

    // Read encrypted data.
    const ciphertext = serializedEncryptedData.slice(
      offset,
      offset + encryptedDataAndAuthTagLength,
    );
    offset += encryptedDataAndAuthTagLength;

    // Check if nonce is included (for backwards compatibility) and deserialize if so.
    let encryptedNonce: Uint8Array = new Uint8Array(0);
    let nonceInitializationVector: Uint8Array = new Uint8Array(0);
    if (offset < serializedEncryptedData.length) {
      // Read data initialization vector.
      nonceInitializationVector = serializedEncryptedData.slice(
        offset,
        offset + IV_LENGTH_12_BYTES,
      );
      offset += IV_LENGTH_12_BYTES;

      // Read encrypted nonce.
      encryptedNonce = serializedEncryptedData.slice(
        offset,
        offset + COMMITMENT_NONCE_LENGTH_32_BYTES + AUTH_TAG_LENGTH_16_BYTES,
      );
    }

    return {
      cryptoVersion: cryptoVersion,
      wrapperKeyId: wrapperKeyId,
      encryptedDataKey: encryptedDataKey,
      dataInitializationVector: dataInitializationVector,
      ciphertext: ciphertext,
      nonceInitializationVector: nonceInitializationVector,
      encryptedNonce: encryptedNonce,
    };
  }

  /**
   * Returns the wrapper key id.
   */
  wrapperKeyId(): Uint8Array {
    return this._wrapperKeyId;
  }

  /**
   * Returns the encrypted data key.
   */
  encryptedDataKey(): Uint8Array {
    return this._encryptedDataKey;
  }

  /**
   * Decrypts the encrypted data using the given data key.
   *
   * @param {Uint8Array} dataKeyTypedArray - The secret key used to encrypt the data.
   * @param {Uint8Array} commitmentId - Optional commitment hash used to perform optional data integrity check.
   * @returns DecryptionResult containing the plaintext data.
   */
  async decrypt(
    dataKeyTypedArray: Uint8Array,
    commitmentId?: Uint8Array,
  ): Promise<DecryptionResult> {
    try {
      const dataKey = await importAESGCMDecryptionKey(dataKeyTypedArray);

      // Decrypt plaintext.
      const plaintext = await aesGCMDecrypt(
        this._ciphertext,
        this._dataInitializationVector,
        dataKey,
      );

      // If commitmentHash passed in, perform integrity check against the commitmentHash.
      if (commitmentId) {
        // Decrypt nonce.
        const nonce = await aesGCMDecrypt(
          this._encryptedNonce,
          this._nonceInitializationVector,
          dataKey,
        );

        // Calculate hash.
        const hash = await sha256(concatBuffers(nonce, plaintext));
        if (!buffersEqual(hash, commitmentId)) {
          throw new CryptoError(
            `Data integrity check failed: expected ${commitmentId}, but got ${hash}`,
          );
        }
      }
      return new DecryptionResult(plaintext);
    } catch (error) {
      if (error instanceof CryptoError) {
        throw error;
      } else {
        throw new CryptoError('Failed to decrypt the encrypted data', error);
      }
    }
  }
}
