import {
  CryptoVersion,
  cryptoVersionToBuffer,
  cryptoVersionFromBuffer,
  CRYPTO_VERSION_LENGTH_IN_BYTES,
} from '../version';
import {PrivyCryptoError} from '../errors';
import {bufferFromUInt64, concatBuffers, uint64FromBuffer} from '../buffers';
import {aes256gcmEncrypt, aes256gcmDecrypt, csprng, rsaOaepSha1Encrypt} from '../crypto';

const IV_LENGTH_IN_BYTES = 12;
const AUTH_TAG_LENGTH_IN_BYTES = 16;
const DATA_KEY_LENGTH_IN_BYTES = 32;

export class EncryptionResult {
  /**
   * Ciphertext buffer
   * @internal
   */
  _ciphertext: Buffer;

  constructor(ciphertext: Buffer) {
    this._ciphertext = ciphertext;
  }

  /**
   * Returns the ciphertext.
   *
   * @param {BufferEncoding} [encoding] - Optional encoding which converts the ciphertext to a string using the given encoding.
   */
  getCiphertext(): Buffer;
  getCiphertext(encoding: BufferEncoding): string;
  getCiphertext(encoding?: BufferEncoding) {
    if (encoding !== undefined) {
      return this._ciphertext.toString(encoding);
    } else {
      return this._ciphertext;
    }
  }
}

export interface EncryptConfig {
  // The wrapper key (RSA public key in PEM format).
  wrapperKey: Buffer;

  // The metadata ID of the RSA public key.
  wrapperKeyId: Buffer;
}

export class Encryption {
  /**
   * Plaintext buffer
   * @internal
   */
  _plaintext: Buffer;

  /**
   * Config object
   * @internal
   */
  _config: EncryptConfig;

  /**
   * Instantiates a new Encryption instance.
   *
   * @param {Buffer} plaintext - The plaintext data to encrypt.
   * @param {EncryptConfig} config - An object to configure encryption.
   *   * wrapperKey - (Buffer) The wrapper key (RSA public key in PEM format).
   *   * wrapperKeyId - (Buffer) The metadata ID of the RSA public key.
   */
  constructor(plaintext: Buffer, config: EncryptConfig) {
    this._plaintext = plaintext;
    this._config = config;
  }

  /**
   * Serialize creates a buffer with the following
   * components concatenated together:
   *
   *     cryptoVersionBuf (UInt16BE)
   *     || wrapperKeyIdLengthInBytes (BigUint64)
   *     || wrapperKeyId (Buffer)
   *     || encryptedDataKeyLengthInBytes (BigUint64)
   *     || encryptedDataKey (Buffer)
   *     || initializationVector (buffer) (12 bytes)
   *     || encryptedDataLengthInBytes (BigUint64)
   *     || encryptedData (Buffer)
   *     || authenticationTag (Buffer) (16 bytes)
   *
   * @internal
   */
  _serialize(
    ciphertext: Buffer,
    encryptedDataKey: Buffer,
    authenticationTag: Buffer,
    initializationVector: Buffer,
    wrapperKeyId: Buffer,
  ): Buffer {
    return concatBuffers(
      cryptoVersionToBuffer(CryptoVersion.x0),
      bufferFromUInt64(wrapperKeyId.length),
      wrapperKeyId,
      bufferFromUInt64(encryptedDataKey.length),
      encryptedDataKey,
      initializationVector,
      bufferFromUInt64(ciphertext.length),
      ciphertext,
      authenticationTag,
    );
  }

  /**
   * Encrypts the given plaintext data.
   *
   * At a high level, the encryption algorithm is implemented as follows:
   *
   *     1. Generate a single-use secret key (aka data key)
   *     2. Encrypt (AES-256-GCM) plaintext data using data key
   *     3. Encrypt (RSA-OAEP-SHA1) data key with wrapper key (RSA public key)
   *     4. Serialize the following components into a single buffer:
   *         * Privy crypto version (0x0001 in this case)
   *         * wrapper key id
   *         * encrypted data key
   *         * initialization vector for AES-256-GCM
   *         * encrypted data
   *         * authentication tag from AES-256-GCM
   *     5. Return an EncryptionResult object
   *
   * @returns a Promise that resolves to an EncryptionResult
   */
  async encrypt(): Promise<EncryptionResult> {
    // 1. Generate a single-use secret key (aka, data key)
    const dataKey = csprng(DATA_KEY_LENGTH_IN_BYTES);

    try {
      // 2. Encrypt (AES-256-GCM) plaintext data using data key
      const {ciphertext, initializationVector, authenticationTag} = aes256gcmEncrypt(
        this._plaintext,
        dataKey,
        {
          ivLengthInBytes: IV_LENGTH_IN_BYTES,
          authTagLengthInBytes: AUTH_TAG_LENGTH_IN_BYTES,
        },
      );

      // 3. Encrypt (RSA-OAEP-SHA1) data key with wrapper key (RSA public key)
      const encryptedDataKey = rsaOaepSha1Encrypt(dataKey, this._config.wrapperKey);

      // 4. Serialize the following components into a single buffer
      const serialized = this._serialize(
        ciphertext,
        encryptedDataKey,
        authenticationTag,
        initializationVector,
        this._config.wrapperKeyId,
      );

      // 5. Return the encryption result
      return new EncryptionResult(serialized);
    } catch (error) {
      throw new PrivyCryptoError('Failed to encrypt plaintext', error);
    } finally {
      // Always clear the secret data key from memory
      dataKey.fill(0);
    }
  }
}

export class DecryptionResult {
  /**
   * plaintext buffer
   * @internal
   */
  _plaintext: Buffer;

  /**
   * constructor
   * @internal
   */
  constructor(plaintext: Buffer) {
    this._plaintext = plaintext;
  }

  /**
   * Returns the plaintext.
   *
   * @param {BufferEncoding} [encoding] - Optional encoding which converts the plaintext to a string using the given encoding.
   */
  getPlaintext(): Buffer;
  getPlaintext(encoding: BufferEncoding): string;
  getPlaintext(encoding?: BufferEncoding) {
    if (encoding !== undefined) {
      return this._plaintext.toString(encoding);
    } else {
      return this._plaintext;
    }
  }
}

export class Decryption {
  /**
   * wrapper key id buffer
   * @internal
   */
  _wrapperKeyId: Buffer;

  /**
   * encrypted data key buffer
   * @internal
   */
  _encryptedDataKey: Buffer;

  /**
   * initialization vector buffer
   * @internal
   */
  _initializationVector: Buffer;

  /**
   * ciphertext buffer
   * @internal
   */
  _ciphertext: Buffer;

  /**
   * authentication tag buffer
   * @internal
   */
  _authenticationTag: Buffer;

  /**
   * Instantiates a new Decryption instance.
   *
   * @param {Buffer} serialized - The serialized encrypted data to decrypt.
   */
  constructor(serialized: Buffer) {
    const {
      cryptoVersion,
      wrapperKeyId,
      encryptedDataKey,
      initializationVector,
      ciphertext,
      authenticationTag,
    } = this._deserializeEncryptedData(serialized);

    if (cryptoVersion !== CryptoVersion.x0) {
      throw new PrivyCryptoError(
        `Invalid PrivyCrypto version for engine: expected ${CryptoVersion.x0} but got ${cryptoVersion}`,
      );
    } else if (initializationVector.length !== IV_LENGTH_IN_BYTES) {
      throw new PrivyCryptoError(
        `Invalid initialization vector length: expected ${IV_LENGTH_IN_BYTES} but got ${initializationVector.length}`,
      );
    } else if (authenticationTag.length !== AUTH_TAG_LENGTH_IN_BYTES) {
      throw new PrivyCryptoError(
        `Invalid authentication tag length: expected ${AUTH_TAG_LENGTH_IN_BYTES} but got ${authenticationTag.length}`,
      );
    }

    this._wrapperKeyId = wrapperKeyId;
    this._encryptedDataKey = encryptedDataKey;
    this._initializationVector = initializationVector;
    this._ciphertext = ciphertext;
    this._authenticationTag = authenticationTag;
  }

  /**
   * Deserialize the encrypted data components
   * @internal
   */
  _deserializeEncryptedData(serializedEncryptedData: Buffer) {
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

    // Read initialization vector.
    const initializationVector = serializedEncryptedData.slice(offset, offset + IV_LENGTH_IN_BYTES);
    offset += IV_LENGTH_IN_BYTES;

    // Read encrypted data length.
    const [encryptedDataLength, encryptedDataOffset] = uint64FromBuffer(
      serializedEncryptedData,
      offset,
    );
    offset = encryptedDataOffset;

    // Read encrypted data.
    const ciphertext = serializedEncryptedData.slice(offset, offset + encryptedDataLength);
    offset += encryptedDataLength;

    // Read authentication tag.
    const authenticationTag = serializedEncryptedData.slice(offset);

    return {
      cryptoVersion: cryptoVersion,
      wrapperKeyId: wrapperKeyId,
      encryptedDataKey: encryptedDataKey,
      initializationVector: initializationVector,
      ciphertext: ciphertext,
      authenticationTag: authenticationTag,
    };
  }

  /**
   * Returns the wrapper key id.
   *
   * @param {BufferEncoding} [encoding] - Optional encoding which converts the wrapper key id to a string using the given encoding.
   */
  getWrapperKeyId(): Buffer;
  getWrapperKeyId(encoding: BufferEncoding): string;
  getWrapperKeyId(encoding?: BufferEncoding) {
    if (encoding !== undefined) {
      return this._wrapperKeyId.toString(encoding);
    } else {
      return this._wrapperKeyId;
    }
  }

  /**
   * Returns the encrypted data key.
   *
   * @param {BufferEncoding} [encoding] - Optional encoding which converts the encrypted data key to a string using the given encoding.
   */
  getEncryptedDataKey(): Buffer;
  getEncryptedDataKey(encoding: BufferEncoding): string;
  getEncryptedDataKey(encoding?: BufferEncoding) {
    if (encoding !== undefined) {
      return this._encryptedDataKey.toString(encoding);
    } else {
      return this._encryptedDataKey;
    }
  }

  /**
   * Decrypts the encrypted data using the given data key.
   *
   * @param {Buffer} dataKey - The secret key used to encrypt the data.
   * @returns DecryptionResult containing the plaintext data
   */
  async decrypt(dataKey: Buffer): Promise<DecryptionResult> {
    try {
      const plaintext = aes256gcmDecrypt(
        this._ciphertext,
        dataKey,
        this._initializationVector,
        this._authenticationTag,
      );

      return new DecryptionResult(plaintext);
    } catch (error) {
      throw new PrivyCryptoError('Failed to decrypt the encrypted data', error);
    } finally {
      // Always clear the secret data key from memory
      dataKey.fill(0);
    }
  }
}
