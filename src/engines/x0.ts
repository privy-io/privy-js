import {
  CryptoVersion,
  cryptoVersionToBuffer,
  cryptoVersionFromBuffer,
  CRYPTO_VERSION_LENGTH_IN_BYTES,
} from '../version';
import {CryptoError} from '../errors';
import {bufferFromUInt64, concatBuffers, uint64FromBuffer} from '../buffers';
import {
  aes256gcmEncrypt,
  aes256gcmDecrypt,
  csprng,
  rsaOaepSha1Encrypt,
  sha256Hash,
} from '../crypto';

// NIST recommended lengths
const IV_LENGTH_IN_BYTES = 12;
const AUTH_TAG_LENGTH_IN_BYTES = 16;
const DATA_KEY_LENGTH_IN_BYTES = 32;
// Nonce to match AES256GCM key length.
const NONCE_LENGTH_IN_BYTES = DATA_KEY_LENGTH_IN_BYTES;

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
  _ciphertext: Buffer;

  /**
   * Wrapper key id buffer
   * @internal
   */
  _wrapperKeyId: Buffer;

  /**
   * Hash of (nonce || plaintext) used for content addressing.
   * @internal
   */
  _contentHash: Buffer;

  /**
   * Constructor
   * @internal
   */
  constructor(ciphertext: Buffer, wrapperKeyId: Buffer, contentHash: Buffer) {
    this._ciphertext = ciphertext;
    this._wrapperKeyId = wrapperKeyId;
    this._contentHash = contentHash;
  }

  /**
   * Returns the ciphertext.
   *
   * @param {BufferEncoding} [encoding] - Optional encoding which converts the ciphertext to a string using the given encoding.
   */
  ciphertext(): Buffer;
  ciphertext(encoding: BufferEncoding): string;
  ciphertext(encoding?: BufferEncoding) {
    if (encoding !== undefined) {
      return this._ciphertext.toString(encoding);
    } else {
      return this._ciphertext;
    }
  }

  /**
   * Returns the wrapper key id.
   *
   * @param {BufferEncoding} [encoding] - Optional encoding which converts the wrapper key id to a string using the given encoding.
   */
  wrapperKeyId(): Buffer;
  wrapperKeyId(encoding: BufferEncoding): string;
  wrapperKeyId(encoding?: BufferEncoding) {
    if (encoding !== undefined) {
      return this._wrapperKeyId.toString(encoding);
    } else {
      return this._wrapperKeyId;
    }
  }

  /**
   * Returns the content hash.
   *
   * @param {BufferEncoding} [encoding] - Optional encoding which converts the content hash to a string using the given encoding.
   */
  contentHash(): Buffer;
  contentHash(encoding: BufferEncoding): string;
  contentHash(encoding?: BufferEncoding) {
    if (encoding !== undefined) {
      return this._contentHash.toString(encoding);
    } else {
      return this._contentHash;
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
   *     || dataAuthenticationTag (Buffer) (16 bytes)
   *     || encryptedNonce (32 bytes)
   *     || nonceAuthenticationTag (Buffer) (16 bytes)
   *
   * @internal
   */
  _serialize(
    ciphertext: Buffer,
    encryptedDataKey: Buffer,
    dataAuthenticationTag: Buffer,
    initializationVector: Buffer,
    wrapperKeyId: Buffer,
    encryptedNonce: Buffer,
    nonceAuthenticationTag: Buffer,
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
      dataAuthenticationTag,
      encryptedNonce,
      nonceAuthenticationTag,
    );
  }

  /**
   * Encrypts the given plaintext data.
   *
   * At a high level, the encryption algorithm is implemented as follows:
   *
   *     1. Generate a secret key (aka data key)
   *     2. Encrypt (AES-256-GCM) plaintext data using data key
   *     3. Encrypt (RSA-OAEP-SHA1) data key with wrapper key (RSA public key)
   *     4. Generate content hash of a nonce concatenated with the plaintext.
   *     5. Serialize the following components into a single buffer:
   *         * Privy crypto version (0x0001 in this case)
   *         * wrapper key id
   *         * encrypted data key
   *         * initialization vector for AES-256-GCM
   *         * encrypted data
   *         * authentication tag from AES-256-GCM for the data
   *         * encrypted nonce
   *         * authentication tag from AES-256-GCM for the data
   *     6. Return an EncryptionResult object
   *
   * @returns a Promise that resolves to an EncryptionResult
   */
  async encrypt(): Promise<EncryptionResult> {
    // 1. Generate a secret key (aka, data key)
    const dataKey = csprng(DATA_KEY_LENGTH_IN_BYTES);

    try {
      // 2. Encrypt (AES-256-GCM) plaintext data using data key
      const initializationVector = csprng(IV_LENGTH_IN_BYTES);
      const {ciphertext, authenticationTag: dataAuthenticationTag} = aes256gcmEncrypt(
        this._plaintext,
        dataKey,
        initializationVector,
      );

      // 3. Generate and encrypt a nonce used for data integrity checks.
      const nonce = csprng(NONCE_LENGTH_IN_BYTES);
      const {ciphertext: encryptedNonce, authenticationTag: nonceAuthenticationTag} =
        aes256gcmEncrypt(nonce, dataKey, initializationVector);

      // 4. Encrypt (RSA-OAEP-SHA1) data key with wrapper key (RSA public key)
      const encryptedDataKey = rsaOaepSha1Encrypt(dataKey, this._config.wrapperKey);

      // 6. Serialize the following components into a single buffer
      const serialized = this._serialize(
        ciphertext,
        encryptedDataKey,
        dataAuthenticationTag,
        initializationVector,
        this._config.wrapperKeyId,
        encryptedNonce,
        nonceAuthenticationTag,
      );

      // 7. Generate a content hash for (nonce || plaintext)
      const contentHash = sha256Hash(Buffer.concat([nonce, this._plaintext]));

      // 8. Return the encryption result
      return new EncryptionResult(serialized, this._config.wrapperKeyId, contentHash);
    } catch (error) {
      throw new CryptoError('Failed to encrypt plaintext', error);
    } finally {
      // Always clear the secret data key from memory
      dataKey.fill(0);
    }
  }
}

export class DecryptionResult {
  /**
   * Plaintext buffer
   * @internal
   */
  _plaintext: Buffer;

  /**
   * Constructor
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
  plaintext(): Buffer;
  plaintext(encoding: BufferEncoding): string;
  plaintext(encoding?: BufferEncoding) {
    if (encoding !== undefined) {
      return this._plaintext.toString(encoding);
    } else {
      return this._plaintext;
    }
  }
}

export class Decryption {
  /**
   * Wrapper key id buffer
   * @internal
   */
  _wrapperKeyId: Buffer;

  /**
   * Encrypted data key buffer
   * @internal
   */
  _encryptedDataKey: Buffer;

  /**
   * Initialization vector buffer
   * @internal
   */
  _initializationVector: Buffer;

  /**
   * Ciphertext buffer
   * @internal
   */
  _ciphertext: Buffer;

  /**
   * Authentication tag for the ciphertext.
   * @internal
   */
  _dataAuthenticationTag: Buffer;

  /**
   * Encrypted nonce buffer
   * @internal
   */
  _encryptedNonce: Buffer;

  /**
   * Authentication tag for the nonce.
   * @internal
   */
  _nonceAuthenticationTag: Buffer;

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
      dataAuthenticationTag,
      encryptedNonce,
      nonceAuthenticationTag,
    } = this._deserializeEncryptedData(serialized);

    if (cryptoVersion !== CryptoVersion.x0) {
      throw new CryptoError(
        `Invalid PrivyCrypto version for engine: expected ${CryptoVersion.x0} but got ${cryptoVersion}`,
      );
    } else if (initializationVector.length !== IV_LENGTH_IN_BYTES) {
      throw new CryptoError(
        `Invalid initialization vector length: expected ${IV_LENGTH_IN_BYTES} but got ${initializationVector.length}`,
      );
    } else if (dataAuthenticationTag.length !== AUTH_TAG_LENGTH_IN_BYTES) {
      throw new CryptoError(
        `Invalid data authentication tag length: expected ${AUTH_TAG_LENGTH_IN_BYTES} but got ${dataAuthenticationTag.length}`,
      );
    } else if (encryptedNonce.length > 0 && encryptedNonce.length !== NONCE_LENGTH_IN_BYTES) {
      throw new CryptoError(
        `Invalid nonce lengeth: expected ${NONCE_LENGTH_IN_BYTES} but got ${encryptedNonce.length}`,
      );
    } else if (
      nonceAuthenticationTag.length > 0 &&
      nonceAuthenticationTag.length !== AUTH_TAG_LENGTH_IN_BYTES
    ) {
      throw new CryptoError(
        `Invalid nonce authentication tag length: expected ${AUTH_TAG_LENGTH_IN_BYTES} but got ${nonceAuthenticationTag.length}`,
      );
    }

    this._wrapperKeyId = wrapperKeyId;
    this._encryptedDataKey = encryptedDataKey;
    this._initializationVector = initializationVector;
    this._ciphertext = ciphertext;
    this._dataAuthenticationTag = dataAuthenticationTag;
    this._encryptedNonce = encryptedNonce;
    this._nonceAuthenticationTag = nonceAuthenticationTag;
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

    // Read data authentication tag.
    const dataAuthenticationTag = serializedEncryptedData.slice(
      offset,
      offset + AUTH_TAG_LENGTH_IN_BYTES,
    );
    offset += AUTH_TAG_LENGTH_IN_BYTES;

    // Check if nonce is included (for backwards compatibility) and deserialize if so.
    let encryptedNonce = Buffer.alloc(0);
    let nonceAuthenticationTag = Buffer.alloc(0);
    if (offset < serializedEncryptedData.length) {
      // Read encrypted nonce.
      encryptedNonce = serializedEncryptedData.slice(offset, offset + NONCE_LENGTH_IN_BYTES);
      offset += NONCE_LENGTH_IN_BYTES;

      // Read nonce authentication tag.
      nonceAuthenticationTag = serializedEncryptedData.slice(
        offset,
        offset + AUTH_TAG_LENGTH_IN_BYTES,
      );
      offset += AUTH_TAG_LENGTH_IN_BYTES;
    }

    return {
      cryptoVersion: cryptoVersion,
      wrapperKeyId: wrapperKeyId,
      encryptedDataKey: encryptedDataKey,
      initializationVector: initializationVector,
      ciphertext: ciphertext,
      dataAuthenticationTag: dataAuthenticationTag,
      encryptedNonce: encryptedNonce,
      nonceAuthenticationTag: nonceAuthenticationTag,
    };
  }

  /**
   * Returns the wrapper key id.
   *
   * @param {BufferEncoding} [encoding] - Optional encoding which converts the wrapper key id to a string using the given encoding.
   */
  wrapperKeyId(): Buffer;
  wrapperKeyId(encoding: BufferEncoding): string;
  wrapperKeyId(encoding?: BufferEncoding) {
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
  encryptedDataKey(): Buffer;
  encryptedDataKey(encoding: BufferEncoding): string;
  encryptedDataKey(encoding?: BufferEncoding) {
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
   * @param {Buffer} contentHash - Optional contentHash used to perform optional data integrity check.
   * @returns DecryptionResult containing the plaintext data.
   */
  async decrypt(dataKey: Buffer, contentHash?: Buffer): Promise<DecryptionResult> {
    try {
      // Decrypt plaintext.
      const plaintext = aes256gcmDecrypt(
        this._ciphertext,
        dataKey,
        this._initializationVector,
        this._dataAuthenticationTag,
      );
      // If contentHash passed in, perform integrity check against the contentHash.
      if (contentHash) {
        // Decrypt nonce.
        const nonce = aes256gcmDecrypt(
          this._encryptedNonce,
          dataKey,
          this._initializationVector,
          this._nonceAuthenticationTag,
        );
        // Calculate hash.
        const hash = sha256Hash(Buffer.concat([nonce, plaintext]));
        if (!hash.equals(contentHash)) {
          throw new CryptoError(
            `Data integrity check failed: expected ${contentHash}, but got ${hash}`,
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
    } finally {
      // Always clear the secret data key from memory
      dataKey.fill(0);
    }
  }
}
