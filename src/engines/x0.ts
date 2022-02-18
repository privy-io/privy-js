import {
  CryptoVersion,
  cryptoVersionToBuffer,
  cryptoVersionFromBuffer,
  CRYPTO_VERSION_LENGTH_IN_BYTES,
} from '../version';
import {CryptoError} from '../errors';
import {bufferFromUInt64, concatBuffers, uint64FromBuffer} from '../buffers';
import {
  aesGCMEncrypt,
  aesGCMDecrypt,
  csprng,
  generateAESGCMEncryptionKey,
  importRSAOAEPEncryptionKey,
  rsaOaepEncrypt,
  generateAESGCMInitializationVector,
} from '../crypto';

// NIST recommended lengths
const IV_LENGTH_IN_BYTES = 12;
const AUTH_TAG_LENGTH_IN_BYTES = 16;

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
   * Constructor
   * @internal
   */
  constructor(ciphertext: Uint8Array, wrapperKeyId: Uint8Array) {
    this._ciphertext = ciphertext;
    this._wrapperKeyId = wrapperKeyId;
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
}

export interface EncryptConfig {
  // The wrapper key (RSA public key in PEM format).
  wrapperKey: string;

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
   *   * wrapperKey - (Buffer) The wrapper key (RSA public key in PEM format).
   *   * wrapperKeyId - (Buffer) The metadata ID of the RSA public key.
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
    ciphertext: Uint8Array,
    encryptedDataKey: Uint8Array,
    initializationVector: Uint8Array,
    wrapperKeyId: Uint8Array,
  ): Uint8Array {
    return concatBuffers(
      cryptoVersionToBuffer(CryptoVersion.x0),
      bufferFromUInt64(wrapperKeyId.byteLength),
      wrapperKeyId,
      bufferFromUInt64(encryptedDataKey.byteLength),
      encryptedDataKey,
      initializationVector,
      bufferFromUInt64(ciphertext.byteLength - AUTH_TAG_LENGTH_IN_BYTES),
      ciphertext,
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
    try {
      // 1. Generate a single-use secret key (aka, data key) and initialization vector
      const dataKey = await generateAESGCMEncryptionKey();
      const initializationVector = generateAESGCMInitializationVector();

      // 2. Encrypt (AES-256-GCM) plaintext data using data key
      const ciphertext = await aesGCMEncrypt(this._plaintext, initializationVector, dataKey);

      // 3. Encrypt (RSA-OAEP-SHA1) data key with wrapper key (RSA public key)
      const wrapperKeyTypedArray = new TextEncoder().encode(this._config.wrapperKey);
      const wrapperKey = await importRSAOAEPEncryptionKey(wrapperKeyTypedArray);
      const dataKeyArrayBuffer = await crypto.subtle.exportKey('raw', dataKey);
      const encryptedDataKey = await rsaOaepEncrypt(dataKeyArrayBuffer, wrapperKey);

      // 4. Serialize the following components into a single buffer
      const serialized = this._serialize(
        ciphertext,
        encryptedDataKey,
        initializationVector,
        this._config.wrapperKeyId,
      );

      // 5. Return the encryption result
      return new EncryptionResult(serialized, this._config.wrapperKeyId);
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
   * Initialization vector buffer
   * @internal
   */
  _initializationVector: Uint8Array;

  /**
   * Ciphertext buffer
   * @internal
   */
  _ciphertext: Uint8Array;

  /**
   * Authentication tag buffer
   * @internal
   */
  _authenticationTag: Uint8Array;

  /**
   * Instantiates a new Decryption instance.
   *
   * @param serialized - The serialized encrypted data to decrypt.
   */
  constructor(serialized: Uint8Array) {
    const {
      cryptoVersion,
      wrapperKeyId,
      encryptedDataKey,
      initializationVector,
      ciphertext,
      authenticationTag,
    } = this._deserializeEncryptedData(serialized);

    if (cryptoVersion !== CryptoVersion.x0) {
      throw new CryptoError(
        `Invalid PrivyCrypto version for engine: expected ${CryptoVersion.x0} but got ${cryptoVersion}`,
      );
    } else if (initializationVector.length !== IV_LENGTH_IN_BYTES) {
      throw new CryptoError(
        `Invalid initialization vector length: expected ${IV_LENGTH_IN_BYTES} but got ${initializationVector.length}`,
      );
    } else if (authenticationTag.length !== AUTH_TAG_LENGTH_IN_BYTES) {
      throw new CryptoError(
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
   * @param {Buffer} dataKey - The secret key used to encrypt the data.
   * @returns DecryptionResult containing the plaintext data
   */
  async decrypt(dataKey: Uint8Array): Promise<DecryptionResult> {
    try {
      const plaintext = aes256gcmDecrypt(
        this._ciphertext,
        dataKey,
        this._initializationVector,
        this._authenticationTag,
      );

      return new DecryptionResult(plaintext);
    } catch (error) {
      throw new CryptoError('Failed to decrypt the encrypted data', error);
    } finally {
      // Always clear the secret data key from memory
      dataKey.fill(0);
    }
  }
}
