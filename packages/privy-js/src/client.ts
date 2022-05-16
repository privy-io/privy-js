import md5 from 'md5';
import {CryptoEngine, CryptoVersion} from '@privy-io/crypto';
import {Http} from './http';
import {Session} from './sessions';
import {PRIVY_API_URL, PRIVY_KMS_URL, DEFAULT_TIMEOUT_MS} from './constants';
import {
  batchDataKeyPath,
  BatchOptions,
  batchUserDataPath,
  dataKeyPath,
  fileDownloadsPath,
  fileUploadsPath,
  integrityHashPath,
  userDataPath,
  wrapperKeyPath,
} from './paths';
import {wrap} from './utils';
import {
  BatchEncryptedUserDataResponse,
  DataKeyUserResponse,
  EncryptedUserDataResponse,
  EncryptedUserDataResponseValue,
  EncryptedUserDataRequestValue,
  FileMetadata,
  WrapperKeyResponse,
  DataKeyUserRequest,
  DataKeyRequest,
  DataKeyBatchRequest,
  DataKeyBatchResponse,
  DataKeyResponseValue,
} from './types';
import {FieldInstance, UserFieldInstances} from './fieldInstance';
import {formatPrivyError, PrivyClientError} from './errors';
import encoding from './encoding';

// At the moment, there is only one version of
// Privy's crypto system, so this can be hardcoded.
// Once there are > 1 versions, this will need to be
// dynamic, at least for decryption.
const x0 = CryptoEngine(CryptoVersion.x0);

async function blobToUint8Array(blob: Blob): Promise<Uint8Array> {
  const arrayBuffer = await blob.arrayBuffer();
  return new Uint8Array(arrayBuffer);
}

/**
 * The Privy client performs operations against the Privy API.
 *
 * ```typescript
 * import {PrivyClient} from '@privy-io/privy-browser';
 * ```
 */
export class PrivyClient {
  private api: Http;
  private kms: Http;

  /**
   * Creates a new Privy client.
   * @param options Initialization options.
   */
  constructor(options: {
    /**
     * An object that implements the {@link Session} interface.
     */
    session: Session;
    /**
     * The URL of the Privy API. Defaults to `https://api.privy.io/v0`.
     */
    apiURL?: string;
    /**
     * The URL of the Privy KMS. Defaults to `https://kms.privy.io/v0`.
     */
    kmsURL?: string;
    /**
     * Time in milliseconds after which to timeout requests to the API and KMS. Defaults to `10000` (10 seconds).
     */
    timeout?: number;
  }) {
    options.session;

    const apiURL = options.apiURL || PRIVY_API_URL;
    const kmsURL = options.kmsURL || PRIVY_KMS_URL;
    const timeout = options.timeout || DEFAULT_TIMEOUT_MS;

    this.api = new Http(options.session, {
      baseURL: apiURL,
      timeout: timeout,
    });

    this.kms = new Http(options.session, {
      baseURL: kmsURL,
      timeout: timeout,
    });
  }

  /**
   * Get a single field of user data from the Privy API.
   *
   * ```typescript
   * const email = await client.get("0x123", "email");
   * ```
   *
   * @param userId The id of the user this data belongs to.
   * @param fields String field name.
   * @returns A {@link FieldInstance} if the field exists, or `null` otherwise.
   */
  async get(userId: string, fields: string): Promise<FieldInstance | null>;
  /**
   * Get multiple fields of user data from the Privy API.
   *
   * ```typescript
   * const [firstName, lastName] = await client.get("0x123", ["first-name", "last-name"]);
   * ```
   *
   * @param userId The id of the user this data belongs to.
   * @param fields Array of string field names.
   * @returns Array of results in the same order as the input. Each result is a {@link FieldInstance} if the field exists or `null` otherwise.
   */
  async get(userId: string, fields: string[]): Promise<Array<FieldInstance | null>>;
  async get(
    userId: string,
    fields: string | string[],
  ): Promise<(FieldInstance | null) | Array<FieldInstance | null>> {
    const path = userDataPath(userId, wrap(fields));

    try {
      const response = await this.api.get<EncryptedUserDataResponse>(path);
      const decrypted = await this.decrypt(userId, response.data.data);
      return typeof fields === 'string' ? decrypted[0] : decrypted;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Get user data for multiple users from the Privy API.
   *
   * @param fields: Array of string field names.
   * @param options Options for the batch to collect, i.e. an optional cursor and limit.
   */
  async getBatch(
    fields: string | string[],
    options: BatchOptions = {},
  ): Promise<Array<UserFieldInstances>> {
    const path = batchUserDataPath(wrap(fields), options);

    try {
      const response = await this.api.get<BatchEncryptedUserDataResponse>(path);
      const decrypted = await this.decryptBatch(wrap(fields), response.data);
      return decrypted;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Updates data for a single field for a given user.
   *
   * ```typescript
   * const email = await client.put("0x123", "email", "foo@example.com");
   * ```
   *
   * @param userId The id of the user this data belongs to.
   * @param field String field name.
   * @param value Value to save.
   * @returns {@link FieldInstance} of the updated field.
   */
  async put(userId: string, field: string, value: string): Promise<FieldInstance>;
  /**
   * Updates data for multiple fields for a given user.
   *
   * ```typescript
   * const [firstName, lastName] = await client.put("0x123", [
   *   {field: "first-name", value: "Jane"},
   *   {field: "last-name", value: "Doe"},
   * ]);
   * ```
   *
   * @param userId The id of the user this data belongs to.
   * @param fields Array of objects with `field` and `value` keys.
   * @returns Array of {@link FieldInstance}s of the updated fields, in the same order as the input.
   */
  async put(userId: string, fields: {field: string; value: string}[]): Promise<FieldInstance[]>;
  async put(
    userId: string,
    fields: string | {field: string; value: string}[],
    value?: string,
  ): Promise<FieldInstance | FieldInstance[]> {
    const data = typeof fields === 'string' ? [{field: fields, value: value!}] : fields;
    const path = userDataPath(userId);
    const encryptedData = await this.encrypt(userId, data);

    try {
      const response = await this.api.post<EncryptedUserDataResponse>(path, {data: encryptedData});
      const result = response.data.data.map((field, index) => {
        const plaintext = encoding.toBuffer(data[index].value, 'utf8');
        return new FieldInstance(field!, plaintext, 'text/plain');
      });
      return typeof fields === 'string' ? result[0] : result;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Download a file stored under a field.
   *
   * ```typescript
   * const avatar = await client.getFile("0x123", "avatar");
   * download(avatar);
   *
   * function download(field: FieldInstance) {
   *   const data = window.URL.createObjectURL(field.blob());
   *
   *   // Lookup extension by mime type (included on blob)
   *   const ext = getExtensionFromMIMEType(blob.type);
   *   const filename = `${field.integrity_hash}.${ext}`;
   *
   *   // Create a link pointing to the ObjectURL containing the blob.
   *   const link = document.createElement("a");
   *   link.style = "display: none;";
   *   link.href = data;
   *   link.download = filename;
   *   link.click();
   *
   *   // Cleanup
   *   window.URL.revokeObjectURL(data);
   *   link.remove();
   * }
   * ```
   *
   * @param userId The id of the user this file belongs to.
   * @param field The field the file is stored under.
   * @returns A {@link FieldInstance} if the file exists, or `null` otherwise.
   */
  async getFile(userId: string, field: string): Promise<FieldInstance | null> {
    const path = userDataPath(userId, [field]);

    try {
      const response = await this.api.get<EncryptedUserDataResponse>(path);
      const field = response.data.data[0];

      if (field === null) {
        return null;
      }

      if (field.object_type !== 'file') {
        throw new PrivyClientError(`${field.field_id} is not a file`);
      }

      const downloadResponse = await this.api.get<Blob>(
        fileDownloadsPath(field.user_id, field.field_id, field.value),
        {
          responseType: 'blob',
        },
      );

      const blob = downloadResponse.data;
      const contentType = downloadResponse.headers['privy-file-content-type'];
      const plaintext = await this.decryptFile(userId, field, blob);

      return new FieldInstance(field, plaintext, contentType);
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Upload a file for a given field.
   *
   * ```typescript
   * const onUpdateAvatar = async (avatar: File) => {
   *   try {
   *     await client.putFile("0x123", "avatar", avatar);
   *   } catch (error) {
   *     console.log(error);
   *   }
   * };
   * ```
   *
   * @param userId The id of the user this file belongs to.
   * @param field The field to store the file in.
   * @param blob The plaintext contents of the file in a Blob.
   * @returns {@link FieldInstance} for the uploaded file.
   */
  async putFile(userId: string, field: string, blob: Blob): Promise<FieldInstance> {
    try {
      const plaintext = await blobToUint8Array(blob);

      const {ciphertext, contentMD5, wrapperKeyId, integrityHash} = await this.encryptFile(
        userId,
        field,
        plaintext,
      );

      const formData = new FormData();
      formData.append('content_type', blob.type);
      formData.append('file_id', integrityHash);
      formData.append('content_md5', contentMD5);
      formData.append('wrapper_key_id', wrapperKeyId);
      formData.append('file', new Blob([ciphertext], {type: 'application/octet-stream'}));

      const uploadResponse = await this.api.post<FileMetadata>(
        fileUploadsPath(userId, field),
        formData,
        undefined,
      );

      const file = uploadResponse.data;

      const response = await this.api.post<EncryptedUserDataResponse>(userDataPath(userId), {
        data: [
          {
            field_id: field,
            object_type: 'file',
            value: file.id,
            integrity_hash: integrityHash,
          },
        ],
      });

      return new FieldInstance(response.data.data[0]!, plaintext, blob.type);
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Lookup a field instance by its integrity hash. This method can be used to verify data in addition to fetching it from Privy. For example, this method will:
   *
   * 1. Lookup data by integrity hash
   * 2. Return the field instance if it exists
   * 3. Re-compute the integrity hash client side. If it is NOT the same as the `integrityHash` argument, this method will throw an error.
   *
   * ```typescript
   * const ssn = await client.put("0x123", "ssn", "123-45-6789");
   * const ssnIntegrityHash = ssn.integrity_hash;
   *
   * // later on...
   * const ssn = await client.getByIntegrityHash(ssnIntegrityHash);
   * ```
   *
   * @param integrityHash Hash used for content addressing.
   * @returns The corresponding {@link FieldInstance} if it exists, or `null` otherwise.
   */
  async getByIntegrityHash(integrityHash: string): Promise<FieldInstance | null> {
    try {
      const path = integrityHashPath(integrityHash);
      const response = await this.api.get<EncryptedUserDataResponse>(path);
      const field = response.data.data[0];

      if (field === null) {
        return null;
      }

      if (field.object_type === 'string') {
        const ciphertext = encoding.toBuffer(field.value, 'base64');
        const plaintext = await this.decryptAndVerify(field, ciphertext, integrityHash);
        return new FieldInstance(field, plaintext, 'text/plain');
      } else {
        const downloadResponse = await this.api.get<Blob>(
          fileDownloadsPath(field.user_id, field.field_id, field.value),
          {
            responseType: 'blob',
          },
        );
        const blob = downloadResponse.data;
        const contentType = downloadResponse.headers['privy-file-content-type'];
        const ciphertext = await blobToUint8Array(blob);
        const plaintext = await this.decryptAndVerify(field, ciphertext, integrityHash);
        return new FieldInstance(field, plaintext, contentType);
      }
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  private async encrypt(
    userId: string,
    data: {field: string; value: string}[],
  ): Promise<EncryptedUserDataRequestValue[]> {
    const wrapperKeys = await this.getWrapperKeys(
      userId,
      data.map(({field}) => field),
      x0.WRAPPER_KEY_ALGORITHM,
    );

    const encryptionPromises = data.map(async ({field, value}, i) => {
      const wrapperKey = wrapperKeys[i];

      const privyEncryption = new x0.Encryption(encoding.toBuffer(value, 'utf8'), {
        wrapperKey: wrapperKey.publicKey,
        wrapperKeyId: wrapperKey.id,
      });

      const encryptedResult = await privyEncryption.encrypt();

      return {
        field_id: field,
        object_type: 'string',
        value: encoding.toString(encryptedResult.ciphertext(), 'base64'),
        wrapper_key_id: encoding.toString(encryptedResult.wrapperKeyId(), 'utf8'),
        integrity_hash: encoding.toString(encryptedResult.commitmentId(), 'hex'),
      } as EncryptedUserDataRequestValue;
    });

    return Promise.all(encryptionPromises);
  }

  private async decrypt(
    userId: string,
    data: (EncryptedUserDataResponseValue | null)[],
  ): Promise<Array<FieldInstance | null>> {
    const dataWithIndex = data.map((field, index) => ({index, field}));

    const nullFieldsWithIndex = dataWithIndex.filter(({field}) => {
      return field === null;
    });

    const stringFieldsWithIndex = dataWithIndex.filter(({field}) => {
      return field !== null && field.object_type === 'string';
    });

    const fileFieldsWithIndex = dataWithIndex.filter(({field}) => {
      return field !== null && field.object_type === 'file';
    });

    const fieldsToDecrypt = stringFieldsWithIndex.map(({field, index}) => ({
      field,
      index,
      decryption: new x0.Decryption(encoding.toBuffer(field!.value, 'base64')),
    }));

    // Prepare and decrypt the data keys
    const keysToDecrypt = fieldsToDecrypt.map(({field, decryption}) => ({
      field_id: field!.field_id,
      wrapper_key_id: encoding.toString(decryption.wrapperKeyId(), 'utf8'),
      encrypted_key: encoding.toString(decryption.encryptedDataKey(), 'base64'),
    }));
    const decryptedKeys = await this.decryptKeys({user_id: userId, data: keysToDecrypt});

    // Using the data keys from previous step, decrypt all fields in need of decryption
    const decryptedStringFields = await Promise.all(
      fieldsToDecrypt.map(async ({index, field, decryption}, i) => {
        const dataKey = decryptedKeys[i];
        const result = await decryption.decrypt(dataKey);
        return {index, field, plaintext: result.plaintext()};
      }),
    );

    // Prepare the result of this function
    const results = new Array<FieldInstance | null>(data.length);

    // Maintaining order, populate the result with the (decrypted) string field values
    for (const {index, field, plaintext} of decryptedStringFields) {
      results[index] = new FieldInstance(field!, plaintext, 'text/plain');
    }

    // Maintaining order, populate the result with the file field values
    for (const {index, field} of fileFieldsWithIndex) {
      results[index] = new FieldInstance(
        field!,
        encoding.toBuffer(field!.value, 'utf8'),
        'text/plain',
      );
    }

    // Maintaining order, populate the result with null fields
    for (const {index} of nullFieldsWithIndex) {
      results[index] = null;
    }

    return results;
  }

  private async encryptFile(userId: string, field: string, plaintext: Uint8Array) {
    const [wrapperKey] = await this.getWrapperKeys(userId, [field], x0.WRAPPER_KEY_ALGORITHM);

    const encryption = new x0.Encryption(plaintext, {
      wrapperKey: wrapperKey.publicKey,
      wrapperKeyId: wrapperKey.id,
    });

    const result = await encryption.encrypt();

    const ciphertext = result.ciphertext();
    const contentMD5 = md5(ciphertext);
    const wrapperKeyId = encoding.toString(result.wrapperKeyId(), 'utf8');
    const integrityHash = encoding.toString(result.commitmentId(), 'hex');

    return {
      ciphertext,
      contentMD5,
      wrapperKeyId,
      integrityHash,
    };
  }

  private async decryptFile(userId: string, field: EncryptedUserDataResponseValue, blob: Blob) {
    const uint8Array = await blobToUint8Array(blob);
    const decryption = new x0.Decryption(uint8Array);

    // Prepare and decrypt the data keys
    const keyToDecrypt = {
      field_id: field.field_id,
      wrapper_key_id: encoding.toString(decryption.wrapperKeyId(), 'utf8'),
      encrypted_key: encoding.toString(decryption.encryptedDataKey(), 'base64'),
    };

    const [dataKey] = await this.decryptKeys({user_id: userId, data: [keyToDecrypt]});
    const result = await decryption.decrypt(dataKey);

    return result.plaintext();
  }

  async decryptAndVerify(
    field: EncryptedUserDataResponseValue,
    ciphertext: Uint8Array,
    integrityHash: string,
  ) {
    const decryption = new x0.Decryption(ciphertext);

    const keyToDecrypt = {
      field_id: field.field_id,
      wrapper_key_id: encoding.toString(decryption.wrapperKeyId(), 'utf8'),
      encrypted_key: encoding.toString(decryption.encryptedDataKey(), 'base64'),
    };

    const [dataKey] = await this.decryptKeys({user_id: field.user_id, data: [keyToDecrypt]});

    const result = await decryption.decrypt(dataKey);

    if (!decryption.verify(result, encoding.toBuffer(integrityHash, 'hex'))) {
      throw new PrivyClientError(
        `Data integrity check failed for field ${field.field_id} using hash ${integrityHash}`,
      );
    }

    return result.plaintext();
  }

  async getWrapperKeys(userId: string, fields: string[], algorithm: string) {
    if (fields.length === 0) {
      return [];
    }
    const path = wrapperKeyPath(userId);

    const body = {
      algorithm,
      data: fields.map((field_id) => ({field_id})),
    };

    const response = await this.kms.post<WrapperKeyResponse>(path, body);

    return response.data.data.map(({id, public_key, algorithm}) => ({
      id: encoding.toBuffer(id, 'utf8'),
      publicKey: encoding.toBuffer(public_key, 'base64'),
      algorithm,
    }));
  }

  async decryptKeys(request: DataKeyUserRequest): Promise<Uint8Array[]> {
    if (request.data.length === 0) {
      return [];
    }
    const path = dataKeyPath(request.user_id);
    const response = await this.kms.post<DataKeyUserResponse>(path, request);
    return response.data.data.map(({key}) => encoding.toBuffer(key, 'base64'));
  }

  async decryptBatchKeys(request: DataKeyBatchRequest): Promise<(Uint8Array | null)[][]> {
    if (request.users.length === 0) {
      return new Array<Array<Uint8Array>>();
    }
    const path = batchDataKeyPath();
    const response = await this.kms.post<DataKeyBatchResponse>(path, request);
    const keyToBuffer = (value: DataKeyResponseValue) =>
      value.key === null ? null : encoding.toBuffer(value.key, 'base64');
    return response.data.users.map((userResponse) => userResponse.data.map(keyToBuffer));
  }

  private async decryptBatch(
    fieldIDs: string[],
    batchDataResponse: BatchEncryptedUserDataResponse,
  ): Promise<Array<UserFieldInstances>> {
    if (batchDataResponse.users.length === 0) {
      return [];
    }
    // Check that only string fields are requested. We don't handle files here.
    // Create decryption instances.
    const decryptionInstances = batchDataResponse.users.map((user) => {
      const fieldDecryptions = fieldIDs.map((_, fieldIdx) => {
        const field = user.data[fieldIdx];
        // Check that only non-files are attempted to be decrypted.
        if (field !== null && field.object_type === 'file') {
          throw new PrivyClientError('Batch decryption of files is not supported');
        }
        return field === null ? null : new x0.Decryption(encoding.toBuffer(field.value, 'base64'));
      });
      return fieldDecryptions;
    });

    // Get data keys.
    const dataKeyRequests: Array<DataKeyUserRequest> = batchDataResponse.users.map(
      (user, userIdx) => {
        const dataKeyRequests = fieldIDs.map((fieldID, fieldIdx) => {
          const decryption = decryptionInstances[userIdx][fieldIdx];
          return {
            field_id: fieldID,
            wrapper_key_id:
              decryption === null ? null : encoding.toString(decryption.wrapperKeyId(), 'utf8'),
            encrypted_key:
              decryption === null
                ? null
                : encoding.toString(decryption.encryptedDataKey(), 'base64'),
          };
        });
        return {user_id: user.user_id, data: dataKeyRequests};
      },
    );

    const decryptedKeys: (Uint8Array | null)[][] = await this.decryptBatchKeys({
      users: dataKeyRequests,
    });

    // Build decrypted field matrix.
    const decryptedFields: (Uint8Array | null)[][] = await Promise.all(
      batchDataResponse.users.map(async (_, userIdx): Promise<(Uint8Array | null)[]> => {
        return await Promise.all(
          fieldIDs.map(async (_, fieldIdx) => {
            const dataKey = decryptedKeys[userIdx][fieldIdx];
            if (dataKey === null) {
              return null;
            } else {
              const decryption = decryptionInstances[userIdx][fieldIdx];
              if (decryption === null) {
                return null;
              } else {
                const result = await decryption.decrypt(dataKey);
                return result.plaintext();
              }
            }
          }),
        );
      }),
    );

    // Collect results into userFieldInstances.
    const userIDs = batchDataResponse.users.map((user) => user.user_id);
    var userFieldInstances = new Array<UserFieldInstances>();
    userFieldInstances = userIDs.map((userID, userIdx) => {
      const fields = batchDataResponse.users[userIdx].data;
      const plaintext = decryptedFields[userIdx];
      const fieldInstances = fieldIDs.map((_, fieldIdx) => {
        if (fields[fieldIdx] === null || plaintext[fieldIdx] === null) {
          return null;
        } else {
          return new FieldInstance(fields[fieldIdx]!, plaintext[fieldIdx]!, 'text/plain');
        }
      });
      return {user_id: userID, field_instances: fieldInstances};
    });
    return userFieldInstances;
  }
}
