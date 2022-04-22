import md5 from 'md5';
import {CryptoEngine, CryptoVersion} from '@privy-io/crypto';
import {Http} from './http';
import {Session} from './sessions';
import {PRIVY_API_URL, PRIVY_KMS_URL, DEFAULT_TIMEOUT_MS} from './constants';
import {
  dataKeyPath,
  fileDownloadsPath,
  fileUploadsPath,
  integrityHashPath,
  userDataPath,
  wrapperKeyPath,
} from './paths';
import {wrap} from './utils';
import {
  DataKeyResponse,
  EncryptedUserDataResponse,
  EncryptedUserDataResponseValue,
  EncryptedUserDataRequestValue,
  FileMetadata,
  WrapperKeyResponse,
} from './types';
import {FieldInstance} from './fieldInstance';
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

interface PrivyOptions {
  session: Session;
  apiURL?: string;
  kmsURL?: string;
  timeout?: number;
}

export class PrivyClient {
  private api: Http;
  private kms: Http;

  constructor(options: PrivyOptions) {
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
   * Get user data from the Privy API.
   *
   * @param userId The id of the user this data belongs to.
   * @param fields Either a string field name or an array of string field names.
   * @returns Either a FieldInstance or null or list of FieldInstances or null depending on fields argument.
   */
  async get(userId: string, fields: string): Promise<FieldInstance | null>;
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
   * Put user data to the Privy API.
   *
   * @param userId The id of the user this data belongs to.
   * @param fields Either a field name as a string or an array of objects with field and value keys.
   * @param value If fields is a string for one field, then value is the value for the field.
   * @returns Either a FieldInstance or list of FieldInstances depending on fields argument.
   */
  async put(userId: string, fields: {field: string; value: string}[]): Promise<FieldInstance[]>;
  async put(userId: string, field: string, value: string): Promise<FieldInstance>;
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
        return new FieldInstance(field, plaintext, 'text/plain');
      });
      return typeof fields === 'string' ? result[0] : result;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Get a user's file from the Privy API.
   *
   * @param userId The id of the user this file belongs to.
   * @param field The field the file is stored under.
   * @returns A FieldInstance or null.
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
   * Put a user's file from the Privy API.
   *
   * @param userId The id of the user this file belongs to.
   * @param field The field to store the file in.
   * @param Blob The plaintext contents of the file in a Blob.
   * @returns A FieldInstance.
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

      return new FieldInstance(response.data.data[0], plaintext, blob.type);
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Reads and decrypts user data from Privy using the integrity hash.
   *
   * @param userId The id of the user.
   * @param integrityHash Hash used for content addressing.
   * @returns A Field
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
    data: EncryptedUserDataResponseValue[],
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
      decryption: new x0.Decryption(encoding.toBuffer(field.value, 'base64')),
    }));

    // Prepare and decrypt the data keys
    const keysToDecrypt = fieldsToDecrypt.map(({field, decryption}) => ({
      field_id: field.field_id,
      wrapper_key_id: encoding.toString(decryption.wrapperKeyId(), 'utf8'),
      encrypted_key: encoding.toString(decryption.encryptedDataKey(), 'base64'),
    }));
    const decryptedKeys = await this.decryptKeys(userId, keysToDecrypt);

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
      results[index] = new FieldInstance(field, plaintext, 'text/plain');
    }

    // Maintaining order, populate the result with the file field values
    for (const {index, field} of fileFieldsWithIndex) {
      results[index] = new FieldInstance(
        field,
        encoding.toBuffer(field.value, 'utf8'),
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

    const [dataKey] = await this.decryptKeys(userId, [keyToDecrypt]);
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

    const [dataKey] = await this.decryptKeys(field.user_id, [keyToDecrypt]);

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

  async decryptKeys(
    userId: string,
    keys: {field_id: string; wrapper_key_id: string; encrypted_key: string}[],
  ): Promise<Uint8Array[]> {
    if (keys.length === 0) {
      return [];
    }
    const path = dataKeyPath(userId);
    const response = await this.kms.post<DataKeyResponse>(path, {data: keys});
    return response.data.data.map(({key}) => encoding.toBuffer(key, 'base64'));
  }
}
