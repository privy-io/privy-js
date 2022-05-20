import crypto from 'crypto';
import {createAccessToken, createAccessTokenClaims, jwtKeyFromApiSecret} from './accessToken';
import {formatPrivyError, PrivyClientError} from './errors';
import {AccessTokenClaims, Field, FieldPermission, Group, Role} from './model/data';
import {
  AliasKeyRequest,
  AliasWrapperKeyRequest,
  AddUserToGroupRequest,
  CreateFieldRequest,
  CreateOrUpdateGroupRequest,
  CreateOrUpdateRoleRequest,
  UpdateFieldRequest,
  EncryptedAliasRequestValue,
} from './model/requests';
import encoding from './encoding';
import {mapPairs} from './utils';
import {CryptoEngine, CryptoVersion} from '@privy-io/crypto';
import {AliasKeyResponse, EncryptedAliasResponse, GroupUsersResponse} from './model/responses';
import {WrapperKeyResponseValue} from './types';
import {Http} from './http';
import {PRIVY_API_URL, PRIVY_KMS_URL, DEFAULT_TIMEOUT_MS} from './constants';

// At the moment, there is only one version of
// Privy's crypto system, so this can be hardcoded.
// Once there are > 1 versions, this will need to be
// dynamic, at least for decryption.
const x0 = CryptoEngine(CryptoVersion.x0);

// Endpoint routes.
const aliasPath = (userId: string) => `/users/${userId}/aliases`;
const deleteAliasPath = (userId: string, hashedAlias: string) =>
  `/users/${userId}/aliases/${hashedAlias}`;
const aliasWrapperKeyPath = () => `/key_manager/alias_wrapper_keys`;
const aliasKeyPath = () => `/key_manager/alias_keys`;
const fieldsPath = () => '/fields';
const fieldPath = (fieldId: string) => `/fields/${fieldId}`;
const fieldPermissionsPath = (fieldId: string) => `/permissions/fields/${fieldId}`;
const fieldPermissionsForGroupPath = (fieldId: string, groupId: string) =>
  `/permissions/fields/${fieldId}/groups/${groupId}`;
const rolesPath = () => '/roles';
const rolePath = (roleId: string) => `/roles/${roleId}`;
const groupsPath = () => '/groups';
const groupPath = (groupId: string) => `/groups/${groupId}`;
const groupUsersPath = (groupId: string) => `/groups/${groupId}/users`;
const groupUserPath = (groupId: string, userId: string) => `/groups/${groupId}/users/${userId}`;

// Data type to represent all id's that are aliased together.
type AliasBundle = {
  primary_user_id: string;
  aliases: string[];
};

export interface PrivyConfigOptions {
  /**
   * Overrides the Privy API.
   */
  apiRoute?: string;

  /**
   * Overrides the Privy KMS.
   */
  kmsRoute?: string;
  /**
   * Enable custom auth keys and disable automatic signing key generation.
   * Custom auth public keys can be registered with Privy via the console.
   */
  customAuthKey?: boolean;
  /**
   * Overrides the default Axios timeout of 10 seconds.
   */
  timeoutMs?: number;
}

export class PrivyConfig {
  /**
   * Privy API key.
   * @internal
   */
  private _apiKey: string;
  /**
   * Privy API secret.
   * @internal
   */
  private _apiSecret: string;
  /**
   * If true, do not enable access token issuance from auto-generated JWT signing keys.
   * This is a precaution, as any access tokens signed with auto-generated keys will not
   * work if an custom key override is entered via the console.
   * @internal
   */
  private _customAuthKey: boolean;
  /**
   * JWT signing key generated from the API secret.
   * @internal
   */
  private _signingKey: crypto.KeyObject;
  /**
   * Privy KMS route.
   * @internal
   */
  private _kmsRoute: string;
  /**
   * Instance of Axios HTTP client.
   * @internal
   */
  private _axiosInstance: Http;

  /**
   * Construct the Privy instance using a Privy API key pair and configuration options.
   */
  constructor(apiKey: string, apiSecret: string, config: PrivyConfigOptions = {}) {
    // Store the Privy API key pair.
    this._apiKey = apiKey;
    this._apiSecret = apiSecret;

    // Store the Privy KMS route.
    this._kmsRoute = config.kmsRoute || PRIVY_KMS_URL;

    this._customAuthKey = config.customAuthKey || false;
    this._signingKey = jwtKeyFromApiSecret(apiSecret);

    // Initialize the Axios HTTP client.
    this._axiosInstance = new Http(undefined, {
      baseURL: config.apiRoute || PRIVY_API_URL,
      timeout: config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      auth: {
        username: apiKey,
        password: apiSecret,
      },
    });
  }

  /**
   * Request alias wrapper keys from the Privy KMS.
   * @internal
   */
  private async _getAliasWrapperKey(
    algorithm: string,
  ): Promise<{id: Uint8Array; publicKey: Uint8Array; algorithm: string}> {
    const path = aliasWrapperKeyPath();
    const body: AliasWrapperKeyRequest = {
      algorithm,
    };
    const response = await this._axiosInstance.post<WrapperKeyResponseValue>(path, body, {
      baseURL: this._kmsRoute,
    });
    return {
      id: encoding.toBuffer(response.data.id, 'utf8'),
      publicKey: encoding.toBuffer(response.data.public_key, 'base64'),
      algorithm: response.data.algorithm,
    };
  }

  /**
   * Request alias keys from the Privy KMS
   * @internal
   */
  private async _getAliasKeys(
    keys: {
      wrapperKeyId: Uint8Array;
      encryptedKey: Uint8Array;
    }[],
  ): Promise<Uint8Array[]> {
    if (keys.length === 0) {
      return [];
    }
    const path = aliasKeyPath();
    const requestBody: AliasKeyRequest = {
      data: keys.map((key) => ({
        encrypted_key: encoding.toString(key.encryptedKey, 'base64'),
        alias_wrapper_key_id: encoding.toString(key.wrapperKeyId, 'utf8'),
      })),
    };
    const response = await this._axiosInstance.post<AliasKeyResponse>(path, requestBody, {
      baseURL: this._kmsRoute,
    });
    return response.data.data.map(({key}) => encoding.toBuffer(key, 'base64'));
  }

  private async _decryptAliases(encAliasResponse: EncryptedAliasResponse): Promise<AliasBundle> {
    if (encAliasResponse.encrypted_aliases.length === 0) {
      return {primary_user_id: encAliasResponse.primary_user_id, aliases: []};
    }
    // For each alias, create privyDecryption instance.
    const aliasDecryption: InstanceType<typeof x0.Decryption>[] =
      encAliasResponse.encrypted_aliases.map(
        (encAlias) => new x0.Decryption(encoding.toBuffer(encAlias.ciphertext, 'base64')),
      );

    // Get alias keys.
    const keys = aliasDecryption.map((decryption) => ({
      wrapperKeyId: decryption.wrapperKeyId(),
      encryptedKey: decryption.encryptedDataKey(),
    }));
    const aliasKeys = await this._getAliasKeys(keys);

    // Decrypt aliases.
    const aliases = await Promise.all(
      mapPairs(aliasKeys, aliasDecryption, async (aliasKey, privyDecryption) => {
        const decryptedResult = await privyDecryption.decrypt(aliasKey);
        return encoding.toString(decryptedResult.plaintext(), 'utf8');
      }),
    );

    return {primary_user_id: encAliasResponse.primary_user_id, aliases: aliases};
  }

  /**
   * Links a new user id alias to an pre-existing user id.
   * @param userId A user id for which data already exists.
   * @param alias A new user id to be linked to the pre-existing user id.
   * No data should previously exist for this new user id.
   * @returns AliasBundle containing the id's of all users that are linked together.
   */
  async link(userId: string, alias: string): Promise<AliasBundle> {
    try {
      // Get wrapper key for alias.
      const wrapperKey = await this._getAliasWrapperKey(x0.WRAPPER_KEY_ALGORITHM);
      const privyEncryption = new x0.Encryption(encoding.toBuffer(alias, 'utf8'), {
        wrapperKey: wrapperKey.publicKey,
        wrapperKeyId: wrapperKey.id,
      });
      const encryptedResult = await privyEncryption.encrypt();
      // Build alias request.
      const hash = crypto.createHash('sha256').update(alias, 'utf8').digest();
      const request: EncryptedAliasRequestValue = {
        ciphertext: encoding.toString(encryptedResult.ciphertext(), 'base64'),
        hash: hash.toString('hex'),
        alias_wrapper_key_id: encoding.toString(wrapperKey.id, 'utf8'),
      };
      // Send the encrypted alias to Privy.
      const response = await this._axiosInstance.post<EncryptedAliasResponse>(
        aliasPath(userId),
        request,
        undefined,
      );
      // Get response and decrypt.
      const encAliasResponse: EncryptedAliasResponse = response.data;
      return this._decryptAliases(encAliasResponse);
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Delinks a particular user id alias from any other user id's it's linked to. If
   * it is not linked to any other user id, an error is thrown.
   * @param userId A user id that the alias is initially linked to.
   * @param alias The user id to be delinked from the bundle.
   * @returns AliasBundle if everything succeeds. Otherwise an error is thrown.
   */
  async delink(userId: string, alias: string): Promise<void> {
    try {
      // Get hash of alias.
      // TODO(dave): Technically just using the hash leaks some info about the alias, in the sense
      // that an informed attacker could confirm whether two user ids / wallet addresses are linked from the url.
      // For the purposes of piloting, we can start with this and change later.
      const hashedAlias = crypto.createHash('sha256').update(alias, 'utf8').digest();
      await this._axiosInstance.delete<EncryptedAliasResponse>(
        deleteAliasPath(userId, encoding.toString(hashedAlias, 'hex')),
        undefined,
      );
      return;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Reads and decrypts the aliases a given user id is linked to.
   * @param userId Any user id within the alias bundle.
   * @returns AliasBundle if everything succeeds. Otherwise an error is thrown.
   */
  async fetchAliases(userId: string): Promise<AliasBundle> {
    try {
      const response = await this._axiosInstance.get<EncryptedAliasResponse>(
        aliasPath(userId),
        undefined,
      );
      // Get response and decrypt.
      const encAliasResponse: EncryptedAliasResponse = response.data;
      return this._decryptAliases(encAliasResponse);
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Generate a Privy access token for the given data requester.
   * @param requesterId Data requester user ID.
   * @param roles Roles the data requester should have with the access token.
   */
  async createAccessToken(requesterId: string, roles: string[]): Promise<string> {
    if (this._customAuthKey) {
      throw new PrivyClientError(
        '`createAccessToken` is disabled because this client is configured with custom ' +
          'signing keys. Please use `createAccessTokenClaims` instead and sign the claims ' +
          'with the custom signing key.',
      );
    }
    return createAccessToken(this._signingKey, this._apiKey, requesterId, roles);
  }

  /**
   * Generate Privy access token claims for the given data requester.
   * These claims can be signed as a JWT to obtain a Privy data access token.
   * @param requesterId Data requester user ID.
   * @param roles Roles the data requester should have with the access token.
   */
  createAccessTokenClaims(requesterId: string, roles: string[]): AccessTokenClaims {
    return createAccessTokenClaims(this._apiKey, requesterId, roles);
  }

  /**
   * List all fields.
   */
  async listFields(): Promise<Field[]> {
    try {
      const response = await this._axiosInstance.get<Field[]>(fieldsPath());
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Create a field.
   * @param name Unique name for the field.
   * @param description Arbitrary string attached to the field.
   * @param permissions The set of permissions on the field.
   */
  async createField(
    name: string,
    description: string,
    permissions: FieldPermission[],
  ): Promise<Field> {
    const request: CreateFieldRequest = {
      name,
      description,
      permissions,
    };
    try {
      const response = await this._axiosInstance.post<Field>(fieldsPath(), request);
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Retrieve a field.
   * @param fieldId Unique alphanumeric identifier for the field.
   */
  async getField(fieldId: string): Promise<Field> {
    try {
      const response = await this._axiosInstance.get<Field>(fieldPath(fieldId));
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Update a field.
   * @param fieldId Unique alphanumeric identifier for the field.
   * @param name Unique name for the field.
   * @param description Arbitrary string attached to the field.
   */
  async updateField(fieldId: string, name: string, description: string): Promise<Field> {
    const request: UpdateFieldRequest = {
      name,
      description,
    };
    try {
      const response = await this._axiosInstance.post<Field>(fieldPath(fieldId), request);
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Delete a field.
   * @param fieldId Unique alphanumeric identifier for the field.
   */
  async deleteField(fieldId: string): Promise<void> {
    try {
      await this._axiosInstance.delete(fieldPath(fieldId));
      return;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Get permissions for a field.
   * @param fieldId Unique alphanumeric identifier for the field.
   */
  async getFieldPermissions(fieldId: string): Promise<FieldPermission[]> {
    try {
      const response = await this._axiosInstance.get<FieldPermission[]>(
        fieldPermissionsPath(fieldId),
      );
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Update permissions for a field.
   * @param fieldId Unique alphanumeric identifier for the field.
   * @param permissions New permissions for the field.
   */
  async updateFieldPermissions(
    fieldId: string,
    permissions: FieldPermission[],
  ): Promise<FieldPermission[]> {
    try {
      const response = await this._axiosInstance.post<FieldPermission[]>(
        fieldPermissionsPath(fieldId),
        permissions,
      );
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Delete permissions for a field.
   * @param fieldId Unique alphanumeric identifier for the field.
   */
  async deleteFieldPermissions(fieldId: string): Promise<FieldPermission[]> {
    try {
      const response = await this._axiosInstance.delete<FieldPermission[]>(
        fieldPermissionsPath(fieldId),
      );
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Get permissions for a field and a group.
   * @param fieldId Unique alphanumeric identifier for the field.
   * @param groupId Unique alphanumeric identifier for the group.
   */
  async getFieldPermissionForGroup(fieldId: string, groupId: string): Promise<FieldPermission> {
    try {
      const response = await this._axiosInstance.get<FieldPermission>(
        fieldPermissionsForGroupPath(fieldId, groupId),
      );
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Set permissions for a field and a group.
   * @param fieldId Unique alphanumeric identifier for the field.
   * @param groupId Unique alphanumeric identifier for the group.
   * @param permission New permission for the field and group.
   */
  async setFieldPermissionForGroup(
    fieldId: string,
    groupId: string,
    permission: Omit<FieldPermission, 'group_id'>,
  ): Promise<FieldPermission> {
    try {
      const response = await this._axiosInstance.post<FieldPermission>(
        fieldPermissionsForGroupPath(fieldId, groupId),
        permission,
      );
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Delete permissions for a field and a group.
   * @param fieldId Unique alphanumeric identifier for the field.
   * @param groupId Unique alphanumeric identifier for the group.
   */
  async deleteFieldPermissionForGroup(fieldId: string, groupId: string): Promise<void> {
    try {
      await this._axiosInstance.delete(fieldPermissionsForGroupPath(fieldId, groupId));
      return;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * List all roles.
   * Retrieves all the defined roles for this account.
   */
  async listRoles(): Promise<Role[]> {
    try {
      const response = await this._axiosInstance.get<Role[]>(rolesPath());
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Create a role.
   * @param name Unique name for the role.
   * @param description Arbitrary string attached to the role.
   */
  async createRole(name: string, description: string): Promise<Role> {
    const request: CreateOrUpdateRoleRequest = {
      name,
      description,
    };
    try {
      const response = await this._axiosInstance.post<Role>(rolesPath(), request);
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Retrieve a role.
   * @param roleId Unique alphanumeric identifier for the role.
   */
  async getRole(roleId: string): Promise<Role> {
    try {
      const response = await this._axiosInstance.get<Role>(rolePath(roleId));
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Update a role.
   * Default roles cannot be updated.
   * @param roleId Unique alphanumeric identifier for the role.
   * @param name Unique name for the role.
   * @param description Arbitrary string attached to the role.
   */
  async updateRole(roleId: string, name: string, description: string): Promise<Role> {
    const request: CreateOrUpdateRoleRequest = {
      name,
      description,
    };
    try {
      const response = await this._axiosInstance.post<Role>(rolePath(roleId), request);
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Delete a role.
   * Default roles cannot be deleted.
   * @param roleId Unique alphanumeric identifier for the role.
   */
  async deleteRole(roleId: string): Promise<void> {
    try {
      await this._axiosInstance.delete(rolePath(roleId));
      return;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * List all groups.
   * Retrieves all the defined groups for this account.
   */
  async listGroups(): Promise<Group[]> {
    try {
      const response = await this._axiosInstance.get<Group[]>(groupsPath());
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Create a group.
   * @param name Unique name for the group.
   * @param description Arbitrary string attached to the group.
   */
  async createGroup(name: string, description: string): Promise<Group> {
    const request: CreateOrUpdateGroupRequest = {
      name,
      description,
    };
    try {
      const response = await this._axiosInstance.post<Group>(groupsPath(), request);
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Retrieve a group.
   * @param groupId Unique alphanumeric identifier for the group.
   */
  async getGroup(groupId: string): Promise<Group> {
    try {
      const response = await this._axiosInstance.get<Group>(groupPath(groupId));
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Update a group.
   * Default groups cannot be updated.
   * @param groupId Unique alphanumeric identifier for the group.
   * @param name Unique name for the group.
   * @param description Arbitrary string attached to the group.
   */
  async updateGroup(groupId: string, name: string, description: string): Promise<Group> {
    const request: CreateOrUpdateGroupRequest = {
      name,
      description,
    };
    try {
      const response = await this._axiosInstance.post<Group>(groupPath(groupId), request);
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Delete a group.
   * Default groups cannot be deleted.
   * @param groupId Unique alphanumeric identifier for the group.
   */
  async deleteGroup(groupId: string): Promise<void> {
    try {
      await this._axiosInstance.delete(groupPath(groupId));
      return;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Get the users in a group.
   * @param groupId Unique alphanumeric identifier for the group.
   */
  async listUsersInGroup(groupId: string): Promise<string[]> {
    try {
      const response = await this._axiosInstance.get<GroupUsersResponse>(groupUsersPath(groupId));
      return response.data.user_ids;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Add a user to a group.
   * @param groupId Unique alphanumeric identifier for the group.
   * @param userId Unique alphanumeric identifier for the user.
   */
  async addUserToGroup(groupId: string, userId: string): Promise<void> {
    try {
      const request: AddUserToGroupRequest = {
        user_id: userId,
      };
      await this._axiosInstance.post<GroupUsersResponse>(groupUsersPath(groupId), request);
      return;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Delete a user from a group.
   * @param groupId Unique alphanumeric identifier for the group.
   * @param userId Unique alphanumeric identifier for the user.
   */
  async removeUserFromGroup(groupId: string, userId: string): Promise<void> {
    try {
      await this._axiosInstance.delete(groupUserPath(groupId, userId));
      return;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }
}
