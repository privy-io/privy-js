import crypto from 'crypto';
import {createAccessTokenClaims, jwtKeyFromApiSecret, signAccessToken} from './accessToken';
import {formatPrivyError} from './errors';
import {AccessGroup, AccessTokenClaims, Field, Role, UserPermission} from './model/data';
import {
  AliasKeyRequest,
  AliasWrapperKeyRequest,
  CreateFieldRequest,
  UpdateRoleRequest,
  CreateRoleRequest,
  CreateAccessGroupRequest,
  UpdateFieldRequest,
  UpdateAccessGroupRequest,
  EncryptedAliasRequestValue,
} from './model/requests';
import {wrapAsBuffer} from './encoding';
import {mapPairs} from './utils';
import {CryptoEngine, CryptoVersion} from '@privy-io/crypto';
import {AliasKeyResponse, EncryptedAliasResponse} from './model/responses';
import {WrapperKeyResponseValue} from './types';
import {Http} from './http';

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
const rolesPath = () => '/roles';
const rolePath = (roleId: string) => `/roles/${roleId}`;
const accessGroupsPath = () => '/access_groups';
const accessGroupPath = (accessGroupId: string) => `/access_groups/${accessGroupId}`;
const userPermissionsPath = (userId: string, fieldIds?: string[]) => {
  if (Array.isArray(fieldIds)) {
    return `/users/${userId}/permissions?field_ids=${fieldIds.join(',')}`;
  } else {
    return `/users/${userId}/permissions`;
  }
};
const requesterRolesPath = (requesterId: string) => `/requesters/${requesterId}/roles`;
const roleRequestersPath = (roleId: string) => `/roles/${roleId}/requesters`;
const roleRequesterPath = (roleId: string, requesterId: string) =>
  `/roles/${roleId}/requesters/${requesterId}`;

// Data type to represent all id's that are aliased together.
type AliasBundle = {
  primary_user_id: string;
  aliases: string[];
};

export type SigningFn = (claims: AccessTokenClaims) => Promise<string>;

const createApiSecretSigningFn = (apiSecret: string): SigningFn => {
  const jwtKey = jwtKeyFromApiSecret(apiSecret);
  return (claims: AccessTokenClaims) => signAccessToken(jwtKey, claims);
};

export class PrivyConfig {
  /**
   * Privy API key.
   * @internal
   */
  private _apiKey: string;
  /**
   * JWT signing function.
   * @internal
   */
  private _signingFn: SigningFn;
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
   * @internal
   */
  protected constructor(
    apiKey: string,
    apiSecret: string,
    config: {
      apiURL: string;
      kmsURL: string;
      timeout: number;
      customSigningFn?: SigningFn;
    },
  ) {
    this._apiKey = apiKey;

    // Store the Privy KMS route.
    this._kmsRoute = config.kmsURL;

    // Use custom signing key if provided, otherwise generate it from the API secret.
    this._signingFn = config.customSigningFn ?? createApiSecretSigningFn(apiSecret);

    // Initialize the Axios HTTP client.
    this._axiosInstance = new Http(undefined, {
      baseURL: config.apiURL,
      timeout: config.timeout,
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
      id: Buffer.from(response.data.id, 'utf8'),
      publicKey: Buffer.from(response.data.public_key, 'base64'),
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
        encrypted_key: wrapAsBuffer(key.encryptedKey).toString('base64'),
        alias_wrapper_key_id: wrapAsBuffer(key.wrapperKeyId).toString('utf8'),
      })),
    };
    const response = await this._axiosInstance.post<AliasKeyResponse>(path, requestBody, {
      baseURL: this._kmsRoute,
    });
    return response.data.data.map(({key}) => Buffer.from(key, 'base64'));
  }

  /**
   * @internal
   */
  private async _decryptAliases(encAliasResponse: EncryptedAliasResponse): Promise<AliasBundle> {
    if (encAliasResponse.encrypted_aliases.length === 0) {
      return {primary_user_id: encAliasResponse.primary_user_id, aliases: []};
    }
    // For each alias, create privyDecryption instance.
    const aliasDecryption: InstanceType<typeof x0.Decryption>[] =
      encAliasResponse.encrypted_aliases.map(
        (encAlias) => new x0.Decryption(Buffer.from(encAlias.ciphertext, 'base64')),
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
        return Buffer.from(decryptedResult.plaintext()).toString('utf8');
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
      const privyEncryption = new x0.Encryption(Buffer.from(alias, 'utf8'), {
        wrapperKey: wrapperKey.publicKey,
        wrapperKeyId: wrapperKey.id,
      });
      const encryptedResult = await privyEncryption.encrypt();
      // Build alias request.
      const hash = crypto.createHash('sha256').update(alias, 'utf8').digest();
      const request: EncryptedAliasRequestValue = {
        ciphertext: Buffer.from(encryptedResult.ciphertext()).toString('base64'),
        hash: hash.toString('hex'),
        alias_wrapper_key_id: Buffer.from(wrapperKey.id).toString('utf8'),
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
        deleteAliasPath(userId, Buffer.from(hashedAlias).toString('hex')),
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
   */
  async createAccessToken(requesterId: string): Promise<string> {
    const claims = createAccessTokenClaims(this._apiKey, requesterId);
    return this._signingFn(claims);
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
   * @param attributes
   * @param attributes.name The field name of which the field id is derived.
   * @param attributes.description Description of the field's purpose.
   * @param attributes.default_access_group The default access group for this field.
   */
  async createField(attributes: CreateFieldRequest): Promise<Field> {
    try {
      const response = await this._axiosInstance.post<Field>(fieldsPath(), attributes);
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
   * @param attributes
   * @param attributes.name The field name of which the field id is derived.
   * @param attributes.description Description of the field's purpose.
   * @param attributes.default_access_group The default access group for this field.
   */
  async updateField(fieldId: string, attributes: UpdateFieldRequest): Promise<Field> {
    try {
      const response = await this._axiosInstance.post<Field>(fieldPath(fieldId), attributes);
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
   * @param attributes
   * @param attributes.name Unique name for the role.
   * @param attributes.description Arbitrary string attached to the role.
   */
  async createRole(attributes: CreateRoleRequest): Promise<Role> {
    try {
      const response = await this._axiosInstance.post<Role>(rolesPath(), attributes);
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
   * @param attributes
   * @param attributes.name Unique name for the role.
   * @param attributes.description Arbitrary string attached to the role.
   */
  async updateRole(roleId: string, attributes: UpdateRoleRequest): Promise<Role> {
    try {
      const response = await this._axiosInstance.post<Role>(rolePath(roleId), attributes);
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
   * List all access groups.
   * Retrieves all the defined access groups for this account.
   */
  async listAccessGroups(): Promise<AccessGroup[]> {
    try {
      const response = await this._axiosInstance.get<AccessGroup[]>(accessGroupsPath());
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Create an access group.
   * @param attributes
   * @param attributes.name The access group name of which the access group id is derived.
   * @param attributes.description Description of the access group's purpose.
   * @param attributes.read_roles List of role ids that have READ permission in this group.
   * @param attributes.write_roles List of role ids that have WRITE permission in this group.
   */
  async createAccessGroup(attributes: CreateAccessGroupRequest): Promise<AccessGroup> {
    try {
      const response = await this._axiosInstance.post<AccessGroup>(accessGroupsPath(), attributes);
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Retrieve an access group.
   * @param accessGroupId The id of the access group.
   */
  async getAccessGroup(accessGroupId: string): Promise<AccessGroup> {
    try {
      const response = await this._axiosInstance.get<AccessGroup>(accessGroupPath(accessGroupId));
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Update an access group.
   * Default access groups cannot be updated.
   * @param accessGroupId The id of the access group.
   * @param attributes
   * @param attributes.name The access group name of which the access group id is derived.
   * @param attributes.description Description of the access group's purpose.
   * @param attributes.read_roles List of role ids that have READ permission in this group.
   * @param attributes.write_roles List of role ids that have WRITE permission in this group.
   */
  async updateAccessGroup(
    accessGroupId: string,
    attributes: UpdateAccessGroupRequest,
  ): Promise<AccessGroup> {
    try {
      const response = await this._axiosInstance.post<AccessGroup>(
        accessGroupPath(accessGroupId),
        attributes,
      );
      return response.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Delete an access group
   * Default access groups cannot be deleted.
   * @param accessGroupId The id of the access group.
   */
  async deleteAccessGroup(accessGroupId: string): Promise<void> {
    try {
      await this._axiosInstance.delete(accessGroupPath(accessGroupId));
      return;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Get the permissions required for accessing a given user's data.
   * @param userId The id of the user to fetch permissions for.
   * @param fieldIds Optional list of field ids to scope the request to.
   */
  async getUserPermissions(userId: string, fieldIds?: string[]): Promise<UserPermission[]> {
    try {
      const response = await this._axiosInstance.get<{data: UserPermission[]}>(
        userPermissionsPath(userId, fieldIds),
      );
      return response.data.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Update the permissions required for accessing a given user's data.
   * @param userId The id of the user to fetch permissions for.
   * @param permissions A list of permissions objects.
   */
  async updateUserPermissions(
    userId: string,
    permissions: UserPermission[],
  ): Promise<UserPermission[]> {
    try {
      const response = await this._axiosInstance.post<{data: UserPermission[]}>(
        userPermissionsPath(userId),
        {data: permissions},
      );
      return response.data.data;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Get all the roles assigned to the requester.
   * @param requesterId The id of the requester.
   */
  async getRequesterRoles(requesterId: string): Promise<string[]> {
    try {
      const response = await this._axiosInstance.get<{role_ids: string[]}>(
        requesterRolesPath(requesterId),
      );
      return response.data.role_ids;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Get all the requesters assigned to the given role id.
   * @param roleId The id of the role.
   */
  async getRoleRequesters(roleId: string): Promise<string[]> {
    try {
      const response = await this._axiosInstance.get<{requester_ids: string[]}>(
        roleRequestersPath(roleId),
      );
      return response.data.requester_ids;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Assign the given role to a list of requesters.
   * @param roleId The id of the role.
   * @param requesterIds A list of requester ids to assign the role.
   */
  async addRequestersToRole(roleId: string, requesterIds: string[]): Promise<string[]> {
    try {
      const response = await this._axiosInstance.post<{added_requester_ids: string[]}>(
        roleRequestersPath(roleId),
        {requester_ids: requesterIds},
      );
      return response.data.added_requester_ids;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }

  /**
   * Remove the requester from the given role.
   * @param roleId The id of the role.
   * @param requesterId The requester to remove from the role.
   */
  async removeRequesterFromRole(roleId: string, requesterId: string): Promise<void> {
    try {
      await this._axiosInstance.delete(roleRequesterPath(roleId, requesterId));
      return;
    } catch (error) {
      throw formatPrivyError(error);
    }
  }
}

