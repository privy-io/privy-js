export interface AccessTokenRequest {
  requester_id: string;
  roles: string[];
}

/** 
  * The required attributes of a field
  */
export interface CreateFieldRequest {
  /**
   * Unique alphanumeric identifier for the field.
   */
  name: string;
  /**
   * Descriptiong of field purpose
   */
  description?: string;
  /**
   * Access group id given default access to all instances of this data
   */
  default_access_group?: string;
}

export interface UpdateFieldRequest {
  name?: string;
  description?: string;
  default_access_group?: string;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
}

/** 
 * The required attributes of an access group
 */
export interface CreateAccessGroupRequest {
  /** 
   * The access group name of which the access group id is derived.
   */
  name: string;
  /** 
   * Description of the access group's purpose.
   */
  description?: string;
  /** 
   * List of role ids that have READ permission in this group.
   */
  read_roles?: string[];
  /** 
   * List of role ids that have WRITE permission in this group.
   */
  write_roles?: string[];
}

export interface UpdateAccessGroupRequest {
  name?: string;
  description?: string;
  read_roles?: string[];
  write_roles?: string[];
}

export interface AliasKeyRequestValue {
  // Encrypted key, base64 encoded.
  encrypted_key: string;
  // Alias wrapper key id, utf8 encoded.
  alias_wrapper_key_id: string;
}

export interface AliasKeyRequest {
  data: AliasKeyRequestValue[];
}

export interface AliasWrapperKeyRequest {
  algorithm: string;
}

// EncryptedAliasRequestValue is the value we POST
// to the API when linking an new alias.
export interface EncryptedAliasRequestValue {
  // Ciphertext, base64 encoded.
  ciphertext: string;
  // Hash, utf8 encoded.
  hash: string;
  // Wrapper key id, utf8 encoded.
  alias_wrapper_key_id: string;
}
