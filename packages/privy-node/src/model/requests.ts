export interface AccessTokenRequest {
  requester_id: string;
  roles: string[];
}

export interface CreateFieldRequest {
  name: string;
  description?: string;
  default_access_group?: string;
}

export interface UpdateFieldRequest {
  name?: string;
  description?: string;
  default_access_group?: string;
}

export interface CreateOrUpdateRoleRequest {
  name: string;
  description: string;
}

export interface CreateAccessGroupRequest {
  name: string;
  description?: string;
  read_roles?: string[];
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
