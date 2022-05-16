export interface GroupUsersResponse {
  group_id: string;
  user_ids: string[];
}

export interface AliasKeyResponseValue {
  key: string; // Alias key as base64 string.
}

export interface AliasKeyResponse {
  data: AliasKeyResponseValue[];
}

// EncryptedAliasResponse and EncryptedAliasResponseValue
// are the types for the alias API response objects.
export interface EncryptedAliasResponseValue {
  ciphertext: string;
  hash: string;
  created_at: number;
}

export interface EncryptedAliasResponse {
  primary_user_id: string;
  encrypted_aliases: EncryptedAliasResponseValue[];
}
