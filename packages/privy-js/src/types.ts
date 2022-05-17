export interface EncryptedUserDataResponseValue {
  user_id: string;
  field_id: string;
  object_type: 'string' | 'file';
  value: string;
  integrity_hash: string;
  created_at: number;
}

export interface EncryptedUserDataResponse {
  user_id: string;
  data: (EncryptedUserDataResponseValue | null)[];
}

// BatchEncryptedUserDataResponse is densely populated i.e. it contains an entry for every user
// and field, even if the field has no data.
export interface BatchEncryptedUserDataResponse {
  users: EncryptedUserDataResponse[];
}

export interface DataKeyResponseValue {
  key: string; // Data key as base64 string.
}

export interface DataKeyUserResponse {
  user_id: string;
  data: DataKeyResponseValue[];
}

export interface DataKeyBatchResponse {
  users: DataKeyUserResponse[];
}

export interface DataKeyRequest {
  field_id: string;
  wrapper_key_id: string | null;
  encrypted_key: string | null;
}

// DataKeyUserRequest must be densely populated i.e. it contains an entry for every user and
// field, even if the encrypted_key in DataKeyRequest is null.
export interface DataKeyUserRequest {
  user_id: string;
  data: DataKeyRequest[];
}

export interface DataKeyBatchRequest {
  users: DataKeyUserRequest[];
}

export interface EncryptedUserDataRequestValue {
  field_id: string;
  object_type: 'string' | 'file';
  value: string;
  wrapper_key_id: string | null;
  integrity_hash: string;
}

export interface WrapperKeyResponseValue {
  id: string;
  public_key: string; // Public key as base64 string.
  algorithm: string;
}

export interface WrapperKeyResponse {
  data: WrapperKeyResponseValue[];
}

export interface FileMetadata {
  id: string;
  user_id: string;
  field_id: string;
  content_type: string;
  commitment_id: string;
  created_at: number;
}

export interface BatchOptions {
  cursor?: string;
  limit?: number;
}
