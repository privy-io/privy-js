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
  data: EncryptedUserDataResponseValue[];
}

export interface BatchEncryptedUserDataResponse {
  users: EncryptedUserDataResponse[];
}

export interface DataKeyResponseValue {
  key: string; // Data key as base64 string.
}

export interface DataKeyResponse {
  data: DataKeyResponseValue[];
}

export interface DataKeyFieldRequest {
  field_id: string;
  wrapper_key_id: string;
  encrypted_key: string;
}

export interface DataKeyUserRequest {
  user_id: string;
  data: DataKeyFieldRequest[];
}

export interface BatchDataKeyRequest {
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
