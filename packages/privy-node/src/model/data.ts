/**
 * Claims in the Privy access token JWT.
 */
export type AccessTokenClaims = {
  aid: string;
  aud: string;
  exp: number;
  iat: number;
  iss: string;
  rls: string[];
  sub: string;
};

/**
 * A field is the smallest unit of data stored in Privy.
 */
export interface Field {
  /**
   * Unique alphanumeric identifier for the field.
   */
  field_id: string;
  /**
   * Unique name for the field.
   */
  name: string;
  /**
   * Arbitrary string description attached to the field.
   */
  description: string;
  /**
   * Set of permissions associated to this field.
   * Includes roles with read and write access for data associated with a given group's users.
   */
  permissions: FieldPermission[];
  /**
   * Last updated timestamp.
   */
  updated_at: number;
}

/**
 * Permissions in Privy are expressed on fields.
 */
export interface FieldPermission {
  /**
   * Unique alphanumeric identifier for the group on which permissions are scoped.
   * If empty, updates permissions for the default group.
   */
  group_id: string;
  /**
   * The list of roles requesters must have to read this field's data,
   * for users belonging to the group group_id.
   */
  read: string[];
  /**
   * The list of roles requesters must have to write this field's data,
   * for users belonging to the group group_id.
   */
  write: string[];
}

/**
 * Roles grant requesters access to fields.
 */
export interface Role {
  /**
   * Unique alphanumeric identifier for the role.
   */
  role_id: string;
  /**
   * Unique name for the role.
   */
  name: string;
  /**
   * Arbitrary string description attached to the role.
   */
  description: string;
  /**
   * Indicates whether the role is a default Privy role.
   * Default roles cannot be updated or deleted.
   */
  is_default: boolean;
}

/**
 * A group is a set of users.
 */
export interface Group {
  /**
   * Unique alphanumeric identifier for the group.
   */
  group_id: string;
  /**
   * Unique name for the group.
   */
  name: string;
  /**
   * Arbitrary string description attached to the group.
   */
  description: string;
  /**
   * Indicates whether the group is a default Privy group.
   * Default groups cannot be updated or deleted.
   */
  is_default: boolean;
}

export interface EncryptedBufferData {
  field_id: string;
  buffer: Buffer;
  content_type: string;
  file_id: string;
  content_md5: string;
  wrapper_key_id: string;
}
