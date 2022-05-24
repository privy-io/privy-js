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
   * The name of the field.
   */
  name: string;
  /**
   * The description of the field's purpose.
   */
  description: string;
  /**
   * The default access group id assigned to the field.
   */
  default_access_group: string;
  /**
   * Last updated timestamp.
   */
  updated_at: number;
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

export interface AccessGroup {
  /**
   * Unique alphanumeric identifier for the access group.
   */
  access_group_id: string;
  /**
   * Unique name for the access group.
   */
  name: string;
  /**
   * Arbitrary string description attached to the access group.
   */
  description: string;
  /**
   * List of role ids that have READ permission in this group.
   */
  read_roles: string[];
  /**
   * List of role ids that have WRITE permission in this group.
   */
  write_roles: string[];
  /**
   * Indicates whether the access group is a default Privy access group.
   * Default access groups cannot be updated or deleted.
   */
  is_default: boolean;
}

export interface UserPermission {
  /**
   * The id of the field this permission is defined for.
   */
  field_id: string;
  /**
   * The id of the access group assigned to the field.
   */
  access_group: string;
}
