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
