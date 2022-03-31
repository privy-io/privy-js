import encoding from './encoding';
import {EncryptedUserDataResponseValue} from './types';

export class FieldInstance {
  private attributes: EncryptedUserDataResponseValue;
  private plaintext: Uint8Array;
  private contentType: string;

  constructor(
    attributes: EncryptedUserDataResponseValue,
    plaintext: Uint8Array,
    contentType: string,
  ) {
    this.attributes = attributes;
    this.plaintext = plaintext;
    this.contentType = contentType;
  }

  /**
   * Returns the plaintext contents of this field instance as a string.
   */
  text(): string {
    return encoding.toString(this.plaintext, 'utf8');
  }

  /**
   * Returns the plaintext contents of this field instance as a Blob.
   */
  blob(): Blob {
    return new Blob([this.plaintext], {type: this.contentType});
  }

  /**
   * The id of the user this field instance belongs to.
   */
  get user_id() {
    return this.attributes.user_id;
  }

  /**
   * The id of the field this field instance belongs to.
   */
  get field_id() {
    return this.attributes.field_id;
  }

  /**
   * The type of object the value is. This is either 'string' or 'file'.
   *
   * If this is 'string', the value will be the encrypted contents.
   *
   * If this is 'file', the value will be the plaintext file id.
   */
  get object_type() {
    return this.attributes.object_type;
  }

  /**
   * The value of this field instance. The value depends on the object type.
   *
   * If object_type is 'string', this will be the encrypted contents.
   *
   * If object_type is 'file', this will be the plaintext file id.
   */
  get value() {
    return this.attributes.value;
  }

  /**
   * The sha256 hash of the plaintext value concatenated with a nonce.
   */
  get integrity_hash() {
    return this.attributes.integrity_hash;
  }

  /**
   * The time this field instance was created.
   */
  get created_at() {
    return this.attributes.created_at;
  }
}
