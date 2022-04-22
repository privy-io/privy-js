import jwtDecode, {JwtPayload} from 'jwt-decode';

export class Token {
  /**
   * The raw token in string form.
   */
  value: string;

  private _decoded: JwtPayload;

  constructor(value: string) {
    this.value = value;
    this._decoded = jwtDecode<JwtPayload>(value);
  }

  /**
   * The subject is the user id to which this token is assigned.
   */
  get subject() {
    return this._decoded.sub as string;
  }

  /**
   * The date in seconds since Epoch that this token expires.
   */
  get expiration() {
    return this._decoded.exp as number;
  }

  /**
   * Whether or not the token is to be considered expired.
   *
   * @param {number} seconds A number in seconds to reduce the expiration time by. Defaults to 0
   */
  isExpired(seconds: number = 0) {
    const now = Date.now();
    const expiration = (this.expiration - seconds) * 1000;
    return now >= expiration;
  }
}
