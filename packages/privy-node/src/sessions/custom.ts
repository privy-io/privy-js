import {Session} from '.';
import {Token} from '../token';
import {RunEffectOnce} from '../effect';
import {PrivySessionError} from '../errors';

// By default, a session will be considered unauthenticated
// 30 seconds prior to its token's expiration time. This is
// so we can eagerly re-authenticate before the server would
// reject requests with a 401.
const DEFAULT_EXPIRATION_PADDING_IN_SECONDS = 30;

/**
 * `CustomSession` implements the {@link Session} interface. `CustomSession` can be used to authenticate to Privy through your own backend.
 *
 * ```typescript
 * import {CustomSession} from '@privy-io/privy-js';
 * ```
 */
export class CustomSession implements Session {
  private authenticateOnce: RunEffectOnce;
  private destroyOnce: RunEffectOnce;

  protected expirationPaddingInSeconds: number;

  token: string | null = null;

  /**
   * @param authenticate Custom authenticate function. Must return a valid JWT on success.
   */
  constructor(authenticate: () => Promise<string>) {
    this.expirationPaddingInSeconds = DEFAULT_EXPIRATION_PADDING_IN_SECONDS;

    this.authenticateOnce = new RunEffectOnce(async () => {
      try {
        this.token = await authenticate();
      } catch (error) {
        throw new PrivySessionError(`Error authenticating session: ${error}`);
      }
    });

    this.destroyOnce = new RunEffectOnce(async () => {
      try {
        this.token = null;
      } catch (error) {
        throw new PrivySessionError(`Error destroying session: ${error}`);
      }
    });
  }

  /**
   * A Session is considered authenticated if there is a token
   * that is not expired or expiring soon (see expiration padding).
   *
   * @returns {boolean} Whether or not the session is considered authenticated.
   */
  async isAuthenticated() {
    if (this.token === null) {
      return false;
    }

    const token = new Token(this.token);

    return !token.isExpired(this.expirationPaddingInSeconds);
  }

  /**
   * Authenticate the session.
   */
  authenticate() {
    return this.authenticateOnce.execute();
  }

  /**
   * Destroy the session.
   */
  destroy() {
    return this.destroyOnce.execute();
  }
}
