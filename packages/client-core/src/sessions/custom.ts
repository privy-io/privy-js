import {Session} from './session';
import {Token} from '../token';
import {RunEffectOnce} from '../effect';
import {PrivySessionError} from '../errors';
import storage from '../storage';

// By default, a session will be considered unauthenticated
// 30 seconds prior to its token's expiration time. This is
// so we can eagerly re-authenticate before the server would
// reject requests with a 401.
const DEFAULT_EXPIRATION_PADDING_IN_SECONDS = 30;

// Store the privy token under this key so that it
// can persist between page refreshes and browser tabs.
const TOKEN_STORAGE_KEY = 'privy:token';

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
    // Attempt to hydrate the session by reading the
    // session token from storage if it exists.
    const token = storage.get(TOKEN_STORAGE_KEY);
    this.token = typeof token === 'string' ? token : null;

    this.expirationPaddingInSeconds = DEFAULT_EXPIRATION_PADDING_IN_SECONDS;

    this.authenticateOnce = new RunEffectOnce(async () => {
      try {
        const token = await authenticate();
        this.token = token;
        storage.put(TOKEN_STORAGE_KEY, token);
      } catch (error) {
        throw new PrivySessionError(`Error authenticating session: ${error}`);
      }
    });

    this.destroyOnce = new RunEffectOnce(async () => {
      try {
        this.token = null;
        storage.del(TOKEN_STORAGE_KEY);
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
