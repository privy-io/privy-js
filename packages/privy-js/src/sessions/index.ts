/**
 * Privy clients depend on a session object to handle authentication. There are three Session objects:
 *
 * 1. {@link CustomSession}
 * 2. {@link SiweSession}
 * 3. {@link PublicSession}
 */
export interface Session {
  /**
   * JWT returned by the Privy API upon successfully authenticating.
   */
  token: string | null;

  /**
   * Should return `true` if the session is considered authenticated, `false` otherwise.
   */
  isAuthenticated(): Promise<boolean>;

  /**
   * Should authenticate with the Privy API (potentially indirectly through a backend). After a successful call, the session should be considered authenticated.
   */
  authenticate(): Promise<void>;

  /**
   * Should remove any state related to authentication. Afterwords, the session should NOT be considered authenticated.
   */
  destroy(): Promise<void>;
}
