import axios, {AxiosResponse} from 'axios';
import {getAddress} from '@ethersproject/address';
import {PRIVY_API_URL, DEFAULT_TIMEOUT_MS} from '@privy-io/client-core/dist/constants';
import {siweNoncePath, siwePath} from '@privy-io/client-core/dist/paths';
import {CustomSession} from '@privy-io/client-core/dist/sessions/custom';
import {wrapApiError} from '@privy-io/client-core/dist/errors';
import {Token} from '@privy-io/client-core/dist/token';

export interface EthereumProvider {
  request(arg: {
    method: 'personal_sign';
    params: [address: string, message: string];
  }): Promise<string>;
  request(arg: {method: 'eth_accounts'}): Promise<string[]>;
  request(arg: {method: 'eth_requestAccounts'}): Promise<string[]>;
  request(arg: {method: 'eth_chainId'}): Promise<string>;
}

interface HTTPOptions {
  baseURL?: string;
  timeout?: number;
}

type SiweSessionOptions = HTTPOptions;

/**
 * Create EIP-4361 message for signing.
 *
 * @internal
 * @param {number} chainId EIP-155 Chain ID to which the session is bound
 * @param {string} address EIP-55 mixed-case checksum-encoded address performing the signing
 * @param {string} domain RFC 3986 authority that is requesting the signing
 * @param {string} uri RFC 3986 URI referring to the resource that is the subject of the signing
 * @param {string} issuedAt ISO 8601 datetime string of the current time
 * @param {string} nonce Randomized token used to prevent replay attacks
 * @param {string} statement Human-readable ASCII assertion that the user will sign
 * @returns {string} EIP-4361 message to sign
 */
const createSiweMessage = (
  chainId: string,
  address: string,
  domain: string,
  uri: string,
  issuedAt: string,
  nonce: string,
  statement: string,
) => `${domain} wants you to sign in with your Ethereum account:
${address}

${statement}

URI: ${uri}
Version: 1
Chain ID: ${chainId}
Nonce: ${nonce}
Issued At: ${issuedAt}
Resources:
- https://privy.io`;

/**
 * Sign-In With Ethereum sessions, i.e., `SiweSessions`, implement the {@link Session} interface.
 *
 * Privy's backend is able to issue access tokens using the [Sign-In With Ethereum](https://eips.ethereum.org/EIPS/eip-4361) spec. This enables developers to use Privy for reading/writing user data *without* hosting their own backend to handle authentication. A big win for reducing operational complexity!
 *
 * ```typescript
 * import {SiweSession} from '@privy-io/privy-js';
 * ```
 */
export class SiweSession extends CustomSession {
  /**
   * @internal
   */
  private provider: EthereumProvider;

  /**
   * @internal
   */
  private apiKey: string;

  /**
   * @internal
   */
  private baseURL: string;

  /**
   * @internal
   */
  private timeout: number;

  /**
   * @param apiKey Your *public* API key.
   * @param provider The Ethereum provider, typically `window.ethereum` (injected by MetaMask).
   * @param options Initialization options.
   */
  constructor(apiKey: string, provider: EthereumProvider, options?: SiweSessionOptions) {
    options = options || {};

    super(() => {
      return this._authenticate();
    });

    this.apiKey = apiKey;
    this.provider = provider;
    this.baseURL = options.baseURL || PRIVY_API_URL;
    this.timeout = options.timeout || DEFAULT_TIMEOUT_MS;
  }

  /**
   * A Session is considered authenticated if there is a valid token
   * and the connected wallet address is the same as the token subject.
   *
   * @returns {boolean} Whether or not the session is considered authenticated.
   */
  async isAuthenticated() {
    if (this.token === null) {
      return false;
    }

    const token = new Token(this.token);
    const address = await this.address();

    return (
      !token.isExpired(this.expirationPaddingInSeconds) &&
      address !== null &&
      address === token.subject
    );
  }

  /**
   * The currently connected address.
   *
   * @returns {string | null} EIP-55 mixed-case checksum-encoded address or null if not connected.
   */
  async address(): Promise<string | null> {
    const accounts = await this.provider.request({method: 'eth_accounts'});
    const hasAccounts = Array.isArray(accounts) && accounts.length > 0;
    return hasAccounts ? getAddress(accounts[0]) : null;
  }

  /**
   * Prompt the user to connect their wallet.
   *
   * @returns {string | null} EIP-55 mixed-case checksum-encoded address of connected wallet or null if user does not connect.
   */
  async connect(): Promise<string | null> {
    await this.provider.request({method: 'eth_requestAccounts'});
    return this.address();
  }

  /**
   * The currently connected EIP-155 chain id. E.g., `1` for Ethereum mainnet.
   *
   * @returns {string} The EIP-155 chain id.
   */
  async chainId(): Promise<string> {
    // Metamask returns a string of the chain id in hex format, e.g.: "0x1"
    const chainIdHexString = await this.provider.request({method: 'eth_chainId'});

    // Number converts string arguments (even in hex) to a proper number.
    const chainIdNumber = Number(chainIdHexString);

    // Return the EIP-155 format (decimal) representation as a string.
    return String(chainIdNumber);
  }

  /**
   * Authenticate with Privy via the Sign-In with Ethereum spec.
   *
   * @internal
   * @returns {Token} the session token.
   */
  private async _authenticate(): Promise<string> {
    const address = (await this.connect()) as string;
    const chainId = await this.chainId();
    const nonceResponse = await this.post<{nonce: string}>(siweNoncePath(), {address});
    const message = this.prepareMessage(chainId, address, nonceResponse.data.nonce);
    const signature = await this.sign(address, message);
    const response = await this.post<{token: string}>(siwePath(), {message, signature});
    return response.data.token;
  }

  /**
   * Perform personal_sign with the user's wallet.
   *
   * @internal
   * @param {string} address EIP-55 mixed-case checksum-encoded address performing the signing.
   * @param {string} message The message to sign.
   * @returns {string} The resulting signature.
   */
  private sign(address: string, message: string): Promise<string> {
    return this.provider.request({
      method: 'personal_sign',
      params: [address, message],
    });
  }

  /**
   * Creates EIP-4361 message for signing.
   *
   * @internal
   * @param {string} address EIP-55 mixed-case checksum-encoded address performing the signing.
   * @param {string} nonce Randomized token used to prevent replay attacks.
   * @returns {string} EIP-4361 message for signing.
   */
  private prepareMessage(chainId: string, address: string, nonce: string): string {
    const domain = window.location.host;
    const uri = window.location.origin;
    const statement = `${domain} requests that you authenticate with Privy.`;
    const issuedAt = new Date().toISOString();
    return createSiweMessage(chainId, address, domain, uri, issuedAt, nonce, statement);
  }

  /**
   * Perform a POST request against the Privy API with basic auth header.
   *
   * @internal
   * @param {string} path The path of the API endpoint.
   * @param {object} body The request body.
   * @returns {AxiosResponse} The axios response.
   */
  private post<T = any, R = AxiosResponse<T>, D = any>(path: string, data?: D): Promise<R> {
    try {
      return axios.post(path, data, {
        auth: {username: this.apiKey, password: ''},
        baseURL: this.baseURL,
        timeout: this.timeout,
      });
    } catch (error) {
      throw wrapApiError(error);
    }
  }
}
