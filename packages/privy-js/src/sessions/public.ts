import axios, {AxiosRequestConfig} from 'axios';
import {CustomSession} from './custom';
import {PRIVY_API_URL, DEFAULT_TIMEOUT_MS} from '../constants';
import {wrapApiError} from '../errors';

interface HTTPOptions {
  baseURL?: string;
  timeout?: number;
}

type PublicSessionOptions = HTTPOptions;

export class PublicSession extends CustomSession {
  constructor(apiKey: string, options?: PublicSessionOptions) {
    options = options || {};

    const axiosOptions: AxiosRequestConfig = {
      auth: {username: apiKey, password: ''},
      baseURL: options.baseURL || PRIVY_API_URL,
      timeout: options.timeout || DEFAULT_TIMEOUT_MS,
    };

    async function authenticate() {
      try {
        const response = await axios.post<{token: string}>('/auth/public', {}, axiosOptions);
        return response.data.token;
      } catch (error) {
        throw wrapApiError(error);
      }
    }

    super(authenticate);
  }
}
