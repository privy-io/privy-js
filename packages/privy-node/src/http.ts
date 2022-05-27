import axios, {AxiosRequestConfig, AxiosResponse} from 'axios';
import {wrapApiError} from './errors';

interface DefaultsType {
  baseURL: string;
  timeout: number;
  auth?: {
    username: string;
    password: string;
  };
}

export class Http {
  private authenticate?: () => Promise<string>;
  private defaults: DefaultsType;

  constructor(authenticate: (() => Promise<string>) | undefined, defaults: DefaultsType) {
    this.authenticate = authenticate;
    this.defaults = defaults;
  }

  async get<T = any, R = AxiosResponse<T>, D = any>(
    path: string,
    config?: AxiosRequestConfig<D>,
  ): Promise<R> {
    try {
      return await axios.get(path, await this.buildConfig(config));
    } catch (e) {
      throw wrapApiError(e);
    }
  }

  async post<T = any, R = AxiosResponse<T>, D = any>(
    path: string,
    data?: D,
    config?: AxiosRequestConfig<D>,
  ): Promise<R> {
    try {
      return await axios.post(path, data, await this.buildConfig(config));
    } catch (e) {
      throw wrapApiError(e);
    }
  }

  async delete<T = any, R = AxiosResponse<T>, D = any>(
    path: string,
    config?: AxiosRequestConfig<D>,
  ): Promise<R> {
    try {
      return await axios.delete(path, await this.buildConfig(config));
    } catch (e) {
      throw wrapApiError(e);
    }
  }

  private async buildConfig(config?: AxiosRequestConfig): Promise<AxiosRequestConfig> {
    config = config || {};
    config.headers = config.headers || {};

    if (this.authenticate) {
      const token = await this.authenticate();
      config.headers.authorization = `Bearer ${token}`;
    }

    return {...this.defaults, ...config};
  }
}
