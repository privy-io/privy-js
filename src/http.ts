import axios, {AxiosRequestConfig, AxiosResponse} from 'axios';
import {Session} from './sessions';
import {wrapApiError} from './errors';

interface DefaultsType {
  baseURL: string;
  timeout: number;
}

export class Http {
  private session: Session;
  private defaults: DefaultsType;

  constructor(session: Session, defaults: DefaultsType) {
    this.session = session;
    this.defaults = defaults;
  }

  async get<T = any, R = AxiosResponse<T>, D = any>(
    path: string,
    config?: AxiosRequestConfig<D>,
  ): Promise<R> {
    const authenticated = await this.session.isAuthenticated();

    if (!authenticated) {
      await this.session.authenticate();
    }

    try {
      return axios.get(path, this.buildConfig(config));
    } catch (e) {
      throw wrapApiError(e);
    }
  }

  async post<T = any, R = AxiosResponse<T>, D = any>(
    path: string,
    data?: D,
    config?: AxiosRequestConfig<D>,
  ): Promise<R> {
    const authenticated = await this.session.isAuthenticated();

    if (!authenticated) {
      await this.session.authenticate();
    }

    try {
      return axios.post(path, data, this.buildConfig(config));
    } catch (e) {
      throw wrapApiError(e);
    }
  }

  private buildConfig(config?: AxiosRequestConfig): AxiosRequestConfig {
    config = config || {};
    config.headers = config.headers || {};

    if (this.session.token !== null) {
      config.headers.authorization = `Bearer ${this.session.token}`;
    }

    return {...this.defaults, ...config};
  }
}
