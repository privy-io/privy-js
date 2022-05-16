/* eslint-disable @typescript-eslint/no-explicit-any */

export interface Storage {
  get(key: string): any;
  put(key: string, value: any): void;
  del(key: string): void;
}

export class InMemoryCache implements Storage {
  _cache: {[key: string]: any} = {};

  get(key: string) {
    return this._cache[key];
  }

  put(key: string, val: any) {
    if (val !== undefined) {
      this._cache[key] = val;
    } else {
      this.del(key);
    }
  }

  del(key: string) {
    delete this._cache[key];
  }
}

export default new InMemoryCache();
