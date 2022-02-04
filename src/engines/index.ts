import {CryptoError} from '../errors';
import {CryptoVersion} from '../version';
import * as x0 from './x0';

export function CryptoEngine(version: CryptoVersion.x0): typeof x0;
export function CryptoEngine(version: CryptoVersion) {
  switch (version) {
    case CryptoVersion.x0:
      return x0;
    default:
      throw new CryptoError(`Invalid crypto version: ${version} is not a valid cypto version`);
  }
}
