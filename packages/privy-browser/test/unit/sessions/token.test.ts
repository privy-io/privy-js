import jwt from '../../jwt';
import {Token} from '../../../src/token';

describe('Token', () => {
  const activeToken = jwt.create('0x123', 60);
  const expiredToken = jwt.create('0x123', -60);

  it('parses an active JWT', () => {
    const token = new Token(activeToken);
    expect(token.value).toEqual(activeToken);
    expect(token.expiration).toEqual(expect.any(Number));
    expect(token.isExpired()).toEqual(false);
    expect(token.subject).toEqual('0x123');
    // The expiration time is reduced by the seconds argument,
    // which defaults to 0. This 'pads' the expiration time so
    // that we can eagerly refresh it if it's about to expire.
    expect(token.isExpired(60)).toEqual(true);
  });

  it('parses an expired JWT', () => {
    const token = new Token(expiredToken);
    expect(token.value).toEqual(expiredToken);
    expect(token.expiration).toEqual(expect.any(Number));
    expect(token.subject).toEqual('0x123');
    expect(token.isExpired()).toEqual(true);
  });
});
