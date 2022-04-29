import jwt from '../../test/jwt';
import {CustomSession} from './custom';
import storage from '../storage';

describe('CustomSession', () => {
  // Expires in sixty seconds
  const activeToken = jwt.create('0x123', 60);

  // Expired 60 seconds ago
  const expiredToken = jwt.create('0x123', -60);

  // Expires in 10 seconds
  const aboutToExpireToken = jwt.create('0x123', 10);

  beforeEach(() => {
    // Custom sessions write the token to storage.
    // Clear this value otherwise state leaks between tests.
    storage.del('privy:token');
  });

  it('works', async () => {
    const authenticateSpy = jest.fn();

    const session = new CustomSession(async function authenticate() {
      authenticateSpy();
      return activeToken;
    });

    expect(authenticateSpy).toBeCalledTimes(0);

    // Session starts off unauthenticated
    expect(await session.isAuthenticated()).toEqual(false);
    expect(session.token).toEqual(null);

    // Can authenticate the session
    await session.authenticate();
    expect(authenticateSpy).toBeCalledTimes(1);
    expect(await session.isAuthenticated()).toEqual(true);
    expect(session.token).toEqual(activeToken);

    // Can destroy the session
    await session.destroy();
    expect(await session.isAuthenticated()).toEqual(false);
    expect(session.token).toEqual(null);

    // Can re-authenticate
    await session.authenticate();
    expect(authenticateSpy).toBeCalledTimes(2);
    expect(await session.isAuthenticated()).toEqual(true);
    expect(session.token).toEqual(activeToken);
  });

  it('is not authenticated when the token is expired', async () => {
    const authenticateSpy = jest.fn();

    const session = new CustomSession(async function authenticate() {
      authenticateSpy();
      return expiredToken;
    });

    expect(authenticateSpy).toBeCalledTimes(0);

    // Session starts off unauthenticated
    expect(await session.isAuthenticated()).toEqual(false);
    expect(session.token).toEqual(null);

    // Can authenticate
    await session.authenticate();
    expect(authenticateSpy).toBeCalledTimes(1);

    // There is a token, but it is expired
    expect(await session.isAuthenticated()).toEqual(false);
    expect(session.token).toEqual(expiredToken);
  });

  it('only calls authenticate once before completion', async () => {
    const authenticateSpy = jest.fn();

    const session = new CustomSession(async function authenticate() {
      authenticateSpy();
      return activeToken;
    });

    expect(authenticateSpy).toBeCalledTimes(0);

    session.authenticate();
    session.authenticate();
    await session.authenticate();

    expect(authenticateSpy).toBeCalledTimes(1);
  });

  it('is not considered authenticated if expiring soon', async () => {
    // Default expiration padding is 15 seconds
    const session = new CustomSession(async function authenticate() {
      // Expires in 10 seconds
      return aboutToExpireToken;
    });

    // With default expiration padding of 15 seconds,
    // the session is considered unauthenticated since
    // the token expires in 10 seconds from now.
    //
    // That is, 10 - 15 = -5, so the token is considerd
    // having expired 5 seconds ago.
    await session.authenticate();
    expect(await session.isAuthenticated()).toEqual(false);
  });
});
