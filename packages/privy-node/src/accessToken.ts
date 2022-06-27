import crypto from 'crypto';
import {SignJWT} from 'jose';
import {AccessTokenClaims} from './model/data';

const secondsSinceEpoch = (): number => {
  return Math.floor(new Date().getTime() / 1000);
};

/**
 * Signs access token claims with the provided signing key, returning a JWT string.
 */
export const signAccessToken = (
  signingKey: crypto.KeyObject,
  claims: AccessTokenClaims,
): Promise<string> => {
  return new SignJWT(claims).setProtectedHeader({alg: 'EdDSA', typ: 'JWT'}).sign(signingKey);
};

/**
 * Returns access token claims for the given data requester.
 */
export const createAccessTokenClaims = (apiKey: string, requesterId: string): AccessTokenClaims => {
  const TEN_MINUTES_IN_SECONDS = 600;
  const issuedAt = secondsSinceEpoch();
  const expiration = issuedAt + TEN_MINUTES_IN_SECONDS;
  return {
    aid: '',
    aud: 'api.privy.io',
    exp: expiration,
    iat: issuedAt,
    iss: apiKey,
    // TODO: Roles are computed by the backend, but the token schema currently still requires this field to be an array.
    rls: [],
    sub: requesterId,
  };
};

/**
 * Returns the JWT signing key generated deterministically from the API secret.
 */
export const jwtKeyFromApiSecret = (apiSecret: string): crypto.KeyObject => {
  // Convert raw Ed25519 key buffers into Node crypto KeyObjects.
  const privateKeyJwk = {
    crv: 'Ed25519',
    d: apiSecret,
    x: '',
    kty: 'OKP',
  };

  return crypto.createPrivateKey({
    key: privateKeyJwk,
    format: 'jwk',
  });
};
