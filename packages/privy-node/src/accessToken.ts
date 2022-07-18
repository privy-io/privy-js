import crypto from 'crypto';
import {SignJWT} from 'jose';
import {AccessTokenClaims} from './model/data';

// https://stackoverflow.com/questions/68668632/convert-node-js-cryptography-code-into-dart#comment121357451_68668632
const ED25519_PKCS8_PRIVATE_KEY_HEADER = Buffer.from('302e020100300506032b657004220420', 'hex');

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
  const key = Buffer.concat([ED25519_PKCS8_PRIVATE_KEY_HEADER, Buffer.from(apiSecret, 'base64')]);
  return crypto.createPrivateKey({
    key,
    format: 'der',
    type: 'pkcs8',
  });
};
