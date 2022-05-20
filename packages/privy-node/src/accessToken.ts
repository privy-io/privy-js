import crypto from 'crypto';
import {SignJWT} from 'jose';
import nacl from 'tweetnacl';
import {AccessTokenClaims} from './model/data';
import encoding from './encoding';

const secondsSinceEpoch = (): number => {
  return Math.floor(new Date().getTime() / 1000);
};

/**
 * getAccessToken returns a signed access token associating a data requester with a set of roles.
 */
export const createAccessToken = (
  signingKey: crypto.KeyObject,
  apiKey: string,
  requesterId: string,
  roles: string[],
): Promise<string> => {
  return new SignJWT(createAccessTokenClaims(apiKey, requesterId, roles))
    .setProtectedHeader({alg: 'EdDSA', typ: 'JWT'})
    .sign(signingKey);
};

/**
 * getAccessTokenClaims returns access token claims associating a data requester with a set of roles.
 */
export const createAccessTokenClaims = (
  apiKey: string,
  requesterId: string,
  roles: string[],
): AccessTokenClaims => {
  const TEN_MINUTES_IN_SECONDS = 600;
  const issuedAt = secondsSinceEpoch();
  const expiration = issuedAt + TEN_MINUTES_IN_SECONDS;
  return {
    aid: '',
    aud: 'api.privy.io',
    exp: expiration,
    iat: issuedAt,
    iss: apiKey,
    rls: roles,
    sub: requesterId,
  };
};

/**
 * Returns the JWT signing key generated deterministically from the API secret.
 */
export const jwtKeyFromApiSecret = (apiSecret: string): crypto.KeyObject => {
  // Decode from URL-safe base64.
  const apiSecretBuffer = encoding.toBuffer(apiSecret, 'base64');

  // Generate the signing key pair deterministicaly from the secret.
  const keyPair = nacl.sign.keyPair.fromSeed(apiSecretBuffer);

  // Convert raw Ed25519 key buffers into Node crypto KeyObjects.
  const privateKeyJwk = {
    crv: 'Ed25519',
    d: encoding.toString(keyPair.secretKey.slice(0, 32), 'base64'),
    x: encoding.toString(keyPair.publicKey, 'base64'),
    kty: 'OKP',
  };

  return crypto.createPrivateKey({
    key: privateKeyJwk,
    format: 'jwk',
  });
};
