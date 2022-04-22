import jwt from 'jsonwebtoken';

export default {
  create(subject: string, expiresInSecondsFromNow: number) {
    const dateInSeconds = Math.floor(Date.now() / 1000) + expiresInSecondsFromNow;
    return jwt.sign({sub: subject, exp: dateInSeconds}, 'secret');
  },
};
