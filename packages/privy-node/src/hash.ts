import {createHash} from 'crypto';

export const md5 = (data: Uint8Array) => createHash('md5').update(data).digest('hex');
