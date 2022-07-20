import * as crypto from 'crypto';
import {PrivyClient} from '../../src';

let client: PrivyClient;

beforeEach(() => {
  const apiKey = crypto.randomBytes(32).toString('base64');
  const apiSecret = crypto.randomBytes(32).toString('base64');
  client = new PrivyClient(apiKey, apiSecret);
});

describe('createAccessToken()', () => {
  it('should create an access token', async () => {
    const token = await client.createAccessToken('requester_id');
    expect(token).toHaveLength(322);
  });
});
