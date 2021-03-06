import axios from 'axios';
import {PrivyClient, FieldInstance, CustomSession} from '../../src';

const PRIVY_API_URL = process.env.PRIVY_API_URL || 'http://127.0.0.1:2424/v0';
const PRIVY_KMS_URL = process.env.PRIVY_KMS_URL || 'http://127.0.0.1:2424/v0';
const PRIVY_CONSOLE = process.env.PRIVY_CONSOLE || 'http://127.0.0.1:2424/console';

// If these are omitted, a new API key pair will be generated using the default dev console login.
let PRIVY_API_KEY = process.env.PRIVY_API_KEY || '';
let PRIVY_API_SECRET = process.env.PRIVY_API_SECRET || '';

// Convenience function to generate a new API key pair using default dev credentials.
const fetchAPIKeys = async () => {
  if (!PRIVY_API_KEY || !PRIVY_API_SECRET) {
    const {
      data: {token},
    } = await axios.post(
      '/token',
      {},
      {
        baseURL: PRIVY_CONSOLE,
        auth: {
          username: 'hi@acme.co',
          password: 'acme-password1',
        },
      },
    );
    const {
      data: {key, secret},
    } = await axios.post(
      '/accounts/api_keys',
      {},
      {
        baseURL: PRIVY_CONSOLE,
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    );
    console.log('Generated API key pair:', key, ',', secret);
    PRIVY_API_KEY = key;
    PRIVY_API_SECRET = secret;
  }
};

beforeAll(async () => {
  await fetchAPIKeys();
});
describe('Privy client', () => {
  const userID = `0x${Date.now()}`;

  // In production code, this would likely be setup to hit
  // a backend that would then call Privy so that the API
  // secret key is not exposed on clients. However, any
  // async function that returns a string JWT that Privy
  // can recognize the signature of is valid.
  const customSession = new CustomSession(async function authenticate() {
    const response = await axios.post<{token: string}>(
      `${PRIVY_API_URL}/auth/token`,
      {requester_id: userID, roles: []},
      {
        auth: {
          username: PRIVY_API_KEY,
          password: PRIVY_API_SECRET,
        },
      },
    );
    return response.data.token;
  });

  const client = new PrivyClient({
    apiURL: PRIVY_API_URL,
    kmsURL: PRIVY_KMS_URL,
    session: customSession,
  });

  it('get / put api', async () => {
    let username: FieldInstance | null, email: FieldInstance | null;

    email = await client.get(userID, 'email');
    expect(email).toEqual(null);

    [username, email] = await client.get(userID, ['username', 'email']);
    expect(username).toEqual(null);
    expect(email).toEqual(null);

    [username, email] = await client.put(userID, [
      {field: 'username', value: 'tobias'},
      {field: 'email', value: 'tobias@funke.com'},
    ]);

    expect(username.integrity_hash).toEqual(expect.any(String));
    expect(username.text()).toEqual('tobias');
    expect(email.integrity_hash).toEqual(expect.any(String));
    expect(email.text()).toEqual('tobias@funke.com');
    expect(username.integrity_hash !== email.integrity_hash).toEqual(true);

    username = (await client.get(userID, 'username')) as FieldInstance;
    expect(username.text()).toEqual('tobias');

    username = await client.put(userID, 'username', 'tobiasfunke');
    expect(username.integrity_hash).toEqual(expect.any(String));
    expect(username.text()).toEqual('tobiasfunke');

    username = (await client.get(userID, 'username')) as FieldInstance;
    expect(username.text()).toEqual('tobiasfunke');

    [username, email] = (await client.get(userID, ['username', 'email'])) as FieldInstance[];
    expect(username.text()).toEqual('tobiasfunke');
    expect(email.text()).toEqual('tobias@funke.com');

    const integrityHash = email.integrity_hash;

    email = (await client.getByIntegrityHash(integrityHash)) as FieldInstance;
    expect(email.text()).toEqual('tobias@funke.com');
    expect(email.integrity_hash).toEqual(integrityHash);
  });
});
