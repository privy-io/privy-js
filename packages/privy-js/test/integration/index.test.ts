import axios from 'axios';
import PrivyClient, {FieldInstance, UserFieldInstances, CustomSession} from '../../src';

const PRIVY_API = process.env.PRIVY_API || 'http://127.0.0.1:2424/v0';
const PRIVY_KMS = process.env.PRIVY_KMS || 'http://127.0.0.1:2424/v0';
const PRIVY_CONSOLE = process.env.PRIVY_CONSOLE || 'http://127.0.0.1:2424/console';

// If these are omitted, a new API key pair will be generated using the default dev console login.
let PRIVY_API_PUBLIC_KEY = process.env.PRIVY_API_PUBLIC_KEY || '';
let PRIVY_API_SECRET_KEY = process.env.PRIVY_API_SECRET_KEY || '';

// Convenience function to generate a new API key pair using default dev credentials.
const fetchAPIKeys = async () => {
  if (!PRIVY_API_PUBLIC_KEY || !PRIVY_API_SECRET_KEY) {
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
    PRIVY_API_PUBLIC_KEY = key;
    PRIVY_API_SECRET_KEY = secret;
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
      `${process.env.PRIVY_API_URL}/auth/token`,
      {requester_id: userID, roles: ['admin']},
      {
        auth: {
          username: PRIVY_API_PUBLIC_KEY,
          password: PRIVY_API_SECRET_KEY,
        },
      },
    );
    return response.data.token;
  });

  const client = new PrivyClient({
    apiURL: PRIVY_API,
    kmsURL: PRIVY_KMS,
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

describe('Privy admin client', () => {
  // In production code, this would likely be setup to hit
  // a backend that would then call Privy so that the API
  // secret key is not exposed on clients. However, any
  // async function that returns a string JWT that Privy
  // can recognize the signature of is valid.
  const customSession = new CustomSession(async function authenticate() {
    const response = await axios.post<{token: string}>(
      `${process.env.PRIVY_API_URL}/auth/token`,
      {requester_id: 'admin_id', roles: ['admin']},
      {
        auth: {
          username: PRIVY_API_PUBLIC_KEY,
          password: PRIVY_API_SECRET_KEY,
        },
      },
    );
    return response.data.token;
  });

  const client = new PrivyClient({
    apiURL: PRIVY_API,
    kmsURL: PRIVY_KMS,
    session: customSession,
  });

  it('batch get / put api', async () => {
    const user0 = `0x${Date.now()}`;
    let username: FieldInstance | null, email: FieldInstance | null;
    [username, email] = await client.put(user0, [
      {field: 'username', value: 'tobias'},
      {field: 'email', value: 'tobias@funke.com'},
    ]);
    const user1 = `0x${Date.now()}`;
    [username] = await client.put(user1, [{field: 'username', value: 'michael'}]);

    const users = (await client.getBatch(['username', 'email'], {
      cursor: user1,
      limit: 2,
    })) as UserFieldInstances[];
    expect(users.length).toEqual(2);
    // Check user0's data.
    expect(users[0].field_instances.length).toEqual(2);
    username = users[0].field_instances[0] as FieldInstance;
    expect(username.text()).toEqual('michael');
    email = users[0].field_instances[1] as FieldInstance;
    expect(email).toEqual(null);
    // Check user1's data.
    expect(users[1].field_instances.length).toEqual(2);
    username = users[1].field_instances[0] as FieldInstance;
    expect(username.text()).toEqual('tobias');
    email = users[1].field_instances[1] as FieldInstance;
    expect(email.text()).toEqual('tobias@funke.com');
  });
});
