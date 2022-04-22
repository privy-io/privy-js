import axios from 'axios';
import PrivyClient, {FieldInstance, CustomSession} from '../../src';

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
      {requester_id: userID, roles: []},
      {
        auth: {
          username: process.env.PRIVY_API_PUBLIC_KEY as string,
          password: process.env.PRIVY_API_SECRET_KEY as string,
        },
      },
    );
    return response.data.token;
  });

  const client = new PrivyClient({
    apiURL: process.env.PRIVY_API_URL,
    kmsURL: process.env.PRIVY_KMS_URL,
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
