import axios from 'axios';
import {PrivyClient, FieldInstance} from '../../src';

const PRIVY_API_URL = process.env.PRIVY_API_URL || 'http://127.0.0.1:2424/v0';
const PRIVY_KMS_URL = process.env.PRIVY_KMS_URL || 'http://127.0.0.1:2424/v0';
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
  const userID = `admin`;

  let client: PrivyClient;

  beforeAll(() => {
    client = new PrivyClient(PRIVY_API_PUBLIC_KEY!, PRIVY_API_SECRET_KEY!, {
      apiURL: PRIVY_API_URL,
      kmsURL: PRIVY_KMS_URL,
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
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

  it('putFile / getFile api', async () => {
    const file = await client.putFile(userID, 'avatar', Buffer.from('file_data'), 'text/plain');
    expect(file.contentType).toEqual('text/plain');
    expect(file.field_id).toEqual('avatar');
    expect(file.user_id).toEqual(userID);

    const downloadedFile = await client.getFile(userID, 'avatar');
    expect(downloadedFile!.buffer().toString()).toEqual('file_data');
    expect(downloadedFile!.contentType).toEqual('text/plain');
  });

  it('sends email with replacement', async () => {
    // This tests the send method E2E _minus_ the part that actually calls the
    // /actions/send_email - we just assume it returns healthy (and if it
    // doesn't, it's a drop-through to standard error handling). The main
    // reason for this is that we can't mock the email provider call on the
    // API side :( We rely on the actual API tests for validating the
    // API functionality.

    // Setup
    await client.put(userID, [
      {field: 'username', value: 'tobias'},
      {field: 'email', value: 'tobias@funke.com'},
    ]);

    // We need the first mockImplementationOnce(axiosPost), because we make a\
    // post call to the KMS endpoint and want that to actually run. After
    // that, the next post call is to /actions/send_email, which we mock.
    const axiosPost = axios.post;
    const mockedPost = async () => Promise.resolve({data: 'Success: email sent'});
    jest.spyOn(axios, 'post').mockImplementationOnce(axiosPost).mockImplementation(mockedPost);

    // Execute
    await client.sendEmail(userID, 'Test Subject', 'Hello{{#if username}} {{username}}{{/if}}!', [
      'username',
    ]);

    expect(axios.post).toHaveBeenLastCalledWith(
      '/actions/send_email',
      {
        to_email: 'tobias@funke.com',
        subject: 'Test Subject',
        html_content: 'Hello tobias!',
      },
      expect.any(Object),
    );
  });
});
