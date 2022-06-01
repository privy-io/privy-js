import axios from 'axios';
import {fetchAPIKeys} from './api_keys';
import {PrivyClient, FieldInstance, BatchOptions} from '../../src';
import uniqueId from '../unique_id';

const PRIVY_API_URL = process.env.PRIVY_API_URL || 'http://127.0.0.1:2424/v0';
const PRIVY_KMS_URL = process.env.PRIVY_KMS_URL || 'http://127.0.0.1:2424/v0';
const PRIVY_CONSOLE = process.env.PRIVY_CONSOLE || 'http://127.0.0.1:2424/console';

// If these are omitted, a new API key pair will be generated using the default dev console login.
let PRIVY_API_PUBLIC_KEY = process.env.PRIVY_API_PUBLIC_KEY || '';
let PRIVY_API_SECRET_KEY = process.env.PRIVY_API_SECRET_KEY || '';

beforeAll(async () => {
  if (!PRIVY_API_PUBLIC_KEY || !PRIVY_API_SECRET_KEY) {
    const keyPair = await fetchAPIKeys(PRIVY_CONSOLE);
    PRIVY_API_PUBLIC_KEY = keyPair.key;
    PRIVY_API_SECRET_KEY = keyPair.secret;
  }
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

  it('get / put api', async () => {
    let username: FieldInstance | null, email: FieldInstance | null;

    // TODO(dave): Checking for initial nulls makes this test not re-runnable.

    // email = await client.get(userID, 'email');
    // expect(email).toEqual(null);

    // [username, email] = await client.get(userID, ['username', 'email']);
    // expect(username).toEqual(null);
    // expect(email).toEqual(null);

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

  it('batch get / put api', async () => {
    const user0 = uniqueId();
    let username: FieldInstance | null, email: FieldInstance | null;
    [username, email] = await client.put(user0, [
      {field: 'username', value: 'tobias'},
      {field: 'email', value: 'tobias@funke.com'},
    ]);
    const user1 = uniqueId();
    [username] = await client.put(user1, [{field: 'username', value: 'michael'}]);
    const user2 = uniqueId();
    [username] = await client.put(user2, [{field: 'username', value: 'gob'}]);

    // Test missing cursor behavior.
    let batchData = await client.getBatch(['username', 'email'], {
      limit: 1,
    });
    expect(batchData.next_cursor_id).toEqual(user1);
    expect(batchData.users.length).toEqual(1);

    // Test data returned when cursor is provided.
    batchData = await client.getBatch(['username', 'email'], {
      cursor: user1,
      limit: 2,
    });
    let users = batchData.users;
    expect(users.length).toEqual(2);
    // Check user0's data.
    expect(users[0].data.length).toEqual(2);
    username = users[0].data[0] as FieldInstance;
    expect(username.text()).toEqual('michael');
    email = users[0].data[1] as FieldInstance;
    expect(email).toEqual(null);
    // Check user1's data.
    expect(users[1].data.length).toEqual(2);
    username = users[1].data[0] as FieldInstance;
    expect(username.text()).toEqual('tobias');
    email = users[1].data[1] as FieldInstance;
    expect(email.text()).toEqual('tobias@funke.com');
  });
});
