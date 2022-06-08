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

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('get / put api', async () => {
    let username: FieldInstance | null, email: FieldInstance | null;

    // TODO(#914): Handle null checks such that these tests can be re-run without failing.
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

  it('batch get / put api', async () => {
    // SETUP: Create 2 fields, initially with admin default access group for both.
    const id = uniqueId();
    const adminDefaultField = `field-${id}-admin`;
    // This field will later have `self` set as the default access group.
    const selfDefaultField = `field-${id}-self`;

    let field;
    field = await client.createField({name: selfDefaultField, default_access_group: 'admin'});
    expect(field).toMatchObject({
      field_id: selfDefaultField,
      name: selfDefaultField,
      default_access_group: 'admin',
      updated_at: expect.any(Number),
    });

    field = await client.createField({name: adminDefaultField, default_access_group: 'admin'});
    expect(field).toMatchObject({
      field_id: adminDefaultField,
      name: adminDefaultField,
      default_access_group: 'admin',
      updated_at: expect.any(Number),
    });

    const user0 = `user-${id}-0`;
    let adminFieldVal: FieldInstance | null, selfFieldVal: FieldInstance | null;
    [adminFieldVal, selfFieldVal] = await client.put(user0, [
      {field: adminDefaultField, value: 'admin-val-0'},
      {field: selfDefaultField, value: 'self-val-0'},
    ]);
    const user1 = `user-${id}-1`;
    [selfFieldVal] = await client.put(user1, [{field: selfDefaultField, value: 'self-val-1'}]);
    const user2 = `user-${id}-2`;
    [adminFieldVal] = await client.put(user2, [{field: adminDefaultField, value: 'admin-val-2'}]);

    // Now change the default access group for the self field.
    field = await client.updateField(selfDefaultField, {default_access_group: 'self'});
    expect(field).toMatchObject({
      field_id: selfDefaultField,
      name: selfDefaultField,
      default_access_group: 'self',
      updated_at: expect.any(Number),
    });

    field = await client.updateField(selfDefaultField, {default_access_group: 'self'});
    expect(field).toMatchObject({
      field_id: selfDefaultField,
      name: selfDefaultField,
      default_access_group: 'self',
      updated_at: expect.any(Number),
    });

    // Update user0's selfDefaultField's access group to a custom access group with read admin perms.
    const testAccessGroupId = `test-access-group-${id}`;
    const accessGroup = await client.createAccessGroup({
      name: testAccessGroupId,
      read_roles: ['admin'],
      write_roles: ['self'],
    });
    expect(accessGroup).toMatchObject({
      access_group_id: testAccessGroupId,
      name: testAccessGroupId,
      read_roles: ['admin'],
      write_roles: ['self'],
      is_default: false,
    });
    let permissions = await client.updateUserPermissions(user0, [
      {field_id: selfDefaultField, access_group: testAccessGroupId},
    ]);
    expect(permissions).toEqual(
      expect.arrayContaining([{field_id: selfDefaultField, access_group: testAccessGroupId}]),
    );

    // TEST: Check missing cursor returns oldest user.
    let batchData = await client.getBatch([adminDefaultField, selfDefaultField], {
      limit: 1,
    });
    expect(batchData.next_cursor_id).toEqual(user1);
    expect(batchData.users.length).toEqual(1);

    // Test data returned when cursor is provided.
    batchData = await client.getBatch([adminDefaultField, selfDefaultField], {
      cursor: user1,
      limit: 2,
    });
    let users = batchData.users;
    expect(users.length).toEqual(2);
    // Check user1's data.
    expect(users[0].data.length).toEqual(2);
    let adminDefaultFieldVal = users[0].data[0] as FieldInstance;
    expect(adminDefaultFieldVal).toEqual(null);
    let selfDefaultFieldVal = users[0].data[1] as FieldInstance;
    expect(selfDefaultFieldVal).toEqual(null);
    // Check user0's data.
    expect(users[1].data.length).toEqual(2);
    adminDefaultFieldVal = users[1].data[0] as FieldInstance;
    expect(adminDefaultFieldVal.text()).toEqual('admin-val-0');
    selfDefaultFieldVal = users[1].data[1] as FieldInstance;
    expect(selfDefaultFieldVal.text()).toEqual('self-val-0');
  });

  it('sends email with replacement', async () => {
    // This tests the send method end-to-end _minus_ the part that actually
    // calls the /actions/send_email - we just assume it returns healthy (and if
    // it doesn't, it's a drop-through to standard error handling). The main
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
