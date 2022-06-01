import {PrivyClient} from '../../src';
import {fetchAPIKeys} from './api_keys';
import uniqueId from '../unique_id';

const PRIVY_API_URL = process.env.PRIVY_API_URL || 'http://127.0.0.1:2424/v0';
const PRIVY_KMS_URL = process.env.PRIVY_KMS_URL || 'http://127.0.0.1:2424/v0';
const PRIVY_CONSOLE = process.env.PRIVY_CONSOLE || 'http://127.0.0.1:2424/console';

// If these are omitted, a new API key pair will be generated using the default dev console login.
let PRIVY_API_PUBLIC_KEY = process.env.PRIVY_API_PUBLIC_KEY || '';
let PRIVY_API_SECRET_KEY = process.env.PRIVY_API_SECRET_KEY || '';

describe('PrivyNode', () => {
  let privyNode: PrivyClient;

  beforeEach(async () => {
    if (!PRIVY_API_PUBLIC_KEY || !PRIVY_API_SECRET_KEY) {
      const keyPair = await fetchAPIKeys(PRIVY_CONSOLE);
      PRIVY_API_PUBLIC_KEY = keyPair.key;
      PRIVY_API_SECRET_KEY = keyPair.secret;
    }
    // Create a config API instance.
    privyNode = new PrivyClient(
      PRIVY_API_PUBLIC_KEY!,
      PRIVY_API_SECRET_KEY!,
      {
        apiURL: PRIVY_API_URL!,
        kmsURL: PRIVY_KMS_URL!,
        timeout: 0,
      },
    );
  });

  describe('fields', () => {
    it('can list all fields', async () => {
      const fields = await privyNode.listFields();
      expect(fields).toEqual(
        expect.arrayContaining([
          expect.objectContaining({field_id: 'email'}),
          expect.objectContaining({field_id: 'name'}),
          expect.objectContaining({field_id: 'username'}),
          expect.objectContaining({field_id: 'bio'}),
          expect.objectContaining({field_id: 'website'}),
          expect.objectContaining({field_id: 'avatar'}),
        ]),
      );
    });

    it('can create, read, update, and delete a field', async () => {
      const id = uniqueId();
      const name = `Field ${id}`;
      const fieldId = `field-${id}`;

      let field;

      // GET should 404 before the field is created
      await expect(privyNode.getField(fieldId)).rejects.toThrow();

      // CREATE the field
      field = await privyNode.createField({name: name, description: 'A field'});
      expect(field).toMatchObject({
        field_id: fieldId,
        name: name,
        description: 'A field',
        default_access_group: 'self',
        updated_at: expect.any(Number),
      });

      // GET should respond with the field
      field = await privyNode.getField(fieldId);
      expect(field).toMatchObject({
        field_id: fieldId,
        name: name,
        description: 'A field',
        default_access_group: 'self',
        updated_at: expect.any(Number),
      });

      // UPDATE the field
      field = await privyNode.updateField(fieldId, {default_access_group: 'admin'});
      expect(field).toMatchObject({
        field_id: fieldId,
        name: name,
        description: 'A field',
        default_access_group: 'admin',
        updated_at: expect.any(Number),
      });

      // GET should respond with the updated field
      field = await privyNode.getField(fieldId);
      expect(field).toMatchObject({
        field_id: fieldId,
        name: name,
        description: 'A field',
        default_access_group: 'admin',
        updated_at: expect.any(Number),
      });

      // DELETE the field
      const result = await privyNode.deleteField(fieldId);
      expect(result).toBe(undefined);

      // GET should 404 when the field has been deleted
      await expect(privyNode.getField(fieldId)).rejects.toThrow();
    });
  });

  describe('roles', () => {
    it('can list all roles', async () => {
      const roles = await privyNode.listRoles();
      expect(roles).toEqual(
        expect.arrayContaining([
          expect.objectContaining({role_id: 'self'}),
          expect.objectContaining({role_id: 'admin'}),
          expect.objectContaining({role_id: 'public'}),
        ]),
      );
    });

    it('can create, read, update, and delete roles', async () => {
      const id = uniqueId();
      const name = `Role ${id}`;
      const roleId = `role-${id}`;

      let role;

      // GET should 404 before the role is created
      await expect(privyNode.getRole(roleId)).rejects.toThrow();

      // CREATE the role
      role = await privyNode.createRole({name: name, description: 'A role'});
      expect(role).toMatchObject({
        role_id: roleId,
        name: name,
        description: 'A role',
        is_default: false,
      });

      // GET should respond with the role
      role = await privyNode.getRole(roleId);
      expect(role).toMatchObject({
        role_id: roleId,
        name: name,
        description: 'A role',
        is_default: false,
      });

      // UPDATE the field
      role = await privyNode.updateRole(roleId, {description: 'An updated description'});
      expect(role).toMatchObject({
        role_id: roleId,
        name: name,
        description: 'An updated description',
        is_default: false,
      });

      // GET should respond with the updated role
      role = await privyNode.getRole(roleId);
      expect(role).toMatchObject({
        role_id: roleId,
        name: name,
        description: 'An updated description',
        is_default: false,
      });

      // DELETE the role
      const result = await privyNode.deleteRole(roleId);
      expect(result).toBe(undefined);

      // GET should 404 after the role is deleted.
      await expect(privyNode.getRole(roleId)).rejects.toThrow();
    });
  });

  describe('access groups', () => {
    it('can list all access groups', async () => {
      const accessGroup = await privyNode.listAccessGroups();
      expect(accessGroup).toEqual(
        expect.arrayContaining([
          expect.objectContaining({access_group_id: 'self'}),
          expect.objectContaining({access_group_id: 'admin'}),
          expect.objectContaining({access_group_id: 'public'}),
        ]),
      );
    });

    it('can create, read, update, and delete access groups', async () => {
      const id = uniqueId();
      const name = `Access group ${id}`;
      const accessGroupId = `access-group-${id}`;

      let accessGroup;

      // GET should 404 before the access group is created
      await expect(privyNode.getAccessGroup(accessGroupId)).rejects.toThrow();

      // CREATE the access group
      accessGroup = await privyNode.createAccessGroup({
        name: name,
        description: 'Compliance group',
        read_roles: ['self'],
        write_roles: ['self'],
      });
      expect(accessGroup).toMatchObject({
        access_group_id: accessGroupId,
        name: name,
        description: 'Compliance group',
        read_roles: ['self'],
        write_roles: ['self'],
        is_default: false,
      });

      // GET should respond with the access group
      accessGroup = await privyNode.getAccessGroup(accessGroupId);
      expect(accessGroup).toMatchObject({
        access_group_id: accessGroupId,
        name: name,
        description: 'Compliance group',
        read_roles: ['self'],
        write_roles: ['self'],
        is_default: false,
      });

      // UPDATE the field
      accessGroup = await privyNode.updateAccessGroup(accessGroupId, {
        description: 'An updated description',
      });
      expect(accessGroup).toMatchObject({
        access_group_id: accessGroupId,
        name: name,
        description: 'An updated description',
        read_roles: ['self'],
        write_roles: ['self'],
        is_default: false,
      });

      // GET should respond with the updated access group
      accessGroup = await privyNode.getAccessGroup(accessGroupId);
      expect(accessGroup).toMatchObject({
        access_group_id: accessGroupId,
        name: name,
        description: 'An updated description',
        read_roles: ['self'],
        write_roles: ['self'],
        is_default: false,
      });

      // DELETE the access group
      const result = await privyNode.deleteAccessGroup(accessGroupId);
      expect(result).toBe(undefined);

      // GET should 404 after the access group is deleted.
      await expect(privyNode.getAccessGroup(accessGroupId)).rejects.toThrow();
    });
  });

  describe('user permissions', () => {
    it('can read and write permissions', async () => {
      const userId = uniqueId();

      let permissions;

      // GET ALL
      permissions = await privyNode.getUserPermissions(userId);
      expect(permissions).toEqual(
        expect.arrayContaining([
          {field_id: 'name', access_group: 'self'},
          {field_id: 'username', access_group: 'self'},
          {field_id: 'email', access_group: 'self'},
          {field_id: 'bio', access_group: 'self'},
          {field_id: 'website', access_group: 'self'},
          {field_id: 'avatar', access_group: 'self'},
        ]),
      );

      // GET SUBSET
      permissions = await privyNode.getUserPermissions(userId, ['email', 'name']);
      expect(permissions).toEqual(
        expect.arrayContaining([
          {field_id: 'email', access_group: 'self'},
          {field_id: 'name', access_group: 'self'},
        ]),
      );

      // UPDATE
      permissions = await privyNode.updateUserPermissions(userId, [
        {field_id: 'email', access_group: 'admin'},
        {field_id: 'name', access_group: 'admin'},
      ]);
      expect(permissions).toEqual(
        expect.arrayContaining([
          {field_id: 'email', access_group: 'admin'},
          {field_id: 'name', access_group: 'admin'},
        ]),
      );

      // GET SUBSET
      permissions = await privyNode.getUserPermissions(userId, ['email', 'name']);
      expect(permissions).toEqual(
        expect.arrayContaining([
          {field_id: 'email', access_group: 'admin'},
          {field_id: 'name', access_group: 'admin'},
        ]),
      );
    });
  });

  describe('role requesters', () => {
    it('can read and update the roles assigned to requesters', async () => {
      const requesterId1 = uniqueId();
      const requesterId2 = uniqueId();

      const id = uniqueId();
      const name = `Role ${id}`;
      const roleId = `role-${id}`;

      let roles;
      let requesters;

      // CREATE a role
      const role = await privyNode.createRole({name: name, description: 'A custom role'});
      expect(role).toMatchObject({
        role_id: roleId,
        name: name,
        description: 'A custom role',
        is_default: false,
      });

      roles = await privyNode.getRequesterRoles(requesterId1);
      expect(roles.length).toEqual(2);
      expect(roles).toEqual(expect.arrayContaining(['self', 'public']));

      roles = await privyNode.getRequesterRoles(requesterId2);
      expect(roles.length).toEqual(2);
      expect(roles).toEqual(expect.arrayContaining(['self', 'public']));

      requesters = await privyNode.getRoleRequesters(roleId);
      expect(requesters).toEqual([]);

      requesters = await privyNode.addRequestersToRole(roleId, [requesterId1, requesterId2]);
      expect(requesters).toEqual(expect.arrayContaining([requesterId1, requesterId2]));

      roles = await privyNode.getRequesterRoles(requesterId1);
      expect(roles.length).toEqual(3);
      expect(roles).toEqual(expect.arrayContaining(['self', 'public', roleId]));

      roles = await privyNode.getRequesterRoles(requesterId2);
      expect(roles.length).toEqual(3);
      expect(roles).toEqual(expect.arrayContaining(['self', 'public', roleId]));

      requesters = await privyNode.getRoleRequesters(roleId);
      expect(requesters.length).toEqual(2);
      expect(requesters).toEqual(expect.arrayContaining([requesterId1, requesterId2]));

      await privyNode.removeRequesterFromRole(roleId, requesterId1);

      requesters = await privyNode.getRoleRequesters(roleId);
      expect(requesters.length).toEqual(1);
      expect(requesters).toEqual([requesterId2]);

      roles = await privyNode.getRequesterRoles(requesterId1);
      expect(roles.length).toEqual(2);
      expect(roles).toEqual(expect.arrayContaining(['self', 'public']));
    });
  });
});
