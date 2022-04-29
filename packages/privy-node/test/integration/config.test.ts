import {Privy as PrivyNode} from './privy';
import {apiRoute, generateCredentials} from './testUtils';

let credentials: {key: string; secret: string};

beforeAll(async () => {
  credentials = await generateCredentials();
});

describe('PrivyNode', () => {
  let privyNode: PrivyNode;

  beforeEach(async () => {
    // Create a config API instance.
    privyNode = new PrivyNode(credentials.key, credentials.secret, {
      apiRoute,
      timeoutMs: 0,
    });
  });

  describe('roles', () => {
    let roleId: string;

    beforeEach(async () => {
      const role = await privyNode.createRole(`test_role`, 'test role');
      expect(role).toMatchObject({
        description: 'test role',
        is_default: false,
        name: 'test_role',
        role_id: 'test-role',
      });
      roleId = role.role_id;
    });

    afterEach(async () => {
      await expect(privyNode.deleteRole(roleId)).resolves.toBeUndefined();
    });

    it('list', async () => {
      await expect(privyNode.listRoles()).resolves.toMatchObject([
        {
          description: 'Grants users access to their own data.',
          is_default: true,
          name: 'admin',
          role_id: 'admin',
        },
        {
          description: 'Grants admin access to user data.',
          is_default: true,
          name: 'public',
          role_id: 'public',
        },
        {
          description: 'Grants public access to user data.',
          is_default: true,
          name: 'self',
          role_id: 'self',
        },
        {
          description: 'test role',
          is_default: false,
          name: 'test_role',
          role_id: 'test-role',
        },
      ]);
    });

    it('update', async () => {
      await expect(
        privyNode.updateRole(roleId, `test_role`, 'test role updated'),
      ).resolves.toMatchObject({
        description: 'test role updated',
        is_default: false,
        name: 'test_role',
        role_id: 'test-role',
      });
    });

    it('get', async () => {
      await expect(privyNode.getRole(roleId)).resolves.toMatchObject({
        description: 'test role',
        is_default: false,
        name: 'test_role',
        role_id: 'test-role',
      });
    });
  });

  describe('groups', () => {
    let groupId: string;

    beforeEach(async () => {
      const result = await privyNode.createGroup(`test_group`, 'test group');
      expect(result).toMatchObject({
        description: 'test group',
        group_id: 'test-group',
        is_default: false,
        name: 'test_group',
      });
      groupId = result.group_id;
    });

    afterEach(async () => {
      await expect(privyNode.deleteGroup(groupId)).resolves.toBeUndefined();
    });

    it('list', async () => {
      await expect(privyNode.listGroups()).resolves.toMatchObject([
        {
          description: 'Default group containing all users.',
          group_id: 'default',
          is_default: true,
          name: 'default',
        },
        {
          description: 'test group',
          group_id: 'test-group',
          is_default: false,
          name: 'test_group',
        },
      ]);
    });

    it('update', async () => {
      await expect(
        privyNode.updateGroup(groupId, `test_group`, 'test group updated'),
      ).resolves.toMatchObject({
        description: 'test group updated',
        group_id: 'test-group',
        is_default: false,
        name: 'test_group',
      });
    });

    it('get', async () => {
      await expect(privyNode.getGroup(groupId)).resolves.toMatchObject({
        description: 'test group',
        group_id: 'test-group',
        is_default: false,
        name: 'test_group',
      });
    });

    it('add and remove user', async () => {
      await expect(privyNode.addUserToGroup(groupId, '0x123456')).resolves.toBeUndefined();

      await expect(privyNode.listUsersInGroup(groupId)).resolves.toMatchObject(['0x123456']);

      await expect(privyNode.removeUserFromGroup(groupId, '0x123456')).resolves.toBeUndefined();

      await expect(privyNode.listUsersInGroup(groupId)).resolves.toMatchObject([]);
    });
  });

  describe('fields', () => {
    let fieldId: string;

    beforeEach(async () => {
      const field = await privyNode.createField('test', 'test', [
        {group_id: '', read: ['admin'], write: ['admin']},
      ]);
      expect(field).toMatchObject({
        description: 'test',
        field_id: 'test',
        name: 'test',
        permissions: [
          {
            group_id: 'default',
            read: ['admin'],
            write: ['admin'],
          },
        ],
        updated_at: expect.any(Number),
      });
      fieldId = field.field_id;
    });

    afterEach(async () => {
      await expect(privyNode.deleteField(fieldId)).resolves.toBeUndefined();
    });

    it('list', async () => {
      await expect(privyNode.listFields()).resolves.toMatchObject([
        {
          description: 'test',
          field_id: 'test',
          name: 'test',
          permissions: [
            {
              group_id: 'default',
              read: ['admin'],
              write: ['admin'],
            },
          ],
          updated_at: expect.any(Number),
        },
        {
          description: "User's avatar photo",
          field_id: 'avatar',
          name: 'Avatar',
          permissions: [
            {
              group_id: 'default',
              read: ['self', 'admin'],
              write: ['self', 'admin'],
            },
          ],
          updated_at: expect.any(Number),
        },
        {
          description: "User's personal website",
          field_id: 'website',
          name: 'Website',
          permissions: [
            {
              group_id: 'default',
              read: ['self', 'admin'],
              write: ['self', 'admin'],
            },
          ],
          updated_at: expect.any(Number),
        },
        {
          description: "User's bio",
          field_id: 'bio',
          name: 'Bio',
          permissions: [
            {
              group_id: 'default',
              read: ['self', 'admin'],
              write: ['self', 'admin'],
            },
          ],
          updated_at: expect.any(Number),
        },
        {
          description: 'Displayed username',
          field_id: 'username',
          name: 'Username',
          permissions: [
            {
              group_id: 'default',
              read: ['self', 'admin'],
              write: ['self', 'admin'],
            },
          ],
          updated_at: expect.any(Number),
        },
        {
          description: "User's email address",
          field_id: 'email',
          name: 'Email',
          permissions: [
            {
              group_id: 'default',
              read: ['self', 'admin'],
              write: ['self', 'admin'],
            },
          ],
          updated_at: expect.any(Number),
        },
        {
          description: "User's first and last",
          field_id: 'name',
          name: 'Name',
          permissions: [
            {
              group_id: 'default',
              read: ['self', 'admin'],
              write: ['self', 'admin'],
            },
          ],
          updated_at: expect.any(Number),
        },
      ]);
    });

    it('get', async () => {
      await expect(privyNode.getField(fieldId)).resolves.toMatchObject({
        description: 'test',
        field_id: 'test',
        name: 'test',
        permissions: [
          {
            group_id: 'default',
            read: ['admin'],
            write: ['admin'],
          },
        ],
        updated_at: expect.any(Number),
      });
    });

    it('field permissions for group', async () => {
      await expect(privyNode.getFieldPermissionForGroup(fieldId, 'default')).resolves.toMatchObject(
        {
          field_id: 'test',
          group_id: 'default',
          read: ['admin'],
          write: ['admin'],
        },
      );

      await expect(
        privyNode.setFieldPermissionForGroup(fieldId, 'default', {
          read: ['self'],
          write: ['self'],
        }),
      ).resolves.toMatchObject({
        field_id: 'test',
        group_id: 'default',
        read: ['self'],
        write: ['self'],
      });

      await expect(privyNode.getFieldPermissionForGroup(fieldId, 'default')).resolves.toMatchObject(
        {
          field_id: 'test',
          group_id: 'default',
          read: ['self'],
          write: ['self'],
        },
      );

      await expect(
        privyNode.deleteFieldPermissionForGroup(fieldId, 'default'),
      ).resolves.toBeUndefined();

      await expect(privyNode.getFieldPermissionForGroup(fieldId, 'default')).resolves.toMatchObject(
        {
          field_id: 'test',
          group_id: 'default',
          read: [],
          write: [],
        },
      );
    });

    it('field permissions array', async () => {
      await expect(privyNode.deleteFieldPermissions(fieldId)).resolves.toMatchObject([
        {
          deleted: true,
          field_id: 'test',
          group_id: 'default',
          read: ['admin'],
          write: ['admin'],
        },
      ]);

      await expect(privyNode.getFieldPermissions(fieldId)).resolves.toMatchObject([]);

      await expect(
        privyNode.updateFieldPermissions(fieldId, [
          {group_id: '', read: ['admin'], write: ['admin']},
        ]),
      ).resolves.toMatchObject([
        {
          field_id: 'test',
          group_id: 'default',
          read: ['admin'],
          write: ['admin'],
        },
      ]);

      await expect(privyNode.getFieldPermissions(fieldId)).resolves.toMatchObject([
        {
          field_id: 'test',
          group_id: 'default',
          read: ['admin'],
          write: ['admin'],
        },
      ]);
    });
  });
});
