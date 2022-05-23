import {PrivyConfig as PrivyNode} from '../../src/config';

describe('PrivyNode', () => {
  let privyNode: PrivyNode;

  beforeEach(async () => {
    // Create a config API instance.
    privyNode = new PrivyNode(
      process.env.PRIVY_API_PUBLIC_KEY!,
      process.env.PRIVY_API_SECRET_KEY!,
      {
        apiRoute: process.env.PRIVY_API_URL!,
        timeoutMs: 0,
      },
    );
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
          description: 'Role that grants users access to their own data.',
          is_default: true,
          name: 'self',
          role_id: 'self',
        },
        {
          description: 'Default role for your admins.',
          is_default: true,
          name: 'admin',
          role_id: 'admin',
        },
        {
          description: 'Role granting public access to data.',
          is_default: true,
          name: 'public',
          role_id: 'public',
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
});
