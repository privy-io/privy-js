import {PrivyConfig as PrivyNode} from '../../src';
import uniqueId from '../unique_id';

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
