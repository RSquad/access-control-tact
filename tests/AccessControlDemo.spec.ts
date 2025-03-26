import { Blockchain, SandboxContract, TreasuryContract } from '@ton/sandbox';
import { AccessControlDemo } from '../wrappers/AccessControlDemo';
import { toNano } from '@ton/core';
import '@ton/test-utils';

describe('AccessControlDemo', () => {
    let blockchain: Blockchain;
    let admin: SandboxContract<TreasuryContract>;
    let user: SandboxContract<TreasuryContract>;
    let accessControlDemo: SandboxContract<AccessControlDemo>;

    const defaultRole = 1n;
    const ACCESS_DENIED = 132n;

    beforeEach(async () => {
        blockchain = await Blockchain.create();
        admin = await blockchain.treasury('admin');
        user = await blockchain.treasury('user');

        accessControlDemo = blockchain.openContract(await AccessControlDemo.fromInit());

        const deployResult = await accessControlDemo.send(
            admin.getSender(),
            {
                value: toNano('0.05'),
            },
            null,
        );

        expect(deployResult.transactions).toHaveTransaction({
            from: admin.address,
            to: accessControlDemo.address,
            deploy: true,
            success: true,
        });
    });

    it('should grant role for new role', async () => {
        const grantResult = await accessControlDemo.send(
            admin.getSender(),
            {
                value: toNano('0.05'),
            },
            {
                $$type: 'GrantRole',
                role: defaultRole,
                account: user.address,
            },
        );

        expect(grantResult.transactions).toHaveTransaction({
            from: admin.address,
            to: accessControlDemo.address,
            success: true,
        });

        const hasRole = await accessControlDemo.getHasRoleExternal(defaultRole, user.address);
        expect(hasRole).toBe(true);
    });

    it('should grant role for existing role', async () => {
        const grantResult = await accessControlDemo.send(
            admin.getSender(),
            {
                value: toNano('0.05'),
            },
            {
                $$type: 'GrantRole',
                role: defaultRole,
                account: user.address,
            },
        );

        expect(grantResult.transactions).toHaveTransaction({
            from: admin.address,
            to: accessControlDemo.address,
            success: true,
        });

        const hasRole = await accessControlDemo.getHasRoleExternal(defaultRole, user.address);
        expect(hasRole).toBe(true);
    });

    it('should set role admin for new role', async () => {
        const role = 2n;
        const newAdminRole = 3n;

        const setAdminResult = await accessControlDemo.send(
            admin.getSender(),
            {
                value: toNano('0.05'),
            },
            {
                $$type: 'SetRoleAdmin',
                role: role,
                newAdminRole: newAdminRole,
            },
        );

        expect(setAdminResult.transactions).toHaveTransaction({
            from: admin.address,
            to: accessControlDemo.address,
            success: true,
        });

        const roleAdmin = await accessControlDemo.getGetRoleAdminExternal(role);
        expect(roleAdmin).toBe(newAdminRole);
    });

    it('should set role admin for existing role', async () => {
        const newAdminRole = 3n;

        const setAdminResult = await accessControlDemo.send(
            admin.getSender(),
            {
                value: toNano('0.05'),
            },
            {
                $$type: 'SetRoleAdmin',
                role: defaultRole,
                newAdminRole: newAdminRole,
            },
        );

        expect(setAdminResult.transactions).toHaveTransaction({
            from: admin.address,
            to: accessControlDemo.address,
            success: true,
        });

        const roleAdmin = await accessControlDemo.getGetRoleAdminExternal(defaultRole);
        expect(roleAdmin).toBe(newAdminRole);
    });

    it('should revoke role for existing role', async () => {
        const revokeResult = await accessControlDemo.send(
            admin.getSender(),
            {
                value: toNano('0.05'),
            },
            {
                $$type: 'RevokeRole',
                role: defaultRole,
                account: admin.address,
            },
        );

        expect(revokeResult.transactions).toHaveTransaction({
            from: admin.address,
            to: accessControlDemo.address,
            success: true,
        });

        const hasRole = await accessControlDemo.getHasRoleExternal(defaultRole, admin.address);
        expect(hasRole).toBe(false);
    });

    it('should fail when non-admin tries to grant role', async () => {
        const role = 1n;

        const grantResult = await accessControlDemo.send(
            user.getSender(),
            {
                value: toNano('0.05'),
            },
            {
                $$type: 'GrantRole',
                role: role,
                account: user.address,
            },
        );

        expect(grantResult.transactions).toHaveTransaction({
            from: user.address,
            to: accessControlDemo.address,
            success: false,
            exitCode: Number(ACCESS_DENIED),
        });
    });

    it('should fail when non-admin tries to revoke role', async () => {
        const revokeResult = await accessControlDemo.send(
            user.getSender(),
            {
                value: toNano('0.05'),
            },
            {
                $$type: 'RevokeRole',
                role: defaultRole,
                account: user.address,
            },
        );

        expect(revokeResult.transactions).toHaveTransaction({
            from: user.address,
            to: accessControlDemo.address,
            success: false,
            exitCode: Number(ACCESS_DENIED),
        });
    });

    it('should renounce role', async () => {
        const role = 1n;

        await accessControlDemo.send(
            admin.getSender(),
            {
                value: toNano('0.05'),
            },
            {
                $$type: 'GrantRole',
                role: role,
                account: user.address,
            },
        );

        let hasRole = await accessControlDemo.getHasRoleExternal(role, user.address);
        expect(hasRole).toBe(true);

        const renounceResult = await accessControlDemo.send(
            user.getSender(),
            {
                value: toNano('0.05'),
            },
            {
                $$type: 'RenounceRole',
                role: role,
            },
        );

        expect(renounceResult.transactions).toHaveTransaction({
            from: user.address,
            to: accessControlDemo.address,
            success: true,
        });

        hasRole = await accessControlDemo.getHasRoleExternal(role, user.address);
        expect(hasRole).toBe(false);
    });
});
