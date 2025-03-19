struct RoleData {
    members: map<Int as uint256, Bool>;
    adminRole: Int;
}

message GrantRole {
    /// The `role` to grant.
    role: Int;
    /// The `account` to grant the role to.
    account: Address;
}

message RevokeRole {
    /// The `role` to revoke.
    role: Int;
    /// The `account` to revoke the role from.
    account: Address;
}

message RenounceRole {
    /// The role to renounce.
    role: Int;
}

/// This trait is similar to the OpenZeppelin AccessControl module.
/// 
/// Trait that provides a basic version of role-based access control.
/// This version lacks methods for securely granting and revoking roles, as well as message handling.
/// To have these methods and enable message-based role management, see {AccessControl}.

/// 
/// Roles are referred to by their `Int` identifier. These should be unique. 
/// The best way to achieve this is by using `constant` hash digests:
/// 
/// ```tact
/// const MY_ROLE: Int = sha256("MY_ROLE");
/// ```
/// 
/// Roles can be used to represent a set of permissions. To restrict access to a
/// function call, use {hasRole} or {checkRole}:
/// 
/// ```tact
/// fun foo() {
///     require(self.hasRole(MY_ROLE, msg.sender), 132);
///     ...
/// }
/// ```
/// 
/// or
/// 
/// ```tact
/// fun foo() {
///     self.checkRole(MY_ROLE, msg.sender);
///     ...
/// }
/// ```
/// 
/// See:
/// * https://docs.tact-lang.org/ref/stdlib-accesscontrol/#accesscontrolbase
/// 
/// Roles can be granted and revoked dynamically via the {_grantRole} and {_revokeRole} functions,  
/// but these methods are not secure as they do not check whether the caller has the administrator role.
/// For secure role management, use the {grantRole} and {revokeRole} functions available  
/// in the extended version {AccessControl}, which enforce proper access checks.
///
/// By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
/// that only accounts with this role will be able to grant or revoke other
/// roles. More complex role relationships can be created by using
/// {_setRoleAdmin}.
///
/// WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
/// grant and revoke this role. Extra precautions should be taken to secure
/// accounts that have been granted it.
@interface("rsquad.accessControlBase")
trait AccessControlBase {
    roles: map<Int, RoleData>;

    const DEFAULT_ADMIN_ROLE: Int = 0;

    /// Grants `role` to `account`.
    /// 
    /// WARNING: Internal function without access restriction.
    inline fun _grantRole(role: Int, account: Address) {
        let stdAddr = parseStdAddress(account.asSlice());
        self._grantRoleHash(role, stdAddr.address);
    }

    /// Grants `role` to `addrHash`.
    /// 
    /// WARNING: Internal function without access restriction.
    inline fun _grantRoleHash(role: Int, addrHash: Int) {
        let roleData = self.roles.get(role);
        if (roleData != null) {
            let members = roleData!!.members;
            members.set(addrHash, true);
            self.roles.set(role, RoleData {
                members,
                adminRole: roleData!!.adminRole
            });
        } else {
            let members: map<Int as uint256, Bool> = emptyMap();
            members.set(addrHash, true);
            self.roles.set(role, RoleData {
                members,
                adminRole: self.DEFAULT_ADMIN_ROLE
            });
        }
    }

    /// Revokes `role` from `account`.
    /// 
    /// WARNING: Internal function without access restriction.
    inline fun _revokeRole(role: Int, account: Address) {
        let stdAddr = parseStdAddress(account.asSlice());
        self._revokeRoleHash(role, stdAddr.address);
    }

    /// Revokes `role` from `addrHash`.
    /// 
    /// WARNING: Internal function without access restriction.
    inline fun _revokeRoleHash(role: Int, addrHash: Int) {
        let roleData = self.roles.get(role);
        if (roleData != null) {
            let members = roleData!!.members;
            let isDeleted = members.del(addrHash);
            if (isDeleted) {
                self.roles.set(role, RoleData {
                    members,
                    adminRole: roleData!!.adminRole
                });
            }
        }
    }

    /// Sets `newRoleAdmin` as `role`'s admin role.
    /// 
    /// WARNING: Internal function without access restriction.
    inline fun _setRoleAdmin(role: Int, newRoleAdmin: Int) {
        let roleData = self.roles.get(role);
        self.roles.set(role, RoleData {
            members: roleData != null ? roleData!!.members : emptyMap(),
            adminRole: newRoleAdmin
        });
    }

    /// Throws an error with exit code 132 if `account` is missing `role`.
    /// Overriding this function changes the {grantRole} and {revokeRole} functions if using the {AccessControl} trait.
    virtual fun checkRole(role: Int, account: Address) {
        if (!self.hasRole(role, account)) {
            throw(132);
        }
    }

    /// Returns the admin role that controls `role`.
    /// 
    /// To change a role's admin, use {_setRoleAdmin}.
    inline fun getRoleAdmin(role: Int): Int {
        let roleData = self.roles.get(role);
        if (roleData != null) {
            return roleData!!.adminRole;
        }
        return self.DEFAULT_ADMIN_ROLE;
    }

    /// Returns `true` if `account` has been granted `role`.
    fun hasRole(role: Int, account: Address): Bool {
        let stdAddr = parseStdAddress(account.asSlice());
        return self.hasRoleHash(role, stdAddr.address);
    }

    /// Returns `true` if `addrHash` has been granted `role`.
    inline fun hasRoleHash(role: Int, addrHash: Int): Bool {
        let roleData = self.roles.get(role);
        if (roleData != null) {
            let members = roleData!!.members;
            let member = members.get(addrHash);
            return member != null;
        }
        return false;
    }

    /// External getter function that returns the admin role that controls `role`.
    get fun getRoleAdminExternal(role: Int): Int {
        return self.getRoleAdmin(role);
    }

    /// External getter function that returns `true` if `account` has been granted `role`.
    get fun hasRoleExternal(role: Int, account: Address): Bool {
        return self.hasRole(role, account);
    }
}

/// Trait that allows to implement role-based access
/// control mechanisms.
/// 
/// Roles are referred to by their `Int` identifier. These should be unique. 
/// The best way to achieve this is by using `constant` hash digests:
/// 
/// ```tact
/// const MY_ROLE: Int = sha256("MY_ROLE");
/// ```
/// 
/// Unlike the basic version, it has protected methods {grantRole} and {revokeRole}
/// and can accept external messages to invoke these methods. It also includes
/// the {renounceRole} method and accepts external messages to revoke a role from itself.
/// 
/// See:
/// * https://docs.tact-lang.org/ref/stdlib-accesscontrol/#accesscontrol
/// 
/// Roles can be granted and revoked dynamically via the {grantRole} and {revokeRole} functions.
/// Each role has an associated admin role, and only accounts that have a role's admin role
/// can call {grantRole} and {revokeRole}.
///
/// By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
/// that only accounts with this role will be able to grant or revoke other
/// roles. More complex role relationships can be created by using
/// {_setRoleAdmin}.
///
/// WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
/// grant and revoke this role. Extra precautions should be taken to secure
/// accounts that have been granted it.
@interface("rsquad.accessControl")
trait AccessControl with AccessControlBase {
    roles: map<Int, RoleData>;

    /// Grants `role` to `account`.
    /// 
    /// Requirements:
    /// 
    /// - the caller must have `role`'s admin role.
    ///
    /// This function can be overridden to add additional logic.
    virtual fun grantRole(role: Int, account: Address) {
        self.checkRole(self.getRoleAdmin(role), sender());
        self._grantRole(role, account);
        cashback(sender());
    }

    /// Revokes `role` from `account`.
    /// 
    /// Requirements:
    /// 
    /// - the caller must have `role`'s admin role.
    ///
    /// This function can be overridden to add additional logic.
    virtual fun revokeRole(role: Int, account: Address) {
        self.checkRole(self.getRoleAdmin(role), sender());
        self._revokeRole(role, account);
        cashback(sender());
    }

    /// Renounces `role` from the caller.
    /// 
    /// Requirements:
    /// 
    /// - the caller must have `role`.
    /// 
    /// This function can be overridden to add additional logic.
    virtual fun renounceRole(role: Int) {
        self._revokeRole(role, sender());
        cashback(sender());
    }

    /// Processes the `GrantRole` message by calling {grantRole}.
    receive(msg: GrantRole) {
        self.grantRole(msg.role, msg.account);
    }

    /// Processes the `RevokeRole` message by calling {revokeRole}.
    receive(msg: RevokeRole) {
        self.revokeRole(msg.role, msg.account);
    }

    /// Processes the `RenounceRole` message by calling {renounceRole}.
    receive(msg: RenounceRole) {
        self.renounceRole(msg.role);
    }
}