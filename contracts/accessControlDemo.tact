import "./accessControl.tact";

message SetRoleAdmin {
    role: Int;
    newAdminRole: Int;
}

contract AccessControlDemo with AccessControl {
    roles: map<Int, RoleData>;

    init() {
        self._grantRole(self.DEFAULT_ADMIN_ROLE, sender());
    }

    receive(msg: SetRoleAdmin) {
        self._setRoleAdmin(msg.role, msg.newAdminRole);
    }

    receive() {
        cashback(sender());
    }

    get fun roleData(role: Int): RoleData {
        return self.roles.get(role)!!;
    }
}
