package sk.janobono.api.service.so;

public enum DefaultRole {

    ROLE_VIEW_USERS("view-users"), ROLE_MANAGE_USERS("manage-users");

    private final String roleName;

    DefaultRole(String roleName) {
        this.roleName = roleName;
    }

    public String getRoleName() {
        return roleName;
    }
}
