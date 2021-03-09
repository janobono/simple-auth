package sk.janobono.common;

public enum DefaultAuthority {

    VIEW_USERS("view-users"), MANAGE_USERS("manage-users");

    private final String authorityName;

    DefaultAuthority(String authorityName) {
        this.authorityName = authorityName;
    }

    public String getAuthorityName() {
        return authorityName;
    }
}
