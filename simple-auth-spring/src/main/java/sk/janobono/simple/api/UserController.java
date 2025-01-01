package sk.janobono.simple.api;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;
import sk.janobono.simple.api.model.*;
import sk.janobono.simple.business.model.UserSearchCriteriaData;
import sk.janobono.simple.business.service.UserService;
import sk.janobono.simple.common.component.PageableUtil;

import java.util.List;

@RequiredArgsConstructor
@RestController
public class UserController implements UsersApi {

    private final PageableUtil pageableUtil;
    private final UserService userService;

    @PreAuthorize("hasAuthority('admin')")
    @Override
    public User addUser(final UserCreate userCreate) {
        return userService.addUser(userCreate);
    }

    @PreAuthorize("hasAuthority('admin')")
    @Override
    public void deleteUser(final Long id) {
        userService.deleteUser(id);
    }

    @PreAuthorize("hasAnyAuthority('admin', 'manager', 'employee')")
    @Override
    public User getUser(final Long id) {
        return userService.getUser(id);
    }

    @PreAuthorize("hasAnyAuthority('admin', 'manager', 'employee')")
    @Override
    public PageUser getUsers(
            final Integer page,
            final Integer size,
            final List<String> sort,
            final String searchField,
            final String email
    ) {
        return userService.getUsers(
                UserSearchCriteriaData.builder()
                        .searchField(searchField)
                        .email(email)
                        .build(),
                pageableUtil.toPageable(page, size, sort, "username", true)
        );
    }

    @PreAuthorize("hasAuthority('admin')")
    @Override
    public User setAuthorities(final Long id, final List<Authority> authorities) {
        return userService.setAuthorities(id, authorities);
    }

    @PreAuthorize("hasAuthority('admin')")
    @Override
    public User setConfirmed(final Long id, final BooleanValue confirmed) {
        return userService.setConfirmed(id, confirmed.getValue());
    }

    @PreAuthorize("hasAuthority('admin')")
    @Override
    public User setEnabled(final Long id, final BooleanValue enabled) {
        return userService.setEnabled(id, enabled.getValue());
    }

    @PreAuthorize("hasAuthority('admin')")
    @Override
    public User setUser(final Long id, final UserProfile userProfile) {
        return userService.setUser(id, userProfile);
    }
}
