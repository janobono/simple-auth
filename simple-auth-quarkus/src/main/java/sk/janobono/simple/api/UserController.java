package sk.janobono.simple.api;

import jakarta.ws.rs.core.Response;
import java.util.List;
import lombok.RequiredArgsConstructor;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.api.model.BooleanValue;
import sk.janobono.simple.api.model.UserCreate;
import sk.janobono.simple.api.model.UserProfile;
import sk.janobono.simple.business.service.UserService;
import sk.janobono.simple.common.component.PageableUtil;
import sk.janobono.simple.common.model.UserSearchCriteriaDto;
import sk.janobono.simple.common.security.SimpleAuthContext;

@RequiredArgsConstructor
public class UserController implements UsersApi {

    private final SimpleAuthContext simpleAuthContext;
    private final PageableUtil pageableUtil;
    private final UserService userService;

    @Override
    public Response addUser(final UserCreate userCreate) {
        simpleAuthContext.hasAnyAuthority(Authority.ADMIN);
        return Response.status(Response.Status.CREATED)
            .entity(userService.addUser(userCreate))
            .build();
    }

    @Override
    public Response deleteUser(final Long id) {
        simpleAuthContext.hasAnyAuthority(Authority.ADMIN);
        userService.deleteUser(id);
        return Response.status(Response.Status.OK).build();
    }

    @Override
    public Response getUser(final Long id) {
        simpleAuthContext.hasAnyAuthority(Authority.ADMIN, Authority.MANAGER, Authority.EMPLOYEE);
        return Response.status(Response.Status.OK)
            .entity(userService.getUser(id))
            .build();
    }

    @Override
    public Response getUsers(
        final Integer page,
        final Integer size,
        final String sort,
        final String searchField,
        final String email
    ) {
        simpleAuthContext.hasAnyAuthority(Authority.ADMIN, Authority.MANAGER, Authority.EMPLOYEE);
        return Response.status(Response.Status.OK)
            .entity(userService.getUsers(
                UserSearchCriteriaDto.builder()
                    .searchField(searchField)
                    .email(email)
                    .build(),
                pageableUtil.toPageable(page, size, sort, "username", true)
            ))
            .build();
    }

    @Override
    public Response setAuthorities(final Long id, final List<Authority> authorities) {
        simpleAuthContext.hasAnyAuthority(Authority.ADMIN);
        return Response.status(Response.Status.OK)
            .entity(userService.setAuthorities(id, authorities))
            .build();
    }

    @Override
    public Response setConfirmed(final Long id, final BooleanValue confirmed) {
        simpleAuthContext.hasAnyAuthority(Authority.ADMIN);
        return Response.status(Response.Status.OK)
            .entity(userService.setConfirmed(id, confirmed.getValue()))
            .build();
    }

    @Override
    public Response setEnabled(final Long id, final BooleanValue enabled) {
        simpleAuthContext.hasAnyAuthority(Authority.ADMIN);
        return Response.status(Response.Status.OK)
            .entity(userService.setEnabled(id, enabled.getValue()))
            .build();
    }

    @Override
    public Response setUser(final Long id, final UserProfile userProfile) {
        simpleAuthContext.hasAnyAuthority(Authority.ADMIN);
        return Response.status(Response.Status.OK)
            .entity(userService.setUser(id, userProfile))
            .build();
    }
}
