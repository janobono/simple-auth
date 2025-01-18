package sk.janobono.simple.api;

import jakarta.annotation.security.RolesAllowed;
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

@RequiredArgsConstructor
public class UserController implements UsersApi {

    private final PageableUtil pageableUtil;
    private final UserService userService;

    @RolesAllowed({"admin"})
    @Override
    public Response addUser(final UserCreate userCreate) {
        return Response.status(Response.Status.CREATED)
            .entity(userService.addUser(userCreate))
            .build();
    }

    @RolesAllowed({"admin"})
    @Override
    public Response deleteUser(final Long id) {
        userService.deleteUser(id);
        return Response.status(Response.Status.OK).build();
    }

    @RolesAllowed({"admin", "manager", "employee"})
    @Override
    public Response getUser(final Long id) {
        return Response.status(Response.Status.OK)
            .entity(userService.getUser(id))
            .build();
    }

    @RolesAllowed({"admin", "manager", "employee"})
    @Override
    public Response getUsers(
        final Integer page,
        final Integer size,
        final String sort,
        final String searchField,
        final String email
    ) {
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

    @RolesAllowed({"admin"})
    @Override
    public Response setAuthorities(final Long id, final List<Authority> authorities) {
        return Response.status(Response.Status.OK)
            .entity(userService.setAuthorities(id, authorities))
            .build();
    }

    @RolesAllowed({"admin"})
    @Override
    public Response setConfirmed(final Long id, final BooleanValue confirmed) {
        return Response.status(Response.Status.OK)
            .entity(userService.setConfirmed(id, confirmed.getValue()))
            .build();
    }

    @RolesAllowed({"admin"})
    @Override
    public Response setEnabled(final Long id, final BooleanValue enabled) {
        return Response.status(Response.Status.OK)
            .entity(userService.setEnabled(id, enabled.getValue()))
            .build();
    }

    @RolesAllowed({"admin"})
    @Override
    public Response setUser(final Long id, final UserProfile userProfile) {
        return Response.status(Response.Status.OK)
            .entity(userService.setUser(id, userProfile))
            .build();
    }
}
