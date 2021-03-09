package sk.janobono.api.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import sk.janobono.api.service.UserApiService;
import sk.janobono.api.service.so.UserCreateSO;
import sk.janobono.api.service.so.UserSO;
import sk.janobono.api.service.so.UserUpdateSO;

import javax.validation.Valid;

@Tag(name = "users", description = "users management endpoint")
@RestController
@RequestMapping(path = "/users")
public class UserController {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

    private final UserApiService userApiService;

    public UserController(UserApiService userApiService) {
        this.userApiService = userApiService;
    }

    @GetMapping()
    @PreAuthorize("hasAnyAuthority('view-users', 'manage-users')")
    public ResponseEntity<Page<UserSO>> getUsers(Pageable pageable) {
        LOGGER.debug("getUsers({})", pageable);
        return new ResponseEntity<>(userApiService.getUsers(pageable), HttpStatus.OK);
    }

    @GetMapping("/by-search-criteria")
    @PreAuthorize("hasAnyAuthority('view-users', 'manage-users')")
    public ResponseEntity<Page<UserSO>> getUsersBySearchCriteria(
            @RequestParam(value = "search-field", required = false) String searchField, Pageable pageable) {
        LOGGER.debug("getUsersBySearchCriteria({},{})", searchField, pageable);
        return new ResponseEntity<>(userApiService.getUsers(searchField, pageable), HttpStatus.OK);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('view-users', 'manage-users')")
    public ResponseEntity<UserSO> getUser(@PathVariable("id") Long id) {
        LOGGER.debug("getUser({})", id);
        return new ResponseEntity<>(userApiService.getUser(id), HttpStatus.OK);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('manage-users')")
    public ResponseEntity<UserSO> addUser(@Valid @RequestBody UserCreateSO userCreateSO) {
        LOGGER.debug("addUser({})", userCreateSO);
        return new ResponseEntity<>(userApiService.addUser(userCreateSO), HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('manage-users')")
    public ResponseEntity<UserSO> setUser(@PathVariable("id") Long id, @Valid @RequestBody UserUpdateSO userUpdateSO) {
        LOGGER.debug("setUser({})", userUpdateSO);
        return new ResponseEntity<>(userApiService.setUser(id, userUpdateSO), HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('manage-users')")
    public void deleteUser(@PathVariable("id") Long id) {
        LOGGER.debug("deleteUser({})", id);
        userApiService.deleteUser(id);
    }
}
