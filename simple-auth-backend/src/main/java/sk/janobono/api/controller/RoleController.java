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
import sk.janobono.api.service.RoleApiService;
import sk.janobono.api.service.so.RoleDetailSO;
import sk.janobono.api.service.so.RoleSO;

import javax.validation.Valid;

@Tag(name = "roles", description = "roles management endpoint")
@RestController
@RequestMapping(path = "/roles")
public class RoleController {

    private static final Logger LOGGER = LoggerFactory.getLogger(RoleController.class);

    private final RoleApiService roleApiService;

    public RoleController(RoleApiService roleApiService) {
        this.roleApiService = roleApiService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('view-users', 'manage-users')")
    public ResponseEntity<Page<RoleDetailSO>> getRoles(Pageable pageable) {
        LOGGER.debug("getRoles({})", pageable);
        return new ResponseEntity<>(roleApiService.getRoles(pageable), HttpStatus.OK);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('view-users', 'manage-users')")
    public ResponseEntity<RoleDetailSO> getRole(@PathVariable("id") Long id) {
        LOGGER.debug("getRole({})", id);
        return new ResponseEntity<>(roleApiService.getRole(id), HttpStatus.OK);
    }

    @PostMapping
    @PreAuthorize("hasRole('manage-users')")
    public ResponseEntity<RoleDetailSO> addRole(@Valid @RequestBody RoleSO role) {
        LOGGER.debug("addRole({})", role);
        return new ResponseEntity<>(roleApiService.addRole(role), HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('manage-users')")
    public ResponseEntity<RoleDetailSO> setRole(@PathVariable("id") Long id, @Valid @RequestBody RoleSO role) {
        LOGGER.debug("addRole({})", role);
        return new ResponseEntity<>(roleApiService.setRole(id, role), HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('manage-users')")
    public void deleteRole(@PathVariable("id") Long id) {
        LOGGER.debug("deleteRole({})", id);
        roleApiService.deleteRole(id);
    }
}
