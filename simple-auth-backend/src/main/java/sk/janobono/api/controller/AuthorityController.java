package sk.janobono.api.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import sk.janobono.api.service.AuthorityApiService;
import sk.janobono.api.service.so.AuthoritySO;

@Tag(name = "authorities", description = "authorities management endpoint")
@RestController
@RequestMapping(path = "/authorities")
public class AuthorityController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorityController.class);

    private final AuthorityApiService authorityApiService;

    public AuthorityController(AuthorityApiService authorityApiService) {
        this.authorityApiService = authorityApiService;
    }

    @Operation(parameters = {
            @Parameter(in = ParameterIn.QUERY, name = "page", content = @Content(schema = @Schema(type = "integer"))),
            @Parameter(in = ParameterIn.QUERY, name = "size", content = @Content(schema = @Schema(type = "integer"))),
            @Parameter(in = ParameterIn.QUERY, name = "sort",
                    content = @Content(array = @ArraySchema(schema = @Schema(type = "string")))
            )
    })
    @GetMapping
    @PreAuthorize("hasAnyAuthority('view-users', 'manage-users')")
    public ResponseEntity<Page<AuthoritySO>> getAuthorities(
            @Parameter(hidden = true) Pageable pageable
    ) {
        LOGGER.debug("getAuthorities({})", pageable);
        return new ResponseEntity<>(authorityApiService.getAuthorities(pageable), HttpStatus.OK);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('view-users', 'manage-users')")
    public ResponseEntity<AuthoritySO> getAuthority(@PathVariable("id") Long id) {
        LOGGER.debug("getAuthority({})", id);
        return new ResponseEntity<>(authorityApiService.getAuthority(id), HttpStatus.OK);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('manage-users')")
    public ResponseEntity<AuthoritySO> addAuthority(@RequestBody String authority) {
        LOGGER.debug("addAuthority({})", authority);
        return new ResponseEntity<>(authorityApiService.addAuthority(authority), HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('manage-users')")
    public ResponseEntity<AuthoritySO> setAuthority(@PathVariable("id") Long id, @RequestBody String authority) {
        LOGGER.debug("addAuthority({})", authority);
        return new ResponseEntity<>(authorityApiService.setAuthority(id, authority), HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('manage-users')")
    public void deleteAuthority(@PathVariable("id") Long id) {
        LOGGER.debug("deleteAuthority({})", id);
        authorityApiService.deleteAuthority(id);
    }
}
