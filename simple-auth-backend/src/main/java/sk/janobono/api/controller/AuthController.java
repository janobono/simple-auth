package sk.janobono.api.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sk.janobono.api.service.AuthApiService;
import sk.janobono.api.service.so.AuthenticationRequestSO;
import sk.janobono.api.service.so.AuthenticationResponseSO;

import javax.validation.Valid;

@Tag(name = "auth", description = "authentication endpoint")
@RestController
@RequestMapping
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    private final AuthApiService authApiService;

    public AuthController(AuthApiService authApiService) {
        this.authApiService = authApiService;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponseSO> authenticate(@Valid @RequestBody AuthenticationRequestSO authenticationRequest) {
        LOGGER.debug("authenticate({})", authenticationRequest);
        return new ResponseEntity<>(authApiService.authenticate(authenticationRequest), HttpStatus.OK);
    }
}
