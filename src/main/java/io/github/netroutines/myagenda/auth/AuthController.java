package io.github.netroutines.myagenda.auth;

import io.github.netroutines.myagenda.auth.dto.RegisterRequest;
import io.github.netroutines.myagenda.auth.dto.RegisterResponse;
import io.github.netroutines.myagenda.auth.dto.UserResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping(value = "/csrf", produces = MediaType.APPLICATION_JSON_VALUE)
    public CsrfToken csrf(CsrfToken token) {
        return token;
    }

    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @GetMapping(value = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
    public UserResponse me(Authentication authentication) {
        return authService.currentUser(authentication.getName());
    }
}
