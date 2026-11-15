package io.github.netroutines.myagenda.auth;

import io.github.netroutines.myagenda.auth.dto.RegisterRequest;
import org.jspecify.annotations.NullMarked;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Locale;

@NullMarked
final class LoginAuthenticationProvider extends DaoAuthenticationProvider {

    LoginAuthenticationProvider(UserDetailsService userDetailsService) {
        super(userDetailsService);
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        var email = authentication.getName().strip().toLowerCase(Locale.ROOT);
        var credentials = authentication.getCredentials();
        var password = credentials == null ? "" : credentials.toString();

        // Form login bypasses DTO validation. Reject invalid sizes before lookup or Argon2,
        // including the dummy password comparison for unknown accounts.
        if (email.isEmpty() || email.length() > RegisterRequest.MAX_EMAIL_LENGTH
            || password.length() < RegisterRequest.MIN_PASSWORD_LENGTH
            || password.length() > RegisterRequest.MAX_PASSWORD_LENGTH
            || password.isBlank()) {
            throw new BadCredentialsException("Invalid credentials");
        }

        return super.authenticate(authentication);
    }
}
