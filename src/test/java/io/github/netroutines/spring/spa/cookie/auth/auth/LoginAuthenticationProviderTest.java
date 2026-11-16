package io.github.netroutines.spring.spa.cookie.auth.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class LoginAuthenticationProviderTest {

    @Test
    void unknownAccountsStillPerformTheFrameworksDummyArgon2Comparison() {
        var encoder = spy(new SecurityConfig().passwordEncoder());
        UserDetailsService users = _ -> { throw new UsernameNotFoundException("Invalid credentials"); };
        var provider = new LoginAuthenticationProvider(users);
        provider.setPasswordEncoder(encoder);
        var request = UsernamePasswordAuthenticationToken.unauthenticated("unknown@example.com", "secret-password");

        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(request));

        // Observe the real encoder; do not infer a timing guarantee from wall-clock measurements.
        verify(encoder).matches(eq("secret-password"), anyString());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 7, 1025, 100000})
    void invalidPasswordSizesDoNotPerformLookupOrEvenTheDummyHash(int length) {
        var users = mock(UserDetailsService.class);
        var encoder = mock(PasswordEncoder.class);
        var provider = new LoginAuthenticationProvider(users);
        provider.setPasswordEncoder(encoder);
        var request = UsernamePasswordAuthenticationToken.unauthenticated("alice@example.com", "p".repeat(length));

        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(request));

        verifyNoInteractions(users, encoder);
    }
}
