package io.github.netroutines.spring.spa.cookie.auth.auth;

import io.github.netroutines.spring.spa.cookie.auth.auth.dto.RegisterRequest;
import io.github.netroutines.spring.spa.cookie.auth.auth.dto.RegisterResponse;
import io.github.netroutines.spring.spa.cookie.auth.auth.dto.UserResponse;
import io.github.netroutines.spring.spa.cookie.auth.user.User;
import io.github.netroutines.spring.spa.cookie.auth.user.UserRepository;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.sql.SQLException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository users;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    @Test
    void registersNormalizedEmailAndStrippedNameWithTheOriginalPassword() {
        var password = "  Știință🔒! e\u0301  ";
        var request = new RegisterRequest("  ALICE@Example.COM  ", "  Alice Ionescu  ", password);
        givenSuccessfulSave(password);

        var response = authService.register(request);

        var saved = ArgumentCaptor.forClass(User.class);
        verify(users).saveAndFlush(saved.capture());
        assertThat(saved.getValue().getEmail()).isEqualTo("alice@example.com");
        assertThat(saved.getValue().getName()).isEqualTo("Alice Ionescu");
        assertThat(saved.getValue().getPasswordHash()).isEqualTo("encoded-password");
        assertThat(response).isEqualTo(new RegisterResponse("alice@example.com", "registered"));
        verify(passwordEncoder).encode(password);
        verify(users).existsByEmail("alice@example.com");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\u2003"})
    void derivesTheNameFromTheEmailWhenNoNameIsProvided(String name) {
        givenSuccessfulSave("password123");

        var response = authService.register(new RegisterRequest("Alice@Example.com", name, "password123"));

        var saved = ArgumentCaptor.forClass(User.class);
        verify(users).saveAndFlush(saved.capture());
        assertThat(saved.getValue().getName()).isEqualTo("alice");
        assertThat(response.email()).isEqualTo("alice@example.com");
    }

    @Test
    void rejectsAnExistingEmailBeforeHashingOrSaving() {
        when(users.existsByEmail("alice@example.com")).thenReturn(true);

        assertThatExceptionOfType(ResponseStatusException.class)
            .isThrownBy(() -> authService.register(new RegisterRequest("ALICE@example.com", null, "password123")))
            .satisfies(exception -> assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.CONFLICT));

        verifyNoInteractions(passwordEncoder);
        verify(users, never()).saveAndFlush(any());
    }

    @Test
    void derivesTheCompleteLocalPartForAQuotedEmailContainingAnAtSign() {
        givenSuccessfulSave("password123");

        authService.register(new RegisterRequest("\"Alice@Home\"@example.com", null, "password123"));

        var saved = ArgumentCaptor.forClass(User.class);
        verify(users).saveAndFlush(saved.capture());
        assertThat(saved.getValue().getName()).isEqualTo("\"alice@home\"");
    }

    @Test
    void mapsAConcurrentEmailUniqueViolationToConflictWithoutLeakingTheDatabaseError() {
        var sql = new SQLException("duplicate key containing private database values", "23505");
        var constraint = new ConstraintViolationException("insert failed", sql, "uk_users_email");
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(users.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("insert", constraint));

        assertThatExceptionOfType(ResponseStatusException.class)
            .isThrownBy(() -> authService.register(new RegisterRequest("alice@example.com", null, "password123")))
            .satisfies(exception -> {
                assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
                assertThat(exception.getReason()).isEqualTo("Email already registered");
                assertThat(exception.getCause()).isNull();
            });
    }

    @ParameterizedTest
    @ValueSource(strings = {"23502", "22001", "23505"})
    void reportsOtherIntegrityFailuresAsServerErrorsWithoutExposingStoredValues(String sqlState) {
        var sql = new SQLException("failing row includes encoded-password", sqlState);
        var constraint = new ConstraintViolationException("insert failed", sql, "another_constraint");
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(users.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("insert", constraint));

        assertThatExceptionOfType(ResponseStatusException.class)
            .isThrownBy(() -> authService.register(new RegisterRequest("alice@example.com", null, "password123")))
            .satisfies(exception -> {
                assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                assertThat(exception.getCause()).isNull();
                assertThat(exception.getMessage()).doesNotContain("encoded-password", "failing row");
            });
    }

    @Test
    void returnsTheCurrentUserWithoutCredentials() {
        var user = new User("Alice", "alice@example.com", "private-hash");
        ReflectionTestUtils.setField(user, "id", 42L);
        when(users.findByEmail("alice@example.com")).thenReturn(Optional.of(user));

        var response = authService.currentUser("alice@example.com");

        assertThat(response).isEqualTo(new UserResponse(42L, "alice@example.com", "Alice"));
    }

    @Test
    void rejectsACurrentUserWhoNoLongerExists() {
        assertThatExceptionOfType(ResponseStatusException.class)
            .isThrownBy(() -> authService.currentUser("deleted@example.com"))
            .satisfies(exception -> assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
    }

    private void givenSuccessfulSave(String password) {
        when(passwordEncoder.encode(password)).thenReturn("encoded-password");
        when(users.saveAndFlush(any())).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            ReflectionTestUtils.setField(user, "id", 42L);
            return user;
        });
    }
}
