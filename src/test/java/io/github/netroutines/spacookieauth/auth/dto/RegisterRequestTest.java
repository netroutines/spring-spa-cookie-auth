package io.github.netroutines.spacookieauth.auth.dto;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class RegisterRequestTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void createValidator() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void closeValidator() {
        factory.close();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "alice", "@example.com", "alice@", "alice@@example.com"})
    void rejectsMissingOrInvalidEmail(String email) {
        assertInvalidField(new RegisterRequest(email, null, "password123"), "email");
    }

    @Test
    void normalizesEmailBeforeValidation() {
        var request = new RegisterRequest("\u2003ALICE@Example.COM  ", null, "password123");

        assertThat(validator.validate(request)).isEmpty();
        assertThat(request.email()).isEqualTo("alice@example.com");
    }

    @Test
    void acceptsQuotedLocalPartsContainingAnAtSign() {
        var request = new RegisterRequest("\"Alice@Home\"@example.com", null, "password123");

        assertThat(validator.validate(request)).isEmpty();
        assertThat(request.email()).isEqualTo("\"alice@home\"@example.com");
    }

    @Test
    void acceptsTheMaximumEmailLength() {
        var email = emailWithLength254();

        assertThat(email).hasSize(254);
        assertThat(validator.validate(new RegisterRequest(email, null, "password123"))).isEmpty();
    }

    @Test
    void rejectsEmailAboveTheMaximumLength() {
        assertInvalidField(new RegisterRequest(emailWithLength254() + "d", null, "password123"), "email");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "Alice", "Ștefania 🔒"})
    void acceptsOptionalAndUnicodeNames(String name) {
        assertThat(validator.validate(new RegisterRequest("alice@example.com", name, "password123"))).isEmpty();
    }

    @Test
    void enforcesTheNameLengthBoundary() {
        assertThat(validator.validate(new RegisterRequest("alice@example.com", "a".repeat(100), "password123")))
            .isEmpty();
        assertInvalidField(new RegisterRequest("alice@example.com", "a".repeat(101), "password123"), "name");
    }

    @Test
    void rejectsNulWhichPostgresqlCannotStoreInAName() {
        assertInvalidField(new RegisterRequest("alice@example.com", "Alice\0", "password123"), "name");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"1234567", "        "})
    void rejectsMissingBlankAndShortPasswords(String password) {
        assertInvalidField(new RegisterRequest("alice@example.com", null, password), "password");
    }

    @ParameterizedTest
    @MethodSource("validPasswords")
    void acceptsPasswordBoundariesAndUnicodeWithoutChangingThePassword(String password) {
        var request = new RegisterRequest("alice@example.com", null, password);

        assertThat(validator.validate(request)).isEmpty();
        assertThat(request.password()).isEqualTo(password);
    }

    static Stream<String> validPasswords() {
        return Stream.of("a".repeat(8), "a".repeat(1024), "🔒".repeat(512), "Știință🔐! e\u0301", "  parola  ");
    }

    @Test
    void rejectsPasswordsBeyond1024Utf16CodeUnits() {
        assertInvalidField(new RegisterRequest("alice@example.com", null, "a".repeat(1025)), "password");
        assertInvalidField(new RegisterRequest("alice@example.com", null, "🔒".repeat(513)), "password");
    }

    @Test
    void doesNotIncludeThePasswordInTheRecordsStringRepresentation() {
        var request = new RegisterRequest("alice@example.com", "Alice", "secret-password");

        assertThat(request.toString()).doesNotContain("secret-password");
    }

    private void assertInvalidField(RegisterRequest request, String field) {
        assertThat(validator.validate(request))
            .extracting(violation -> violation.getPropertyPath().toString())
            .contains(field);
    }

    private static String emailWithLength254() {
        return "a".repeat(64) + "@" + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61);
    }
}
