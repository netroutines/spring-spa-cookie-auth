package io.github.netroutines.spring.spa.cookie.auth.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

import java.util.Locale;

public record RegisterRequest(
    @NotBlank
    @Email
    @Size(max = RegisterRequest.MAX_EMAIL_LENGTH)
    String email,

    @Size(max = RegisterRequest.MAX_NAME_LENGTH)
    @Pattern(regexp = "[^\\x00]*", message = "must not contain NUL characters")
    String name,

    @NotBlank
    @Size(min = RegisterRequest.MIN_PASSWORD_LENGTH, max = RegisterRequest.MAX_PASSWORD_LENGTH)
    String password
) {
    public static final int MAX_EMAIL_LENGTH = 254;
    public static final int MAX_NAME_LENGTH = 100;
    // Jakarta @Size measures String.length(), in UTF-16 code units, not UTF-8 bytes.
    public static final int MIN_PASSWORD_LENGTH = 8;
    public static final int MAX_PASSWORD_LENGTH = 1024;

    public RegisterRequest {
        if (email != null) {
            email = email.strip().toLowerCase(Locale.ROOT);
        }
    }

    @Override
    public @NonNull String toString() {
        return "RegisterRequest[email=" + email + ", name=" + name + ", password=[REDACTED]]";
    }
}
