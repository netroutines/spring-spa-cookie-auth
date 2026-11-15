package io.github.netroutines.myagenda.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordEncoderTest {

    private final PasswordEncoder encoder = new SecurityConfig().passwordEncoder();

    @Test
    void usesArgon2idWithRandomSaltsAndVerifiesThePassword() {
        var password = "correct horse battery staple";

        var hash = encoder.encode(password);
        var anotherHash = encoder.encode(password);

        assertThat(hash).startsWith("$argon2id$v=19$m=19456,t=2,p=1$");
        assertThat(hash).hasSizeLessThanOrEqualTo(255).isNotEqualTo(anotherHash);
        assertThat(encoder.matches(password, hash)).isTrue();
        assertThat(encoder.matches(password, anotherHash)).isTrue();
        assertThat(encoder.matches("wrong-password", hash)).isFalse();
    }

    @Test
    void preservesUnicodeWhitespaceAndTheSuffixBeyond72Utf8Bytes() {
        var prefix = "Știință🔒".repeat(10);
        var password = "  " + prefix + "e\u0301!  ";
        assertThat(prefix.getBytes(StandardCharsets.UTF_8).length).isGreaterThan(72);

        var hash = encoder.encode(password);

        assertThat(encoder.matches(password, hash)).isTrue();
        assertThat(encoder.matches("  " + prefix + "different!  ", hash)).isFalse();
        assertThat(encoder.matches(password.strip(), hash)).isFalse();
        assertThat(encoder.matches("  " + prefix + "é!  ", hash)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 1024})
    void supportsTheApplicationsPasswordLengthBoundaries(int length) {
        var password = "ș".repeat(length);

        var hash = encoder.encode(password);

        assertThat(encoder.matches(password, hash)).isTrue();
        assertThat(encoder.matches(password + "x", hash)).isFalse();
    }
}
