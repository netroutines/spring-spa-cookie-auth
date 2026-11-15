package io.github.netroutines.myagenda.auth;

import io.github.netroutines.myagenda.auth.dto.RegisterRequest;
import io.github.netroutines.myagenda.auth.dto.UserResponse;
import io.github.netroutines.myagenda.user.User;
import io.github.netroutines.myagenda.user.UserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;

@Service
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    public UserResponse register(RegisterRequest request) {
        var email = request.email()
            .strip()
            .toLowerCase(Locale.ROOT);

        if (users.existsByEmail(email)) {
            throw new ResponseStatusException(
                HttpStatus.CONFLICT,
                "Email already registered"
            );
        }

        var name = request.name() == null
            ? ""
            : request.name().strip();

        if (name.isEmpty()) {
            var atIndex = email.indexOf('@');

            if (atIndex <= 0) {
                throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid email address"
                );
            }

            name = email.substring(0, atIndex);
        }

        var user = new User(
            name,
            email,
            passwordEncoder.encode(request.password())
        );

        try {
            return UserResponse.from(users.saveAndFlush(user));
        } catch (DataIntegrityViolationException exception) {
            throw new ResponseStatusException(
                HttpStatus.CONFLICT,
                "Could not create account",
                exception
            );
        }
    }

    public UserResponse currentUser(String email) {
        var user = users.findByEmail(email)
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "User not found"
            ));

        return UserResponse.from(user);
    }
}
