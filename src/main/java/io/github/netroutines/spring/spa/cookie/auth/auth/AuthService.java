package io.github.netroutines.spring.spa.cookie.auth.auth;

import io.github.netroutines.spring.spa.cookie.auth.auth.dto.RegisterRequest;
import io.github.netroutines.spring.spa.cookie.auth.auth.dto.RegisterResponse;
import io.github.netroutines.spring.spa.cookie.auth.auth.dto.UserResponse;
import io.github.netroutines.spring.spa.cookie.auth.user.User;
import io.github.netroutines.spring.spa.cookie.auth.user.UserRepository;
import org.hibernate.exception.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {

    private static final String UNIQUE_VIOLATION_SQLSTATE = "23505";
    private static final String EMAIL_UNIQUE_CONSTRAINT = "uk_users_email";
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    public RegisterResponse register(RegisterRequest request) {
        var email = request.email();

        if (users.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered");
        }

        var name = request.name() == null ? "" : request.name().strip();

        if (name.isEmpty()) {
            var atIndex = email.lastIndexOf('@');

            if (atIndex <= 0) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email address");
            }

            name = email.substring(0, atIndex);
        }

        var user = new User(name, email, passwordEncoder.encode(request.password()));

        try {
            var savedUser = users.saveAndFlush(user);
            return new RegisterResponse(savedUser.getEmail(), "registered");
        } catch (DataIntegrityViolationException exception) {
            for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
                if (cause instanceof ConstraintViolationException violation
                    && UNIQUE_VIOLATION_SQLSTATE.equals(violation.getSQLState())
                    && EMAIL_UNIQUE_CONSTRAINT.equals(violation.getConstraintName())) {
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered");
                }
            }

            // Database exception details may contain the entire row, including its password hash.
            logger.error("Account creation failed due to a database integrity violation");
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Could not create account");
        }
    }

    public UserResponse currentUser(String email) {
        return UserResponse.from(
            users.findByEmail(email).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found")
            )
        );
    }
}
