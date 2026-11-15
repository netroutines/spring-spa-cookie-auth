package io.github.netroutines.myagenda.auth;

import io.github.netroutines.myagenda.auth.dto.RegisterRequest;
import io.github.netroutines.myagenda.auth.dto.UserResponse;
import io.github.netroutines.myagenda.user.User;
import io.github.netroutines.myagenda.user.UserRepository;
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

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    public UserResponse register(RegisterRequest request) {
        var email = request.email();

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
            for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
                if (cause instanceof ConstraintViolationException violation
                    && "23505".equals(violation.getSQLState())
                    && "uk_users_email".equals(violation.getConstraintName())) {
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered");
                }
            }

            // Database exception details may contain the entire row, including its password hash.
            logger.error("Account creation failed due to a database integrity violation");
            throw new ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Could not create account"
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
