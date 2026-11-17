package io.github.netroutines.spacookieauth.auth;

import io.github.netroutines.spacookieauth.web.ApiErrors;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Validate the HTTP envelope; Spring's form-login filter still performs authentication.
 */
@NullMarked
final class LoginRequestFilter extends OncePerRequestFilter {

    private final RequestMatcher login = PathPatternRequestMatcher
        .withDefaults()
        .matcher(HttpMethod.POST, "/api/auth/login");

    private final ApiErrors errors;

    LoginRequestFilter(ApiErrors errors) {
        this.errors = errors;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        if (login.matches(request)) {
            if (!isForm(request)) {
                errors.write(response, HttpStatus.UNSUPPORTED_MEDIA_TYPE);
                return;
            }

            // Servlet parameters merge query and form values; reject ambiguous input and credentials in URLs.
            var emails = request.getParameterValues("email");
            var passwords = request.getParameterValues("password");

            if (request.getQueryString() != null
                || (emails != null && emails.length != 1)
                || (passwords != null && passwords.length != 1)) {
                errors.write(response, HttpStatus.BAD_REQUEST);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private boolean isForm(HttpServletRequest request) {
        var contentType = request.getContentType();

        if (contentType == null) {
            return false;
        }

        try {
            return MediaType.APPLICATION_FORM_URLENCODED.includes(MediaType.parseMediaType(contentType));
        } catch (InvalidMediaTypeException exception) {
            return false;
        }
    }
}
