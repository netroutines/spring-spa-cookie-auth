package io.github.netroutines.spring.spa.cookie.auth.web;

import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.net.URI;

/**
 * The same public error vocabulary for MVC, servlet errors and security filters.
 */
@Component
@NullMarked
public final class ApiErrors {

    private final JsonMapper json;

    public ApiErrors(JsonMapper json) {
        this.json = json;
    }

    public ProblemDetail body(HttpStatusCode status) {
        var detail = switch (status.value()) {
            case 400 -> "Invalid request.";
            case 401 -> "Authentication is required or the credentials are invalid.";
            case 403 -> "Request forbidden.";
            case 404 -> "Resource not found.";
            case 405 -> "HTTP method not allowed.";
            case 406 -> "Requested response type is not supported.";
            case 409 -> "Email already registered.";
            case 415 -> "Content type is not supported.";
            default -> "The request could not be completed.";
        };
        var problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create("about:blank"));
        return problem;
    }

    public void write(HttpServletResponse response, HttpStatusCode status) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setHeader("Cache-Control", "no-store");
        json.writeValue(response.getOutputStream(), body(status));
    }
}
