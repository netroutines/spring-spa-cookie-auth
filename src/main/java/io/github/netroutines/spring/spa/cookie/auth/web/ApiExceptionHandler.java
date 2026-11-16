package io.github.netroutines.spring.spa.cookie.auth.web;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
@NullMarked
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    private final ApiErrors errors;

    public ApiExceptionHandler(ApiErrors errors) {
        this.errors = errors;
    }

    @Override
    protected @Nullable ResponseEntity<Object> handleExceptionInternal(
        Exception exception, @Nullable Object body, HttpHeaders headers,
        HttpStatusCode status, WebRequest request
    ) {
        if (request instanceof ServletWebRequest servletRequest) {
            var response = servletRequest.getResponse();
            if (response != null && response.isCommitted()) {
                return null;
            }
        }
        // Never include exception messages, rejected values or persistence details.
        return ResponseEntity.status(status).headers(headers)
            .contentType(MediaType.APPLICATION_PROBLEM_JSON)
            .cacheControl(CacheControl.noStore()).body(errors.body(status));
    }

    @ExceptionHandler(Exception.class)
    public @Nullable ResponseEntity<Object> unexpected(Exception exception, WebRequest request) throws Exception {
        // Let the security filter chain translate authentication/authorization exceptions.
        if (exception instanceof AuthenticationException || exception instanceof AccessDeniedException) {
            throw exception;
        }

        log.error("Request failed with {}", exception.getClass().getSimpleName());

        return handleExceptionInternal(exception, null, HttpHeaders.EMPTY,
            HttpStatus.INTERNAL_SERVER_ERROR, request);
    }
}
