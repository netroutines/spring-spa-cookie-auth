package io.github.netroutines.spring.spa.cookie.auth.web;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.NullMarked;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Fallback for errors dispatched by the servlet container, outside MVC exception handling.
 */
@RestController
@NullMarked
public class ApiErrorController implements ErrorController {

    private final ApiErrors errors;

    public ApiErrorController(ApiErrors errors) {
        this.errors = errors;
    }

    @RequestMapping("${spring.web.error.path:/error}")
    public ResponseEntity<ProblemDetail> error(HttpServletRequest request) {
        var attribute = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        var status = attribute instanceof Integer code && code >= 400 && code <= 599 ? code : 500;
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON)
            .cacheControl(CacheControl.noStore()).body(errors.body(HttpStatusCode.valueOf(status)));
    }
}
