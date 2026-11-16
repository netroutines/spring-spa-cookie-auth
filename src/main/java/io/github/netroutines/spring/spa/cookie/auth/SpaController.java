package io.github.netroutines.spring.spa.cookie.auth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SpaController {

    @GetMapping({"/login", "/register", "/app"})
    public String index() {
        return "forward:/index.html";
    }
}
