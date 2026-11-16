package io.github.netroutines.spring.spa.cookie.auth.auth.dto;

import io.github.netroutines.spring.spa.cookie.auth.user.User;

public record UserResponse(Long id, String email, String name) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getEmail(), user.getName());
    }
}
