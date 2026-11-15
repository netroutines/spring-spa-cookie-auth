package io.github.netroutines.myagenda.auth.dto;

import io.github.netroutines.myagenda.user.User;

public record UserResponse(
    Long id,
    String email,
    String name
) {

    public static UserResponse from(User user) {
        return new UserResponse(
            user.getId(),
            user.getEmail(),
            user.getName()
        );
    }
}
