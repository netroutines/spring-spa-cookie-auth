package io.github.netroutines.myagenda.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @NotBlank
    @Email
    @Size(max = 254)
    String email,

    @Size(max = 100)
    String name,

    @NotBlank
    @Size(min = 8, max = 1024)
    String password
) {
}
