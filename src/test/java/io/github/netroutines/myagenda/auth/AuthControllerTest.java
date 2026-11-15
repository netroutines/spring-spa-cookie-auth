package io.github.netroutines.myagenda.auth;

import io.github.netroutines.myagenda.auth.dto.RegisterRequest;
import io.github.netroutines.myagenda.auth.dto.UserResponse;
import io.github.netroutines.myagenda.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
@ExtendWith(OutputCaptureExtension.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private JsonMapper json;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private UserRepository users;

    @Test
    void registersWithCreatedStatusAndOnlyPublicUserFields() throws Exception {
        when(authService.register(any())).thenReturn(new UserResponse(42L, "alice@example.com", "Alice"));
        mvc.perform(post("/api/auth/register").with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content("""
                    {"email":" ALICE@Example.COM ","name":"Alice","password":"secret-password"}
                    """))
            .andExpect(status().isCreated())
            .andExpect(content().json("""
                {"id":42,"email":"alice@example.com","name":"Alice"}
                """))
            .andExpect(jsonPath("$.password").doesNotExist())
            .andExpect(jsonPath("$.passwordHash").doesNotExist());

        verify(authService).register(new RegisterRequest("alice@example.com", "Alice", "secret-password"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "{}",
        "{\"email\":\"wrong\",\"password\":\"password123\"}",
        "{\"email\":\"alice@example.com\",\"password\":\"short\"}",
        "{\"email\":\"alice@example.com\",\"password\":null}",
        "{\"email\":\"alice@example.com\",\"password\":\"        \"}"
    })
    void rejectsInvalidRegistrationBeforeCallingTheService(String body) throws Exception {
        mvc.perform(post("/api/auth/register").with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isBadRequest());

        verifyNoInteractions(authService);
    }

    @Test
    void rejectsNamesContainingNulBeforeCallingTheService() throws Exception {
        var request = new RegisterRequest("alice@example.com", "Alice\0", "password123");

        mvc.perform(post("/api/auth/register").with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(request)))
            .andExpect(status().isBadRequest());

        verifyNoInteractions(authService);
    }

    @Test
    void validationErrorsDoNotExposeTheRejectedPasswordInTheResponseOrLogs(CapturedOutput output) throws Exception {
        var secret = "sensitive-password".repeat(70);
        var body = json.writeValueAsString(new RegisterRequest("alice@example.com", "Alice", secret));

        var result = mvc.perform(post("/api/auth/register").with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isBadRequest())
            .andReturn();

        assertThat(result.getResponse().getContentAsString()).doesNotContain(secret);
        assertThat(output.getAll()).doesNotContain(secret);
        verifyNoInteractions(authService);
    }

    @Test
    void rejectsMalformedJsonWithoutEchoingItsContents(CapturedOutput output) throws Exception {
        var secret = "private-json-value";

        var result = mvc.perform(post("/api/auth/register").with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"alice@example.com\",\"password\":{\"" + secret + "\":true}}"))
            .andExpect(status().isBadRequest())
            .andReturn();

        assertThat(result.getResponse().getContentAsString()).doesNotContain(secret);
        assertThat(output.getAll()).doesNotContain(secret);
        verifyNoInteractions(authService);
    }

    @Test
    void returnsTheCurrentUsersPublicDetails() throws Exception {
        when(authService.currentUser("alice@example.com"))
            .thenReturn(new UserResponse(42L, "alice@example.com", "Alice"));

        mvc.perform(get("/api/auth/me").with(user("alice@example.com")))
            .andExpect(status().isOk())
            .andExpect(content().json("""
                {"id":42,"email":"alice@example.com","name":"Alice"}
                """))
            .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void requiresAuthenticationForTheCurrentUser() throws Exception {
        mvc.perform(get("/api/auth/me"))
            .andExpect(status().isUnauthorized());

        verifyNoInteractions(authService);
    }

    @Test
    void requiresCsrfEvenForPublicRegistration() throws Exception {
        mvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isForbidden());

        mvc.perform(post("/api/auth/register").with(csrf().useInvalidToken())
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isForbidden());

        verifyNoInteractions(authService);
    }
}
