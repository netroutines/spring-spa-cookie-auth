package io.github.netroutines.myagenda.auth;

import io.github.netroutines.myagenda.auth.dto.RegisterRequest;
import io.github.netroutines.myagenda.auth.dto.RegisterResponse;
import io.github.netroutines.myagenda.auth.dto.UserResponse;
import io.github.netroutines.myagenda.user.UserRepository;
import io.github.netroutines.myagenda.web.ApiErrors;
import io.github.netroutines.myagenda.web.ApiJsonConfiguration;
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
import org.springframework.test.json.JsonCompareMode;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, ApiErrors.class, ApiJsonConfiguration.class})
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

    @ParameterizedTest
    @ValueSource(strings = {"application/json", "*/*"})
    void registersWithOnlyTheNormalizedEmailAndSuccessStatus(String accept) throws Exception {
        when(authService.register(any())).thenReturn(new RegisterResponse("alice@example.com", "registered"));
        mvc.perform(post("/api/auth/register").with(csrf())
                .accept(accept).contentType(MediaType.APPLICATION_JSON).content("""
                    {"email":" ALICE@Example.COM ","name":"Alice","password":"secret-password"}
                    """))
            .andExpect(status().isCreated())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(content().json("""
                {"email":"alice@example.com","status":"registered"}
                """, JsonCompareMode.STRICT))
            .andExpect(unauthenticated())
            .andExpect(header().doesNotExist("Location"));

        verify(authService).register(new RegisterRequest("alice@example.com", "Alice", "secret-password"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"application/x-www-form-urlencoded", "application/vnd.my-agenda+json"})
    void acceptsOnlyJsonRegistrationRequests(String contentType) throws Exception {
        mvc.perform(post("/api/auth/register").with(csrf()).accept(MediaType.APPLICATION_JSON)
                .contentType(contentType).content("""
                    {"email":"alice@example.com","password":"secret-password"}
                    """))
            .andExpect(status().isUnsupportedMediaType())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.status").value(415))
            .andExpect(jsonPath("$.detail").value("Content type is not supported."));

        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/html", "application/xml", "application/problem+json"})
    void rejectsUnacceptableRegistrationResponsesBeforeCreatingAnAccount(String accept) throws Exception {
        mvc.perform(post("/api/auth/register").with(csrf()).accept(accept)
                .contentType(MediaType.APPLICATION_JSON).content("""
                    {"email":"alice@example.com","password":"secret-password"}
                    """))
            .andExpect(status().isNotAcceptable())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.status").value(406))
            .andExpect(jsonPath("$.detail").value("Requested response type is not supported."));

        verifyNoInteractions(authService);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/auth/csrf", "/api/auth/me"})
    void rejectsHtmlForJsonGetEndpointsBeforeCallingTheService(String path) throws Exception {
        mvc.perform(get(path).with(user("alice@example.com")).accept(MediaType.TEXT_HTML))
            .andExpect(status().isNotAcceptable())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.status").value(406));

        verifyNoInteractions(authService);
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

        mvc.perform(get("/api/auth/me").with(user("alice@example.com")).accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
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
