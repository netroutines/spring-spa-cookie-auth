package io.github.netroutines.spacookieauth.auth;

import io.github.netroutines.spacookieauth.SpaController;
import io.github.netroutines.spacookieauth.user.User;
import io.github.netroutines.spacookieauth.user.UserRepository;
import io.github.netroutines.spacookieauth.web.ApiErrors;
import io.github.netroutines.spacookieauth.web.ApiJsonConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.FormLoginRequestBuilder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest({AuthController.class, SpaController.class})
@Import({SecurityConfig.class, AuthService.class, ApiErrors.class, ApiJsonConfiguration.class})
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Autowired
    private AuthenticationProvider authenticationProvider;

    @MockitoBean
    private UserRepository users;

    @Test
    void configuresOnlyTheApplicationProviderWithArgon2() throws Exception {
        var manager = assertInstanceOf(ProviderManager.class, authenticationConfiguration.getAuthenticationManager());

        assertThat(manager.getProviders()).containsExactly(authenticationProvider);
        assertInstanceOf(LoginAuthenticationProvider.class, authenticationProvider);
        assertInstanceOf(Argon2PasswordEncoder.class, encoder);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/login", "/register", "/app"})
    void exposesTheSpaShellWithoutAuthentication(String path) throws Exception {
        mvc.perform(get(path)).andExpect(status().isOk()).andExpect(forwardedUrl("/index.html"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/", "/index.html", "/favicon.svg", "/api/auth/csrf"})
    void exposesPublicResources(String path) throws Exception {
        mvc.perform(get(path)).andExpect(status().isOk());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/auth/me", "/api/private", "/api/auth/register"})
    void protectsApiRequestsOutsideThePublicMethodMappings(String path) throws Exception {
        mvc.perform(get(path))
            .andExpect(status().isUnauthorized())
            .andExpect(header().doesNotExist("Location"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/auth/login", "/api/auth/logout", "/api/auth/register"})
    void rejectsMissingAndInvalidCsrfTokens(String path) throws Exception {
        mvc.perform(post(path)).andExpect(status().isForbidden());
        mvc.perform(post(path).with(csrf().useInvalidToken())).andExpect(status().isForbidden());
        verifyNoInteractions(users);
    }

    @ParameterizedTest
    @ValueSource(strings = {"password123", "  Știință🔒 e\u0301  "})
    void authenticatesThroughTheRealProviderAndPreservesTheSession(String password) throws Exception {
        givenUser(password);

        var result = performFormLogin(formLogin("/api/auth/login")
                .user("email", " ALICE@Example.COM ").password(password))
            .andExpect(status().isNoContent())
            .andExpect(authenticated().withUsername("alice@example.com"))
            .andExpect(content().string(""))
            .andReturn();
        var session = assertInstanceOf(MockHttpSession.class, result.getRequest().getSession(false));
        var context = assertInstanceOf(SecurityContext.class, session.getAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
        var authentication = context.getAuthentication();
        assertNotNull(authentication);
        assertThat(authentication.getCredentials()).isNull();
        var principal = assertInstanceOf(UserDetails.class, authentication.getPrincipal());
        assertThat(principal.getPassword()).isNull();

        mvc.perform(get("/api/auth/me").session(session))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").value("alice@example.com"))
            .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void changesAnExistingSessionIdAtLogin() throws Exception {
        givenUser("password123");
        var session = new MockHttpSession();
        var originalId = session.getId();
        session.setAttribute("preLoginPreference", "value");

        mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded")
                .session(session).with(csrf()).with(request -> {
                    request.setRequestedSessionId(originalId);
                    request.setRequestedSessionIdValid(true);
                    return request;
                })
                .param("email", "alice@example.com").param("password", "password123"))
            .andExpect(status().isNoContent())
            .andExpect(authenticated());

        assertThat(session.getId()).isNotEqualTo(originalId);
        assertThat(session.getAttribute("preLoginPreference")).isEqualTo("value");
    }

    @Test
    void returnsTheSameFailureForAnUnknownAccountAndAnIncorrectPassword() throws Exception {
        givenUser("password123");

        for (var email : new String[]{"alice@example.com", "unknown@example.com"}) {
            performFormLogin(formLogin("/api/auth/login").user("email", email).password("wrong-password"))
                .andExpect(status().isUnauthorized())
                .andExpect(unauthenticated())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.detail").value("Authentication is required or the credentials are invalid."))
                .andExpect(header().doesNotExist("Location"));
            verify(users).findByEmail(email);
        }
    }

    @Test
    void usesTheEmailFormParameterAndDoesNotTreatJsonOrHttpBasicAsFormLogin() throws Exception {
        givenUser("password123");

        performFormLogin(formLogin("/api/auth/login").user("alice@example.com").password("password123"))
            .andExpect(status().isUnauthorized()).andExpect(unauthenticated());
        mvc.perform(post("/api/auth/login").with(csrf()).contentType("application/json")
                .content("{\"email\":\"alice@example.com\",\"password\":\"password123\"}"))
            .andExpect(status().isUnsupportedMediaType()).andExpect(unauthenticated());
        mvc.perform(get("/api/auth/me").with(httpBasic("alice@example.com", "password123")))
            .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 7, 1025, 100000})
    void rejectsOutOfRangePasswordsBeforeAccessingTheRepository(int length) throws Exception {
        performFormLogin(formLogin("/api/auth/login").user("email", "alice@example.com")
                .password("p".repeat(length)))
            .andExpect(status().isUnauthorized())
            .andExpect(unauthenticated());

        verifyNoInteractions(users);
    }

    @Test
    void rejectsOversizedEmailBeforeAccessingTheRepository() throws Exception {
        performFormLogin(formLogin("/api/auth/login").user("email", "a".repeat(255) + "@example.com")
                .password("password123"))
            .andExpect(status().isUnauthorized())
            .andExpect(unauthenticated());

        verifyNoInteractions(users);
    }

    @Test
    void logsOutAndInvalidatesTheAuthenticatedSession() throws Exception {
        givenUser("password123");
        var login = performFormLogin(formLogin("/api/auth/login").user("email", "alice@example.com")
                .password("password123"))
            .andExpect(status().isNoContent()).andReturn();
        var session = assertInstanceOf(MockHttpSession.class, login.getRequest().getSession(false));

        mvc.perform(servletContext -> {
                var request = logout("/api/auth/logout").buildRequest(servletContext);
                request.setSession(session);
                return request;
            })
            .andExpect(status().isNoContent())
            .andExpect(unauthenticated())
            .andExpect(cookie().maxAge("JSESSIONID", 0));

        assertThat(session.isInvalid()).isTrue();
        mvc.perform(get("/api/auth/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void aGetRequestDoesNotLogOutTheSession() throws Exception {
        givenUser("password123");
        var login = performFormLogin(formLogin("/api/auth/login").user("email", "alice@example.com")
                .password("password123"))
            .andExpect(status().isNoContent()).andReturn();
        var session = assertInstanceOf(MockHttpSession.class, login.getRequest().getSession(false));

        mvc.perform(get("/api/auth/logout").session(session)).andExpect(status().isNotFound());

        assertThat(session.isInvalid()).isFalse();
        mvc.perform(get("/api/auth/me").session(session)).andExpect(status().isOk());
    }

    private void givenUser(String password) {
        when(users.findByEmail("alice@example.com"))
            .thenReturn(Optional.of(new User("Alice", "alice@example.com", encoder.encode(password))));
    }

    private ResultActions performFormLogin(FormLoginRequestBuilder login) throws Exception {
        // Spring Security's test builder sets parameters but omits the HTTP form Content-Type.
        return mvc.perform(servletContext -> {
            var request = login.buildRequest(servletContext);
            request.setContentType("application/x-www-form-urlencoded");
            return request;
        });
    }
}
