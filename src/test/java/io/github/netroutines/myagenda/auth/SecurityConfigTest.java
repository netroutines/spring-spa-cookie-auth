package io.github.netroutines.myagenda.auth;

import io.github.netroutines.myagenda.SpaController;
import io.github.netroutines.myagenda.user.User;
import io.github.netroutines.myagenda.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
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
@Import({SecurityConfig.class, AuthService.class})
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PasswordEncoder encoder;

    @MockitoBean
    private UserRepository users;

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

        var result = mvc.perform(formLogin("/api/auth/login")
                .user("email", " ALICE@Example.COM ").password(password))
            .andExpect(status().isNoContent())
            .andExpect(authenticated().withUsername("alice@example.com"))
            .andExpect(content().string(""))
            .andReturn();
        var session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session).isNotNull();
        var context = (SecurityContext) session.getAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertThat(context.getAuthentication().getCredentials()).isNull();
        assertThat(((UserDetails) context.getAuthentication().getPrincipal()).getPassword()).isNull();

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

        mvc.perform(post("/api/auth/login").session(session).with(csrf()).with(request -> {
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
            mvc.perform(formLogin("/api/auth/login").user("email", email).password("wrong-password"))
                .andExpect(status().isUnauthorized())
                .andExpect(unauthenticated())
                .andExpect(content().string(""))
                .andExpect(header().doesNotExist("Location"));
            verify(users).findByEmail(email);
        }
    }

    @Test
    void usesTheEmailFormParameterAndDoesNotTreatJsonOrHttpBasicAsFormLogin() throws Exception {
        mvc.perform(formLogin("/api/auth/login").user("alice@example.com").password("password123"))
            .andExpect(status().isUnauthorized()).andExpect(unauthenticated());
        mvc.perform(post("/api/auth/login").with(csrf()).contentType("application/json")
                .content("{\"email\":\"alice@example.com\",\"password\":\"password123\"}"))
            .andExpect(status().isUnauthorized()).andExpect(unauthenticated());
        mvc.perform(get("/api/auth/me").with(httpBasic("alice@example.com", "password123")))
            .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 7, 1025, 100000})
    void rejectsOutOfRangePasswordsBeforeAccessingTheRepository(int length) throws Exception {
        mvc.perform(formLogin("/api/auth/login").user("email", "alice@example.com")
                .password("p".repeat(length)))
            .andExpect(status().isUnauthorized())
            .andExpect(unauthenticated());

        verifyNoInteractions(users);
    }

    @Test
    void rejectsOversizedEmailBeforeAccessingTheRepository() throws Exception {
        mvc.perform(formLogin("/api/auth/login").user("email", "a".repeat(255) + "@example.com")
                .password("password123"))
            .andExpect(status().isUnauthorized())
            .andExpect(unauthenticated());

        verifyNoInteractions(users);
    }

    @Test
    void logsOutAndInvalidatesTheAuthenticatedSession() throws Exception {
        givenUser("password123");
        var login = mvc.perform(formLogin("/api/auth/login").user("email", "alice@example.com")
                .password("password123"))
            .andExpect(status().isNoContent()).andReturn();
        var session = (MockHttpSession) login.getRequest().getSession(false);

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
        var login = mvc.perform(formLogin("/api/auth/login").user("email", "alice@example.com")
                .password("password123"))
            .andExpect(status().isNoContent()).andReturn();
        var session = (MockHttpSession) login.getRequest().getSession(false);

        mvc.perform(get("/api/auth/logout").session(session)).andExpect(status().isNotFound());

        assertThat(session.isInvalid()).isFalse();
        mvc.perform(get("/api/auth/me").session(session)).andExpect(status().isOk());
    }

    private void givenUser(String password) {
        when(users.findByEmail("alice@example.com"))
            .thenReturn(Optional.of(new User("Alice", "alice@example.com", encoder.encode(password))));
    }
}
