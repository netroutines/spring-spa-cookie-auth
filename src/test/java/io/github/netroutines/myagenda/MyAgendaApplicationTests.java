package io.github.netroutines.myagenda;

import io.github.netroutines.myagenda.auth.dto.RegisterRequest;
import io.github.netroutines.myagenda.user.User;
import io.github.netroutines.myagenda.user.UserRepository;
import jakarta.persistence.EntityManagerFactory;
import jakarta.servlet.http.Cookie;
import liquibase.integration.spring.SpringLiquibase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.Cookie.SameSite;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.boot.web.server.servlet.Session;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.json.JsonMapper;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class MyAgendaApplicationTests {

    // Use actual CSRF cookies here. csrf() and formLogin() replace the filter's token repository.

    @Autowired
    private ApplicationContext context;

    @Autowired
    private MockMvc mvc;

    @Autowired
    private JsonMapper json;

    @Autowired
    private ServerProperties serverProperties;

    @MockitoBean
    private UserRepository users;

    private User storedUser;

    @BeforeEach
    void createAnIsolatedRepository() {
        when(users.existsByEmail(anyString())).thenAnswer(invocation ->
            storedUser != null && storedUser.getEmail().equals(invocation.getArgument(0)));
        when(users.findByEmail(anyString())).thenAnswer(invocation ->
            Optional.ofNullable(storedUser).filter(user -> user.getEmail().equals(invocation.getArgument(0))));
        when(users.saveAndFlush(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            ReflectionTestUtils.setField(user, "id", 42L);
            storedUser = user;
            return user;
        });
    }

    @Test
    void startsTheRealApplicationWithNoDatabaseInfrastructure() {
        assertThat(context.getBeansOfType(DataSource.class)).isEmpty();
        assertThat(context.getBeansOfType(EntityManagerFactory.class)).isEmpty();
        assertThat(context.getBeansOfType(SpringLiquibase.class)).isEmpty();
        assertThat(mockingDetails(users).isMock()).isTrue();
        assertThat(context.getEnvironment().getProperty("spring.datasource.url")).isEqualTo("jdbc:disabled:tests");
        assertThat(context.getEnvironment().getProperty("spring.datasource.password")).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("passwords")
    void registersLogsInReadsTheUserAndLogsOutUsingRealCsrfCookies(String password) throws Exception {
        var beforeLogin = register(password);
        mvc.perform(get("/api/auth/me")).andExpect(status().isUnauthorized());
        assertThat(storedUser.getPasswordHash()).startsWith("$argon2id$").isNotEqualTo(password);

        var login = mvc.perform(post("/api/auth/login").cookie(beforeLogin)
                .header("X-XSRF-TOKEN", beforeLogin.getValue())
                .param("email", " ALICE@Example.COM ").param("password", password))
            .andExpect(status().isNoContent()).andExpect(content().string(""))
            .andExpect(authenticated().withUsername("alice@example.com")).andReturn();
        var session = (MockHttpSession) login.getRequest().getSession(false);
        assertThat(session).isNotNull();

        mvc.perform(get("/api/auth/me").session(session))
            .andExpect(status().isOk())
            .andExpect(content().json("""
                {"id":42,"email":"alice@example.com","name":"alice"}
                """))
            .andExpect(jsonPath("$.password").doesNotExist())
            .andExpect(jsonPath("$.passwordHash").doesNotExist());

        var afterLogin = Arrays.stream(login.getResponse().getCookies())
            .filter(cookie -> cookie.getName().equals("XSRF-TOKEN"))
            .reduce((_, current) -> current).orElseThrow();
        assertThat(afterLogin.getValue()).isNotBlank();
        assertThat(afterLogin.getMaxAge()).isNotZero();
        assertThat(afterLogin.getValue()).isNotEqualTo(beforeLogin.getValue());
        mvc.perform(post("/api/auth/logout").session(session).cookie(afterLogin)
                .header("X-XSRF-TOKEN", beforeLogin.getValue()))
            .andExpect(status().isForbidden());
        mvc.perform(get("/api/auth/me").session(session)).andExpect(status().isOk());

        mvc.perform(post("/api/auth/logout").session(session).cookie(afterLogin)
                .header("X-XSRF-TOKEN", afterLogin.getValue()))
            .andExpect(status().isNoContent()).andExpect(unauthenticated())
            .andExpect(cookie().maxAge("JSESSIONID", 0))
            .andExpect(cookie().maxAge("XSRF-TOKEN", 0));
        assertThat(session.isInvalid()).isTrue();
        mvc.perform(get("/api/auth/me")).andExpect(status().isUnauthorized());

        var afterLogout = fetchCsrf();
        assertThat(afterLogout.getValue()).isNotEqualTo(afterLogin.getValue());
        mvc.perform(post("/api/auth/login").cookie(afterLogout)
                .header("X-XSRF-TOKEN", afterLogin.getValue())
                .param("email", "alice@example.com").param("password", password))
            .andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/login").cookie(afterLogout)
                .header("X-XSRF-TOKEN", afterLogout.getValue())
                .param("email", "alice@example.com").param("password", password))
            .andExpect(status().isNoContent()).andExpect(authenticated());
    }

    static Stream<String> passwords() {
        return Stream.of("12345678", "  Știință🔒".repeat(12) + " e\u0301  ", "🔒".repeat(512));
    }

    @Test
    void acceptsMaskedFormTokensAndRejectsUsingThemAsSpaHeaders() throws Exception {
        var raw = register("password123");
        var response = mvc.perform(get("/api/auth/csrf").cookie(raw))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.headerName").value("X-XSRF-TOKEN"))
            .andExpect(jsonPath("$.parameterName").value("_csrf"))
            .andReturn().getResponse();
        var masked = json.readTree(response.getContentAsString()).get("token").asString();
        assertThat(masked).isNotBlank().isNotEqualTo(raw.getValue());

        mvc.perform(post("/api/auth/login").cookie(raw).header("X-XSRF-TOKEN", masked)
                .param("email", "alice@example.com").param("password", "password123"))
            .andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/login").cookie(raw).param("_csrf", raw.getValue())
                .param("email", "alice@example.com").param("password", "password123"))
            .andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/login").cookie(raw).param("_csrf", masked)
                .param("email", "alice@example.com").param("password", "password123"))
            .andExpect(status().isNoContent()).andExpect(authenticated());
    }

    @Test
    void requiresBothTheCsrfCookieAndAMatchingHeader() throws Exception {
        var raw = fetchCsrf();
        mvc.perform(post("/api/auth/register").cookie(raw).contentType("application/json").content("{}"))
            .andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/register").cookie(raw).header("X-XSRF-TOKEN", "invalid")
                .contentType("application/json").content("{}"))
            .andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/register").header("X-XSRF-TOKEN", raw.getValue())
                .contentType("application/json").content("{}"))
            .andExpect(status().isForbidden());
        assertThat(storedUser).isNull();
    }

    @Test
    void returnsConflictForARepeatedRegistration() throws Exception {
        var csrf = register("password123");
        var originalHash = storedUser.getPasswordHash();

        var result = mvc.perform(post("/api/auth/register").cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue()).contentType("application/json")
                .content(json.writeValueAsString(new RegisterRequest("ALICE@EXAMPLE.COM", "Other", "different-password"))))
            .andExpect(status().isConflict()).andReturn();

        assertThat(storedUser.getPasswordHash()).isEqualTo(originalHash);
        assertThat(result.getResponse().getContentAsString()).doesNotContain(originalHash, "different-password");
    }

    @Test
    void retainsTheCsrfTokenAfterAnUnsuccessfulLogin() throws Exception {
        var csrf = register("password123");

        var result = mvc.perform(post("/api/auth/login").cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue())
                .param("email", "alice@example.com").param("password", "wrong-password"))
            .andExpect(status().isUnauthorized()).andReturn();

        assertThat(result.getResponse().getCookies())
            .noneSatisfy(cookie -> {
                assertThat(cookie.getName()).isEqualTo("XSRF-TOKEN");
                assertThat(cookie.getMaxAge()).isZero();
            });
        mvc.perform(post("/api/auth/login").cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue())
                .param("email", "alice@example.com").param("password", "password123"))
            .andExpect(status().isNoContent()).andExpect(authenticated());
    }

    @Test
    void bindsTheApplicationsSessionCookieAndTimeoutSettings() {
        var session = serverProperties.getServlet().getSession();

        assertThat(session.getTimeout()).isEqualTo(Duration.ofMinutes(30));
        assertThat(session.getCookie().getHttpOnly()).isTrue();
        assertThat(session.getCookie().getSameSite()).isEqualTo(SameSite.LAX);
        assertThat(session.getTrackingModes()).containsExactly(Session.SessionTrackingMode.COOKIE);
    }

    @Test
    void marksTheSpaCsrfCookieSecureOnHttpsRequests() throws Exception {
        mvc.perform(get("/api/auth/csrf").secure(true))
            .andExpect(status().isOk())
            .andExpect(cookie().secure("XSRF-TOKEN", true))
            .andExpect(cookie().httpOnly("XSRF-TOKEN", false));
    }

    private Cookie register(String password) throws Exception {
        var csrf = fetchCsrf();
        var result = mvc.perform(post("/api/auth/register").cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue()).contentType("application/json")
                .content(json.writeValueAsString(new RegisterRequest(" ALICE@Example.COM ", null, password))))
            .andExpect(status().isCreated()).andReturn();
        assertThat(result.getResponse().getContentAsString()).doesNotContain(password, "passwordHash", "$argon2id$");
        return csrf;
    }

    private Cookie fetchCsrf() throws Exception {
        var result = mvc.perform(get("/api/auth/csrf"))
            .andExpect(status().isOk())
            .andExpect(cookie().httpOnly("XSRF-TOKEN", false))
            .andExpect(cookie().path("XSRF-TOKEN", "/"))
            .andReturn();
        assertThat(result.getResponse().getHeader("Cache-Control")).contains("no-store");
        var token = result.getResponse().getCookie("XSRF-TOKEN");
        assertThat(token).isNotNull();
        assertThat(token.getValue()).isNotBlank();
        return token;
    }
}
