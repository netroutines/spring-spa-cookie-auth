package io.github.netroutines.spacookieauth;

import io.github.netroutines.spacookieauth.auth.dto.RegisterRequest;
import io.github.netroutines.spacookieauth.user.User;
import io.github.netroutines.spacookieauth.user.UserRepository;
import jakarta.persistence.EntityManagerFactory;
import jakarta.servlet.http.Cookie;
import liquibase.integration.spring.SpringLiquibase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.Cookie.SameSite;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.boot.web.server.servlet.Session;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.json.JsonCompareMode;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.json.JsonMapper;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
class SpaCookieAuthApplicationTests {

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
        var registeredUser = storedUser;
        assertNotNull(registeredUser);
        assertThat(registeredUser.getPasswordHash()).startsWith("$argon2id$").isNotEqualTo(password);

        var login = mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded").cookie(beforeLogin)
                .header("X-XSRF-TOKEN", beforeLogin.getValue())
                .param("email", " ALICE@Example.COM ").param("password", password))
            .andExpect(status().isNoContent()).andExpect(content().string(""))
            .andExpect(authenticated().withUsername("alice@example.com")).andReturn();
        var session = assertInstanceOf(MockHttpSession.class, login.getRequest().getSession(false));

        mvc.perform(get("/api/auth/me").session(session))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
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
        var authenticatedSessionId = session.getId();
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
        mvc.perform(get("/api/auth/me").session(session)
                .cookie(new Cookie("JSESSIONID", authenticatedSessionId)))
            .andExpect(status().isUnauthorized()).andExpect(unauthenticated());
        // Cookie CSRF tokens are stateless. Replaying a matching old pair cannot restore authentication.
        mvc.perform(post("/api/private").session(session)
                .cookie(new Cookie("JSESSIONID", authenticatedSessionId), afterLogin)
                .header("X-XSRF-TOKEN", afterLogin.getValue()))
            .andExpect(status().isUnauthorized()).andExpect(unauthenticated());

        var afterLogout = fetchCsrf();
        assertThat(afterLogout.getValue()).isNotEqualTo(afterLogin.getValue());
        mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded").cookie(afterLogout)
                .header("X-XSRF-TOKEN", afterLogin.getValue())
                .param("email", "alice@example.com").param("password", password))
            .andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded").cookie(afterLogout)
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
        var token = json.readTree(response.getContentAsString()).get("token");
        assertNotNull(token);
        var masked = token.asString();
        assertThat(masked).isNotBlank().isNotEqualTo(raw.getValue());

        mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded").cookie(raw).header("X-XSRF-TOKEN", masked)
                .param("email", "alice@example.com").param("password", "password123"))
            .andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded").cookie(raw).param("_csrf", raw.getValue())
                .param("email", "alice@example.com").param("password", "password123"))
            .andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded").cookie(raw)
                .header("X-XSRF-TOKEN", "invalid").param("_csrf", masked)
                .param("email", "alice@example.com").param("password", "password123"))
            .andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded").cookie(raw).param("_csrf", masked)
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
        var originalUser = storedUser;
        assertNotNull(originalUser);
        var originalHash = originalUser.getPasswordHash();

        var result = mvc.perform(post("/api/auth/register").cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue()).contentType("application/json")
                .content(json.writeValueAsString(new RegisterRequest("ALICE@EXAMPLE.COM", "Other", "different-password"))))
            .andExpect(status().isConflict()).andReturn();

        var currentUser = storedUser;
        assertNotNull(currentUser);
        assertThat(currentUser.getPasswordHash()).isEqualTo(originalHash);
        assertThat(result.getResponse().getContentAsString()).doesNotContain(originalHash, "different-password");
    }

    @Test
    void retainsTheCsrfTokenAfterAnUnsuccessfulLogin() throws Exception {
        var csrf = register("password123");

        var result = mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded").cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue())
                .param("email", "alice@example.com").param("password", "wrong-password"))
            .andExpect(status().isUnauthorized()).andReturn();

        assertThat(result.getResponse().getCookies())
            .noneSatisfy(cookie -> {
                assertThat(cookie.getName()).isEqualTo("XSRF-TOKEN");
                assertThat(cookie.getMaxAge()).isZero();
            });
        mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded").cookie(csrf)
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

    @Test
    void ignoresUnknownRegistrationFieldsWithoutGrantingAuthorityOrChangingTheId() throws Exception {
        var csrf = fetchCsrf();
        mvc.perform(post("/api/auth/register").cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                .contentType("application/json").content("""
                    {"email":"alice@example.com","password":"secret-password","id":1,
                     "roles":["ADMIN"],"passwordHash":"attacker-controlled","enabled":true}
                    """))
            .andExpect(status().isCreated())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(content().json("""
                {"email":"alice@example.com","status":"registered"}
                """, JsonCompareMode.STRICT));
        var registeredUser = storedUser;
        assertNotNull(registeredUser);
        assertThat(registeredUser.getId()).isEqualTo(42L);

        var result = mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded")
                .cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                .param("email", "alice@example.com").param("password", "secret-password"))
            .andExpect(status().isNoContent()).andExpect(authenticated().withRoles("USER")).andReturn();
        var session = assertInstanceOf(MockHttpSession.class, result.getRequest().getSession(false));
        var securityContext = assertInstanceOf(SecurityContext.class,
            session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
        var authentication = securityContext.getAuthentication();
        assertNotNull(authentication);
        var principal = assertInstanceOf(UserDetails.class, authentication.getPrincipal());
        assertThat(principal.getPassword()).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"<script>alert('x')</script>", "Robert'); DROP TABLE users;--"})
    void treatsDisplayNamesAsJsonDataWithoutInterpretingMarkupOrSql(String name) throws Exception {
        var csrf = fetchCsrf();
        mvc.perform(post("/api/auth/register").cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                .contentType("application/json")
                .content(json.writeValueAsString(new RegisterRequest("alice@example.com", name, "secret-password"))))
            .andExpect(status().isCreated())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(content().json("""
                {"email":"alice@example.com","status":"registered"}
                """, JsonCompareMode.STRICT));
        var user = storedUser;
        assertNotNull(user);
        assertThat(user.getName()).isEqualTo(name);

        var login = mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded")
                .cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                .param("email", "alice@example.com").param("password", "secret-password"))
            .andExpect(status().isNoContent()).andExpect(authenticated()).andReturn();
        var session = assertInstanceOf(MockHttpSession.class, login.getRequest().getSession(false));
        mvc.perform(get("/api/auth/me").session(session))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(header().string("X-Content-Type-Options", "nosniff"))
            .andExpect(jsonPath("$.name").value(name));
    }

    @Test
    void doesNotRestoreAuthenticationFromAnInvalidatedSessionOrItsOldCookie() throws Exception {
        var csrf = register("secret-password");
        var result = mvc.perform(post("/api/auth/login").contentType("application/x-www-form-urlencoded")
                .cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                .param("email", "alice@example.com").param("password", "secret-password"))
            .andExpect(status().isNoContent()).andReturn();
        var session = assertInstanceOf(MockHttpSession.class, result.getRequest().getSession(false));
        var oldId = session.getId();
        // Simulate container invalidation at timeout; MockMvc itself does not run an expiry timer.
        session.invalidate();

        mvc.perform(get("/api/auth/me").session(session).cookie(new Cookie("JSESSIONID", oldId)))
            .andExpect(status().isUnauthorized()).andExpect(unauthenticated());
        assertThat(session.isInvalid()).isTrue();
    }

    private Cookie register(String password) throws Exception {
        var csrf = fetchCsrf();
        var result = mvc.perform(post("/api/auth/register").cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue()).contentType("application/json")
                .content(json.writeValueAsString(new RegisterRequest(" ALICE@Example.COM ", null, password))))
            .andExpect(status().isCreated())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(content().json("""
                {"email":"alice@example.com","status":"registered"}
                """, JsonCompareMode.STRICT))
            .andExpect(unauthenticated())
            .andExpect(header().doesNotExist("Location"))
            .andReturn();
        assertThat(result.getResponse().getContentAsString()).doesNotContain(password, "passwordHash", "$argon2id$");
        return csrf;
    }

    private Cookie fetchCsrf() throws Exception {
        var result = mvc.perform(get("/api/auth/csrf").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(cookie().httpOnly("XSRF-TOKEN", false))
            .andExpect(cookie().path("XSRF-TOKEN", "/"))
            .andReturn();
        assertThat(result.getResponse().getHeader("Cache-Control")).contains("no-store");
        var token = result.getResponse().getCookie("XSRF-TOKEN");
        assertNotNull(token);
        assertThat(token.getValue()).isNotBlank();
        return token;
    }
}
