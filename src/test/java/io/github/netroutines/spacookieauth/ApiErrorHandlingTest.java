package io.github.netroutines.spacookieauth;

import io.github.netroutines.spacookieauth.user.User;
import io.github.netroutines.spacookieauth.user.UserRepository;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.RequestDispatcher;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.JdbcSettings;
import org.hibernate.engine.jdbc.connections.spi.ConnectionProvider;
import org.hibernate.engine.jdbc.env.spi.JdbcEnvironment;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.env.Environment;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.sql.SQLException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@ExtendWith(OutputCaptureExtension.class)
class ApiErrorHandlingTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private Environment environment;

    @MockitoBean
    private UserRepository users;

    @Test
    void anonymousApiRequestsReceiveJsonEvenWhenHtmlIsRequested() throws Exception {
        assertProblem(mvc.perform(get("/api/auth/me").accept(MediaType.TEXT_HTML)), 401);
        assertProblem(mvc.perform(get("/api/unknown").accept(MediaType.TEXT_HTML)), 401);
        verifyNoInteractions(users);
    }

    @Test
    void csrfFailuresFromTheFilterAreJsonWithoutAnErrorDispatch() throws Exception {
        var result = assertProblem(mvc.perform(post("/api/auth/register").accept(MediaType.TEXT_HTML)), 403)
            .andReturn();
        assertThat(result.getResponse().getErrorMessage()).isNull();
        verifyNoInteractions(users);
    }

    @ParameterizedTest
    @ValueSource(strings = {"application/json", "text/html", "*/*"})
    void unknownAuthenticatedApiRoutesNeverForwardToTheSpa(String accept) throws Exception {
        var result = assertProblem(mvc.perform(get("/api/does-not-exist")
            .with(user("alice@example.com")).accept(accept)), 404).andReturn();
        assertThat(result.getResponse().getForwardedUrl()).isNull();
        assertThat(result.getResponse().getContentAsString()).doesNotContain("<html", "index.html");
    }

    @Test
    void unsupportedMethodsRetainTheAllowHeader() throws Exception {
        assertProblem(mvc.perform(get("/api/auth/register").with(user("alice@example.com"))), 405)
            .andExpect(header().string("Allow", "POST"));
    }

    @Test
    void unsupportedRegistrationMediaTypesReturnJson() throws Exception {
        assertProblem(mvc.perform(withCsrf(post("/api/auth/register"))
            .contentType(MediaType.TEXT_PLAIN).content("private-request-body")), 415)
            .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("private-request-body"))));
        verifyNoInteractions(users);
    }

    @Test
    void duplicateRegistrationIsAJsonConflict() throws Exception {
        when(users.existsByEmail("alice@example.com")).thenReturn(true);

        assertProblem(mvc.perform(withCsrf(post("/api/auth/register"))
            .contentType(MediaType.APPLICATION_JSON).content(validRegistration())), 409);

        verify(users, never()).saveAndFlush(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{", "{\"email\":\"invalid\",\"password\":\"secret-password\"}"})
    void invalidBodiesHaveSanitizedJsonErrors(String body, CapturedOutput output) throws Exception {
        var result = assertProblem(mvc.perform(withCsrf(post("/api/auth/register"))
            .contentType(MediaType.APPLICATION_JSON).content(body)), 400).andReturn();

        assertThat(result.getResponse().getContentAsString()).doesNotContain("secret-password", "rejectedValue");
        assertThat(output.getAll()).doesNotContain("secret-password");
        verifyNoInteractions(users);
    }

    @Test
    void unexpectedPersistenceErrorsDoNotExposeDatabaseDetails(CapturedOutput output) throws Exception {
        when(users.existsByEmail(anyString()))
            .thenThrow(new DataAccessResourceFailureException("private-database-detail SELECT password FROM users"));

        var result = assertProblem(mvc.perform(withCsrf(post("/api/auth/register"))
            .contentType(MediaType.APPLICATION_JSON).content(validRegistration())), 500).andReturn();

        assertThat(result.getResponse().getContentAsString()).doesNotContain("private-database-detail", "SELECT", "password");
        assertThat(output.getAll()).doesNotContain("private-database-detail", "SELECT password");
    }

    @Test
    void loginInfrastructureFailuresAreNotReportedAsBadCredentialsOrLoggedWithSecrets(CapturedOutput output) throws Exception {
        when(users.findByEmail(anyString()))
            .thenThrow(new DataAccessResourceFailureException("private-database-detail stored-hash-value"));

        var result = assertProblem(mvc.perform(withCsrf(post("/api/auth/login"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("email", "alice@example.com").param("password", "secret-password")), 500).andReturn();

        assertThat(result.getResponse().getContentAsString())
            .doesNotContain("private-database-detail", "stored-hash-value", "secret-password");
        assertThat(output.getAll()).doesNotContain("private-database-detail", "stored-hash-value", "secret-password");
    }

    @ParameterizedTest
    @ValueSource(strings = {"12345678", "true", "[]", "{}"})
    void rejectsNonStringPasswordsWithoutCoercion(String password) throws Exception {
        assertProblem(mvc.perform(withCsrf(post("/api/auth/register"))
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"email\":\"alice@example.com\",\"password\":" + password + "}")), 400);
        verifyNoInteractions(users);
    }

    @Test
    void rejectsJsonLoginEvenWhenCredentialsAreSuppliedAsQueryParameters() throws Exception {
        givenExistingUser();
        assertProblem(mvc.perform(withCsrf(post("/api/auth/login"))
            .contentType(MediaType.APPLICATION_JSON).content("{}")
            .queryParam("email", "alice@example.com").queryParam("password", "secret-password")), 415);
        verifyNoInteractions(users);
    }

    @Test
    void rejectsAmbiguousRepeatedLoginFields() throws Exception {
        givenExistingUser();
        assertProblem(mvc.perform(withCsrf(post("/api/auth/login"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("email", "alice@example.com", "other@example.com")
            .param("password", "secret-password")), 400);
        assertProblem(mvc.perform(withCsrf(post("/api/auth/login"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("email", "alice@example.com")
            .param("password", "secret-password", "other-password")), 400);
        verifyNoInteractions(users);
    }

    @Test
    void rejectsFormCredentialsInTheUrlBeforeLookingUpTheUser() throws Exception {
        givenExistingUser();
        assertProblem(mvc.perform(withCsrf(post("/api/auth/login"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .queryParam("email", "alice@example.com").queryParam("password", "secret-password")), 400);
        verifyNoInteractions(users);
    }

    @ParameterizedTest
    @ValueSource(strings = {"uk_users_email", "another_constraint"})
    void classifiesConcurrentAndUnrelatedIntegrityFailuresWithoutDisclosingRows(String constraint, CapturedOutput output)
        throws Exception {
        var cause = new ConstraintViolationException("private-database-detail",
            new SQLException("failing row contains private-hash-value", "23505"), constraint);
        when(users.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("insert failed", cause));
        var expectedStatus = constraint.equals("uk_users_email") ? 409 : 500;

        var result = assertProblem(mvc.perform(withCsrf(post("/api/auth/register"))
            .contentType(MediaType.APPLICATION_JSON).content(validRegistration())), expectedStatus).andReturn();

        assertThat(result.getResponse().getContentAsString()).doesNotContain("private-database-detail", "private-hash-value");
        assertThat(output.getAll()).doesNotContain("private-database-detail", "private-hash-value");
    }

    @Test
    void rejectsAPathBlockedByTheSecurityFirewallBeforeCallingTheRepository() throws Exception {
        // A real container subsequently dispatches sendError to our /error endpoint (tested separately).
        mvc.perform(get("/api/auth/me;unexpected=1")).andExpect(status().isBadRequest());
        verifyNoInteractions(users);
    }

    @Test
    void hibernateDoesNotLogSensitiveJdbcErrorsBeforeApplicationHandlersCanSanitizeThem(CapturedOutput output)
        throws Exception {
        // Build only Hibernate's JDBC services, with metadata disabled and no usable connection provider.
        var connections = mock(ConnectionProvider.class);
        var registry = new StandardServiceRegistryBuilder()
            .applySetting(JdbcSettings.ALLOW_METADATA_ON_BOOT, false)
            .applySetting("jakarta.persistence.database-product-name", "PostgreSQL")
            .applySetting("jakarta.persistence.database-major-version", 17)
            .applySetting("jakarta.persistence.database-minor-version", 0)
            .applySetting(JdbcSettings.CONNECTION_PROVIDER, connections)
            .applySetting(JdbcSettings.LOG_JDBC_ERRORS,
                environment.getProperty("spring.jpa.properties.hibernate.jdbc.log.errors", "true"))
            .build();
        try {
            var jdbc = registry.getService(JdbcEnvironment.class);
            assertNotNull(jdbc);
            var cause = new SQLException("private-row-data private-password-hash", "22001");
            var converted = jdbc.getSqlExceptionHelper().convert(cause, "Insert failed", "insert into users values (?)");

            assertSame(cause, converted.getSQLException());
            assertThat(output.getAll()).doesNotContain("private-row-data", "private-password-hash");
            verify(connections, never()).getConnection();
        } finally {
            StandardServiceRegistryBuilder.destroy(registry);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 403, 404, 500})
    void servletErrorDispatchesProduceSanitizedJsonEvenForHtmlClients(int status) throws Exception {
        // MockMvc does not dispatch container errors automatically. Exercise that entry point explicitly.
        var result = assertProblem(mvc.perform(get("/error").with(request -> {
                request.setDispatcherType(DispatcherType.ERROR);
                return request;
            })
            .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, status)
            .requestAttr(RequestDispatcher.ERROR_REQUEST_URI, "/api/unknown")
            .requestAttr(RequestDispatcher.ERROR_MESSAGE, "private-error-message")
            .requestAttr(RequestDispatcher.ERROR_EXCEPTION, new IllegalStateException("private-exception"))
            .accept(MediaType.TEXT_HTML)), status).andReturn();

        assertThat(result.getResponse().getContentAsString())
            .doesNotContain("private-error-message", "private-exception", "<html", "stackTrace");
    }

    private MockHttpServletRequestBuilder withCsrf(MockHttpServletRequestBuilder request) throws Exception {
        var cookie = mvc.perform(get("/api/auth/csrf")).andReturn().getResponse().getCookie("XSRF-TOKEN");
        assertNotNull(cookie);
        return request.cookie(cookie).header("X-XSRF-TOKEN", cookie.getValue());
    }

    private ResultActions assertProblem(ResultActions result, int status) throws Exception {
        return result.andExpect(status().is(status))
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.status").value(status))
            .andExpect(jsonPath("$.type").value("about:blank"))
            .andExpect(jsonPath("$.title").isNotEmpty())
            .andExpect(jsonPath("$.detail").isNotEmpty())
            .andExpect(jsonPath("$.trace").doesNotExist())
            .andExpect(jsonPath("$.exception").doesNotExist());
    }

    private String validRegistration() {
        return """
            {"email":"alice@example.com","password":"secret-password"}
            """;
    }

    private void givenExistingUser() {
        when(users.findByEmail("alice@example.com"))
            .thenReturn(Optional.of(new User("Alice", "alice@example.com", encoder.encode("secret-password"))));
    }
}
