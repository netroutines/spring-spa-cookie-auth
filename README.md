# Spring SPA Cookie Authentication

<p>
  <a href="https://github.com/netroutines/spring-spa-cookie-auth/actions/workflows/tests.yaml">
    <img src="https://github.com/netroutines/spring-spa-cookie-auth/actions/workflows/tests.yaml/badge.svg?branch=main&event=push" alt="CI Status">
  </a>
</p>

A full-stack reference application demonstrating session-based authentication between a first-party React SPA and a Spring Boot API.

The project uses Spring Security, HttpOnly session cookies, CSRF protection, Argon2id password hashing, Liquibase, and either PostgreSQL or an H2 in-memory database.

## Overview

This repository demonstrates a complete authentication flow using a React single-page application and a Spring Boot backend.

The application includes:

- Spring Boot and Spring Security for authentication and session management
- React, TypeScript, Vite, and Mantine for the frontend
- HttpOnly `JSESSIONID` cookie for server-side sessions
- CSRF protection using the `XSRF-TOKEN` cookie and `X-XSRF-TOKEN` header
- Argon2id for password hashing
- PostgreSQL or H2 in-memory for persistence
- Spring Data JPA, Hibernate, and Liquibase for database access and schema migrations
- Automated backend and frontend tests

The frontend and backend are developed separately within the same repository. The production frontend build is served by Spring Boot.

## Getting Started

### Requirements

- Java 25
- PostgreSQL (optional; not required for the in-memory demo)
- Node.js and npm (only required to rebuild or develop the frontend)

The Maven Wrapper is included, so a separate Maven installation is not required.

### Option 1: H2 In-Memory Database (Recommended for Quick Testing)

Start the application using the `demo` profile:

```powershell
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=demo"
```

Open http://localhost:8080 in your browser.

The demo profile uses an embedded H2 database and does not require PostgreSQL, database installation, or environment variables.

Liquibase creates the database schema automatically when the application starts. Hibernate validates the resulting schema.

**Important:** All registered accounts and other database records are temporary and are lost when the application process stops.

The demo server binds to `127.0.0.1` and is intended for local use only.

### Option 2: PostgreSQL

The default configuration uses PostgreSQL.

Create a PostgreSQL database and user of your choice. Configure the following environment variables to match your PostgreSQL setup:

- `DB_NAME`: PostgreSQL database name
- `DB_USERNAME`: PostgreSQL username
- `DB_PASSWORD`: PostgreSQL user password

In Windows PowerShell, configure the database name and username, then enter the password without exposing it in the command history:

```powershell
$env:DB_NAME = "your_database"
$env:DB_USERNAME = "your_username"

$securePassword = Read-Host "PostgreSQL password" -AsSecureString
$env:DB_PASSWORD = [System.Net.NetworkCredential]::new("", $securePassword).Password
```

Start the application:

```powershell
.\mvnw.cmd spring-boot:run
```

Open http://localhost:8080 in your browser.

Liquibase manages the database schema, while Hibernate validates it using `spring.jpa.hibernate.ddl-auto=validate`.

The PostgreSQL database persists registered accounts across application restarts.

### Database Configuration

| Feature | PostgreSQL | H2 In-Memory |
|---|---|---|
| Spring profile | Default | `demo` |
| External database required | Yes | No |
| Liquibase migrations | Yes | Yes |
| Hibernate schema validation | Yes | Yes |
| Data persists after shutdown | Yes | No |
| Intended use | Persistent local development | Quick local demonstrations |

Both profiles use the same application code, authentication endpoints, and Spring Security configuration.

H2 uses PostgreSQL compatibility mode, but it does not reproduce every PostgreSQL-specific behavior. PostgreSQL remains the reference database for database-specific behavior.

## Authentication Flow

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/auth/csrf` | Obtain CSRF token information and cookie |
| `POST` | `/api/auth/register` | Register an account without automatically signing in |
| `POST` | `/api/auth/login` | Authenticate and establish an HTTP session |
| `GET` | `/api/auth/me` | Retrieve the current authenticated user |
| `POST` | `/api/auth/logout` | Invalidate the authenticated session |

Registration accepts JSON. Login uses `application/x-www-form-urlencoded` and returns `204 No Content` on success.

API errors use sanitized `application/problem+json` responses.

## Security Model

Authentication state is maintained server-side. The browser receives an HttpOnly session cookie, while CSRF tokens protect state-changing requests.

The SPA uses same-origin API requests. During development, Vite can proxy API requests to Spring Boot.

The implementation includes session fixation protection, session invalidation on logout, credential validation, and regression tests for authentication and CSRF behavior.

## Build and Tests

Run the backend tests and package the application:

```powershell
.\mvnw.cmd clean verify
```

The executable Spring Boot JAR is generated at:

```text
target/spring-spa-cookie-auth-0.0.1-SNAPSHOT.jar
```

To rebuild the frontend, run the following commands from `src/main/frontend`:

```powershell
npm ci
npm run lint
npm run test
npm run build
```

The frontend build is written to `src/main/resources/static` and is served by Spring Boot.

When changing frontend source files, rebuild the frontend before packaging the Spring Boot JAR.

To run the packaged application with H2:

```powershell
java -jar .\target\spring-spa-cookie-auth-0.0.1-SNAPSHOT.jar --spring.profiles.active=demo
```

To run it with the default PostgreSQL configuration:

```powershell
java -jar .\target\spring-spa-cookie-auth-0.0.1-SNAPSHOT.jar
```

The PostgreSQL configuration requires a working database connection and the `DB_NAME`, `DB_USERNAME`, and `DB_PASSWORD` environment variables.

## Scope

This project is intended as an educational and reference implementation, not a production-ready identity provider.

Before public deployment, additional considerations include login and registration rate limiting, HTTPS configuration, secure cookie settings, and deployment-specific infrastructure controls.

The H2 profile is intended exclusively for local demonstrations. PostgreSQL should be used when validating PostgreSQL-specific behavior.
