# Spring SPA Cookie Authentication

A full-stack reference application demonstrating session-based authentication between a first-party React SPA and a Spring Boot API.

The project uses Spring Security, HttpOnly session cookies, CSRF protection, Argon2id password hashing, and PostgreSQL persistence.

## Overview

This repository demonstrates a complete authentication flow using a React single-page application and a Spring Boot backend.

The application includes:

- Spring Boot and Spring Security for authentication and session management
- React, TypeScript, Vite, and Mantine for the frontend
- HttpOnly `JSESSIONID` cookie for server-side sessions
- CSRF protection using the `XSRF-TOKEN` cookie and `X-XSRF-TOKEN` header
- Argon2id for password hashing
- PostgreSQL, Spring Data JPA, and Liquibase for persistence
- Automated backend and frontend tests

The frontend and backend are developed separately within the same repository. The production frontend build is served by Spring Boot.

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

## Scope

This project is intended as an educational and reference implementation, not a production-ready identity provider.

Before public deployment, additional considerations include login and registration rate limiting, HTTPS configuration, secure cookie settings, and deployment-specific infrastructure controls.
