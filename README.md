<img width="970" height="110" alt="better-goth-banner" src="https://github.com/user-attachments/assets/9734aace-9180-4526-baea-ba235731d24b" />

<div align="center">
  <a href="https://github.com/Protofarm/better-goth/stargazers" target="_blank">
    <img src="https://img.shields.io/github/stars/Protofarm/better-goth.svg?style=social&label=Star" alt="GitHub stars" />
  </a>
  <a href="https://goreportcard.com/report/github.com/Protofarm/better-goth" target="_blank">
    <img src="https://goreportcard.com/badge/github.com/Protofarm/better-goth" alt="Go Report Card" />
  </a>
  <a href="https://pkg.go.dev/github.com/Protofarm/better-goth" target="_blank">
    <img src="https://pkg.go.dev/badge/github.com/Protofarm/better-goth.svg" alt="Go Reference" />
  </a>
  <a href="https://github.com/Protofarm/better-goth/blob/main/LICENSE" target="_blank">
    <img src="https://img.shields.io/github/license/Protofarm/better-goth.svg" alt="License" />
  </a>
</div>


---

### 👀 Overview

Better Goth is a better-auth alternative, written purely in Go. It provides a complete OAuth 2.1 and OpenID Connect implementation as an embeddable library, giving you full control over your authentication flow without external dependencies or managed services.

---

### ✅ Standards & Compliance

Better Goth implements the following OAuth 2.0 and OpenID Connect RFCs:

- **[RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)** – OAuth 2.0 Authorization Framework. The core protocol for delegated authorization, enabling secure token-based access.
- **[OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)** – OAuth 2.1 Authorization Framework. The next-generation OAuth specification with security improvements and best practices baked in.
- **[RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)** – OAuth 2.0 Token Revocation. Endpoints to revoke access and refresh tokens, ensuring users can log out and invalidate sessions.
- **[RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)** – JSON Web Key (JWK). Support for public key distribution via JWKS endpoints, enabling clients to verify token signatures.
- **[RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)** – SAML 2.0 Bearer Assertion Profile for OAuth 2.0 Client Authentication. Implements `private_key_jwt` client authentication for high-security token exchanges.
- **[RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)** – OAuth 2.0 Dynamic Client Registration Protocol. Endpoints for programmatic client registration without manual setup.
- **[RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)** – OAuth 2.0 Token Introspection. Endpoints to validate and inspect token claims, useful for API gateways and resource servers.
- **[RFC 9560](https://datatracker.ietf.org/doc/html/rfc9560)** – OpenID Connect Federation 1.0. Support for federated identity across multiple issuers.
- **[RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700)** – OpenID Connect Core 1.0. Full OpenID Connect support including ID tokens, user info endpoints, and discovery.

---

### ⚡ Core Capabilities

- **Authorization & Token Exchange** – Authorization code flow with PKCE (Proof Key for Code Exchange) for secure mobile and SPA applications.
- **Client Authentication** – Support for `client_secret_basic`, `client_secret_post`, and `private_key_jwt` methods.
- **Token Management** – Issue access tokens, refresh tokens, and ID tokens with configurable lifetimes and scopes.
- **Revocation & Introspection** – Full token lifecycle management including revocation and introspection endpoints.
- **JWKS & Discovery** – OpenID Connect discovery and JSON Web Key Set endpoints for seamless client integration.
- **External Provider Integration** – Authenticate users against external OIDC providers and exchange their credentials.
- **Session Management** – JWT-backed session tokens with secure cookie storage and validation.

---

### 🔌 Library Endpoints

The library exposes the following endpoints:

**Authorization & Tokens**
- `GET /authorize` – Authorization endpoint for initiating the OAuth flow
- `POST /oauth/token` – Token endpoint for exchanging authorization codes and refreshing tokens
- `POST /oauth/token/revocation` – Token revocation endpoint per RFC 7009

**Discovery & Keys**
- `GET /.well-known/openid-configuration` – OpenID Connect discovery document
- `GET /.well-known/jwks.json` – JSON Web Key Set for token signature verification

**User & Token Inspection**
- `GET /userinfo` – OpenID Connect userinfo endpoint for retrieving authenticated user claims
- `POST /oauth/token/introspection` – Token introspection endpoint per RFC 7662

**Administration**
- `GET /admin/rotate` – Key rotation endpoint for maintaining security posture

---

### 🎨 Customization

Better Goth is built for flexibility. While the library provides complete OAuth 2.1 and OpenID Connect implementations out of the box, you can override and customize critical parts of the flow:

- **User Flow** – Replace the user authentication handler to integrate with your own user store, LDAP, or custom identity system.
- **Authorization Flow** – Customize how authorization codes are generated, validated, and exchanged. Implement custom scopes, claim mapping, or consent flows.
- **Token Issuance** – Override token generation to add custom claims, apply business logic, or integrate with external systems.
- **Storage Backend** – Swap the default in-memory store for your own database layer (PostgreSQL, MySQL, SQLite) or custom implementation.
- **Session Management** – Customize session cookie behavior, JWT claims, session duration, and validation logic.
- **Hooks & Middleware** – Intercept requests at key points to add logging, metrics, audit trails, or custom validation.

The library's modular design ensures you can layer your own logic on top without forking or rewriting core OAuth flows.

---

### 🔗 Integration

Better Goth is designed to be embedded directly into your Go application. It handles OAuth 2.1 and OpenID Connect flows out of the box, with configuration through YAML. Wire it into your existing HTTP router to add authentication without external services.

The library manages its own key lifecycle, token storage, and client registry. Extend it with custom user stores, hooks, and business logic.

To see the library in action, check out the example app in the `examples/` directory. It demonstrates a complete end-to-end flow with user login, authorization, and token exchange.

---

### 📜 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
