# AuthGate SDK

Provider-agnostic OIDC library for Java 21+. Handles JWT validation and client-credentials token acquisition — without framework dependencies.

## Key Concepts

| Term | Description |
|---|---|
| **IdP** (Identity Provider) | Authentication server that issues tokens. Examples: Keycloak, Auth0, Okta, Azure AD |
| **OIDC** (OpenID Connect) | Authentication protocol on top of OAuth 2.1. Defines a standard way to obtain user identity |
| **JWT** (JSON Web Token) | Signed token containing claims about the user. Issued by the IdP, verified by your service |
| **JWKS** (JSON Web Key Set) | Set of public keys from the IdP used to verify JWT signatures. Fetched automatically |
| **Claims** | Fields inside a JWT: `sub` (who), `iss` (issued by), `aud` (intended for), `exp` (expires at), `scope` (permissions) |
| **Scope** | Permission recorded in the token. Examples: `openid`, `profile`, `admin` |
| **Audience** (`aud`) | Identifier of the service the token is intended for. If your service is `my-api`, tokens without `aud=my-api` will be rejected |
| **Client Credentials** | OAuth 2.1 grant for service-to-service communication. A service obtains its own token without user involvement |
| **Discovery** | Endpoint `{issuerUri}/.well-known/openid-configuration` — the IdP publishes its URLs (token, jwks, authorization) |

## Installation

```xml
<dependency>
    <groupId>io.authgate</groupId>
    <artifactId>authgate-sdk</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Configuration

| Parameter | Required | Default | Description |
|---|---|---|---|
| `issuerUri` | **yes** | — | OIDC provider base URL. Used to discover JWKS, token, and authorization endpoints via `{issuerUri}/.well-known/openid-configuration` |
| `clientId` | **yes** | — | OAuth 2.1 client identifier registered at the provider |
| `clientSecret` | no | `null` | OAuth 2.1 client secret. Required only for the client-credentials grant |
| `audience` | no | `null` | Expected `aud` claim. When set, tokens without this audience are rejected |
| `httpTimeout` | no | `10s` | Connection and read timeout for all HTTP calls (discovery, JWKS, token endpoint) |
| `discoveryTtl` | no | `1h` | OIDC discovery document cache TTL |
| `clockSkewTolerance` | no | `30s` | Allowed clock drift when verifying `exp` and `nbf` claims |
| `requireHttps` | no | `false` | Reject non-HTTPS issuer URIs. Disable only for local development |

## Usage

### Initialization

```java
var sdk = new AuthGate(new AuthGateConfiguration.Builder()
        .issuerUri("https://idp.example.com/realms/my-realm/")
        .clientId("my-client")
        .clientSecret("secret")       // optional — needed for client-credentials
        .audience("my-api")           // optional — enables audience validation
        .build());
```

### Token Validation

`authorize()` validates the token and returns a fluent chain. Two ways to get the result:

**Exception-based** — zero handling, catch globally (e.g. `@ExceptionHandler`).
Throws `TokenValidationException` (401) or `AccessDeniedException` (403):

```java
// just validate — any authenticated user
sdk.authorizeFromHeader(authHeader).orThrow();

// require specific scope
sdk.authorizeFromHeader(authHeader).scope("admin").orThrow();

// require scope + owner check
sdk.authorizeFromHeader(authHeader).scope("admin").subject(userId).orThrow();

// require audience
sdk.authorizeFromHeader(authHeader).audience("my-api").orThrow();
```

Full example:

```java
// Only authenticated users — no role/scope needed
public ResponseEntity<?> getProfile(String authHeader) {
    ValidatedToken token = sdk.authorizeFromHeader(authHeader).orThrow();
    log.info("Profile accessed by {}", token.subject());
    return ResponseEntity.ok(profileService.get());
}

// Admin-only endpoint
public ResponseEntity<?> deleteUser(String authHeader, String userId) {
    sdk.authorizeFromHeader(authHeader).scope("admin").subject(userId).orThrow();
    userService.delete(userId);
    return ResponseEntity.noContent().build();
}
```

**Polymorphic** — `AuthorizationResult` sealed interface with `Granted`, `Denied`, `Rejected`:

```java
return switch (sdk.authorizeFromHeader(authHeader).evaluate()) {
    case AuthorizationResult.Granted g -> {
        log.info("User: {}", g.token().subject());
        yield ResponseEntity.ok(data);
    }
    case AuthorizationResult.Denied d -> {
        log.warn(d.reason());
        yield ResponseEntity.status(403).build();
    }
    case AuthorizationResult.Rejected r -> {
        log.warn(r.reason().description());
        yield ResponseEntity.status(401).build();
    }
};
```

**Rejection codes:**

| Code | Description |
|---|---|
| `TOKEN_EXPIRED` | Token has expired |
| `INVALID_SIGNATURE` | Signature verification failed |
| `ISSUER_MISMATCH` | Issuer does not match the expected value |
| `AUDIENCE_MISMATCH` | Audience does not match |
| `MALFORMED_TOKEN` | Invalid JWT structure |
| `UNKNOWN` | Unexpected error |

### Client Credentials (Service-to-Service)

OAuth 2.1 grant for machine-to-machine communication. A service authenticates with its own identity (no user involvement) and receives an access token. Use this when one backend service needs to call another.

**Use cases:**

| Case | Description |
|---|---|
| Microservice-to-microservice | Order Service calls User Service to fetch user data |
| Background jobs / Cron | Scheduled tasks that sync data or send reports |
| Telegram bot | Bot calls internal APIs with its own service token |
| API Gateway | Gateway acquires a service token for downstream services |
| ETL / Data sync | Import/export services accessing protected APIs |

**Basic usage:**

```java
ServiceToken token = sdk.acquireServiceToken(Set.of("user:read", "order:read"));

// Tokens are cached per scope-set and refreshed automatically before expiry
httpClient.header("Authorization", "Bearer " + token.accessToken());
```

**Microservice-to-microservice example:**

```java
// Order Service calls User Service
var sdk = new AuthGate(new AuthGateConfiguration.Builder()
        .issuerUri("https://idp.example.com/realms/production/")
        .clientId("order-service")
        .clientSecret("order-service-secret")
        .build());

ServiceToken token = sdk.acquireServiceToken(Set.of("user:read"));
httpClient.newRequest("https://user-service/api/users/" + userId)
    .header("Authorization", "Bearer " + token.accessToken())
    .send();
```

**Background job example:**

```java
// Cron job that syncs data every hour
ServiceToken token = sdk.acquireServiceToken(Set.of("data:sync"));
syncClient.header("Authorization", "Bearer " + token.accessToken());
```

### Cache

The SDK caches two types of data with different strategies:

| What | Storage | TTL |
|---|---|---|
| OIDC discovery document | `CacheStore` (pluggable) | `discoveryTtl` (default 1h) |
| Service tokens (client_credentials) | In-process `ConcurrentHashMap` | Until 30s before `expires_in` |

**OIDC discovery** uses the `CacheStore` port — shareable across instances via Redis, Memcached, etc.

**Service tokens** are always kept in process memory (`ConcurrentHashMap`). No serialization, no external cache — tokens are re-fetched atomically when expiring soon. This is intentional: service tokens are cheap to obtain and should not leak to external storage.

**Default CacheStore** — in-memory `ConcurrentHashMap` with lazy expiration. No background threads, no external dependencies. Works out of the box for single-instance deployments.

**Custom CacheStore** — implement the `CacheStore` interface and pass it to the constructor:

```java
public class RedisCacheStore implements CacheStore {
    @Override public String get(String key) { /* ... */ }
    @Override public void put(String key, String value, Duration ttl) { /* ... */ }
    @Override public void evict(String key) { /* ... */ }
}

var sdk = new AuthGate(config, new RedisCacheStore());
```

Use a shared `CacheStore` (Redis, Memcached, etc.) when running multiple instances — otherwise each instance fetches its own discovery document.

**Custom HttpTransport** — implement the `HttpTransport` interface and pass it to the constructor:

```java
var sdk = new AuthGate(config, new InMemoryCacheStore(), new MyCustomHttpTransport());
```

**Disabling cache** — pass a no-op implementation. Not recommended for production (every call triggers an HTTP request to the IdP):

```java
var sdk = new AuthGate(config, new CacheStore() {
    @Override public String get(String key) { return null; }
    @Override public void put(String key, String value, Duration ttl) {}
    @Override public void evict(String key) {}
});
```

## Architecture

```
AuthGate (facade)
├── TokenValidator              — JWT validation (signature, claims, expiration)
├── ClientCredentialsClient     — service token acquisition (cache, auto-refresh)
├── OidcDiscoveryClient         — IdP endpoint discovery (TTL cache)
└── HttpTransport (port)        — HTTP client (default: java.net.http)
```

## Dependencies

| Library | Purpose |
|---|---|
| Nimbus JOSE JWT | JWT validation, JWKS, signature verification |
| Jackson | JSON parsing |
| SLF4J | Logging |

**Requires:** Java 21+
