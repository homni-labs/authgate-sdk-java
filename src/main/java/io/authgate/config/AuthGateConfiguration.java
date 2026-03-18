package io.authgate.config;

import java.time.Duration;
import java.util.Objects;

/**
 * Immutable SDK configuration.
 *
 * <p>All OIDC endpoints are resolved automatically via
 * {@code {issuerUri}/.well-known/openid-configuration}.</p>
 *
 * <h2>Required parameters:</h2>
 * <ul>
 *   <li>{@code issuerUri} — base URL of the OIDC provider
 *       (e.g. {@code https://idp.example.com/realms/my-realm/}).
 *       Used to discover JWKS, token, and authorization endpoints.</li>
 *   <li>{@code clientId} — OAuth 2.1 client identifier registered at the provider.
 *       Used for token introspection and client-credentials flow.</li>
 * </ul>
 *
 * <h2>Optional parameters (with defaults):</h2>
 * <ul>
 *   <li>{@code clientSecret} — OAuth 2.1 client secret. Required only for
 *       the client-credentials grant. Default: {@code null} (no secret).</li>
 *   <li>{@code audience} — expected {@code aud} claim for token validation.
 *       When set, tokens without this audience are rejected. Default: {@code null} (no audience check).</li>
 *   <li>{@code httpTimeout} — connection and read timeout for all HTTP calls
 *       (discovery, JWKS, token endpoint). Default: {@code 10s}.</li>
 *   <li>{@code discoveryTtl} — how long the OIDC discovery document is cached
 *       before re-fetching. Default: {@code 1h}.</li>
 *   <li>{@code clockSkewTolerance} — allowed clock drift when verifying
 *       token expiration ({@code exp}) and not-before ({@code nbf}) claims.
 *       Default: {@code 30s}.</li>
 *   <li>{@code requireHttps} — when {@code true}, rejects issuer URIs that
 *       are not HTTPS. Disable for local development only. Default: {@code false}.</li>
 * </ul>
 *
 * <h2>Minimal example:</h2>
 * <pre>{@code
 * var config = new AuthGateConfiguration.Builder()
 *     .issuerUri("https://idp.example.com/realms/my-realm/")
 *     .clientId("my-client")
 *     .build();
 * }</pre>
 */
public final class AuthGateConfiguration {

    private final String issuerUri;
    private final String clientId;
    private final String clientSecret;
    private final String audience;
    private final Duration httpTimeout;
    private final Duration discoveryTtl;
    private final Duration clockSkewTolerance;
    private final boolean requireHttps;

    private AuthGateConfiguration(Builder builder) {
        this.issuerUri = Objects.requireNonNull(builder.issuerUri, "issuerUri must not be null");
        this.clientId = Objects.requireNonNull(builder.clientId, "clientId must not be null");
        this.clientSecret = builder.clientSecret;
        this.audience = builder.audience;
        this.httpTimeout = Objects.requireNonNullElse(builder.httpTimeout, Duration.ofSeconds(10));
        this.discoveryTtl = Objects.requireNonNullElse(builder.discoveryTtl, Duration.ofHours(1));
        this.clockSkewTolerance = Objects.requireNonNullElse(builder.clockSkewTolerance, Duration.ofSeconds(30));
        this.requireHttps = builder.requireHttps;
    }

    // ── Accessors ────────────────────────────────────────────────

    /** OIDC provider base URL. Never {@code null}. */
    public String issuerUri()           { return issuerUri; }

    /** OAuth 2.1 client identifier. Never {@code null}. */
    public String clientId()            { return clientId; }

    /** OAuth 2.1 client secret. {@code null} if not configured. */
    public String clientSecret()        { return clientSecret; }

    /** Expected {@code aud} claim. {@code null} if audience check is disabled. */
    public String audience()            { return audience; }

    /** HTTP timeout for all IdP calls. Never {@code null}. */
    public Duration httpTimeout()       { return httpTimeout; }

    /** OIDC discovery cache TTL. Never {@code null}. */
    public Duration discoveryTtl()      { return discoveryTtl; }

    /** Clock skew tolerance for token expiration checks. Never {@code null}. */
    public Duration clockSkewTolerance() { return clockSkewTolerance; }

    /** Whether to reject non-HTTPS issuer URIs. */
    public boolean requireHttps()       { return requireHttps; }

    public static final class Builder {
        private String issuerUri;
        private String clientId;
        private String clientSecret;
        private String audience;
        private Duration httpTimeout;
        private Duration discoveryTtl;
        private Duration clockSkewTolerance;
        private boolean requireHttps;

        public Builder() {}

        public Builder issuerUri(String v)                { this.issuerUri = v; return this; }
        public Builder clientId(String v)                 { this.clientId = v; return this; }
        public Builder clientSecret(String v)             { this.clientSecret = v; return this; }
        public Builder audience(String v)                 { this.audience = v; return this; }
        public Builder httpTimeout(Duration v)            { this.httpTimeout = v; return this; }
        public Builder discoveryTtl(Duration v)           { this.discoveryTtl = v; return this; }
        public Builder clockSkewTolerance(Duration v)     { this.clockSkewTolerance = v; return this; }
        public Builder requireHttps(boolean v)            { this.requireHttps = v; return this; }

        public AuthGateConfiguration build() {
            return new AuthGateConfiguration(this);
        }
    }
}
