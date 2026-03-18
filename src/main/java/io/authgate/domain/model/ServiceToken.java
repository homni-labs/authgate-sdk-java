package io.authgate.domain.model;

import io.authgate.domain.exception.IdentityProviderException;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable token obtained via {@code client_credentials} grant.
 *
 * <p>Designed exclusively for machine-to-machine communication:
 * no refresh token, no user context — just an access token with an expiry.</p>
 */
public final class ServiceToken {

    private static final Duration EXPIRY_MARGIN = Duration.ofSeconds(30);

    private final String accessToken;
    private final Instant expiresAt;

    private ServiceToken(String accessToken, Instant expiresAt) {
        this.accessToken = Objects.requireNonNull(accessToken);
        this.expiresAt = Objects.requireNonNull(expiresAt);
    }

    /**
     * Creates a {@code ServiceToken} from a standard OAuth 2.1 token response body.
     *
     * @throws IdentityProviderException if {@code access_token} is missing
     */
    public static ServiceToken fromTokenResponse(Map<String, Object> body) {
        var accessToken = body.get("access_token");
        if (accessToken == null) {
            throw new IdentityProviderException("Missing 'access_token' in token response");
        }

        long expiresInSeconds = body.containsKey("expires_in")
                ? ((Number) body.get("expires_in")).longValue()
                : 3600;

        return new ServiceToken(accessToken.toString(), Instant.now().plusSeconds(expiresInSeconds));
    }

    /**
     * Returns {@code true} if the token will expire within 30 seconds.
     */
    public boolean isExpiringSoon() {
        return Instant.now().plus(EXPIRY_MARGIN).isAfter(expiresAt);
    }

    /**
     * Returns the raw access token string.
     */
    public String accessToken() {
        return accessToken;
    }

    @Override
    public String toString() {
        return "ServiceToken[expiresAt=" + expiresAt + ", expiringSoon=" + isExpiringSoon() + "]";
    }
}
