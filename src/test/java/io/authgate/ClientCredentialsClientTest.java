package io.authgate;

import io.authgate.application.port.EndpointDiscovery;
import io.authgate.application.port.HttpTransport;
import io.authgate.credentials.ClientCredentialsClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("ClientCredentialsClient — scope validation")
class ClientCredentialsClientTest {

    private final ClientCredentialsClient client = new ClientCredentialsClient(
            () -> { throw new UnsupportedOperationException(); },
            new HttpTransport() {
                @Override public TransportResponse postForm(String endpoint, Map<String, String> params) {
                    throw new UnsupportedOperationException();
                }
                @Override public TransportResponse fetchJson(String endpoint) {
                    throw new UnsupportedOperationException();
                }
            },
            "test-client",
            "test-secret"
    );

    @Test
    void rejectsNullScopes() {
        assertThatThrownBy(() -> client.acquire(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("scopes must not be null");
    }

    @Test
    void rejectsEmptyScopes() {
        assertThatThrownBy(() -> client.acquire(Set.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be empty");
    }

    @Test
    void rejectsNullScopeElement() {
        assertThatThrownBy(() -> client.acquire(Collections.singleton(null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be null or blank");
    }

    @Test
    void rejectsBlankScope() {
        assertThatThrownBy(() -> client.acquire(Set.of("  ")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be null or blank");
    }

    @Test
    void rejectsScopeWithWhitespace() {
        assertThatThrownBy(() -> client.acquire(Set.of("user read")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not contain whitespace");
    }

    @Test
    void rejectsScopeWithLeadingSpace() {
        assertThatThrownBy(() -> client.acquire(Set.of(" read")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not contain whitespace");
    }

    @Test
    void rejectsScopeWithTab() {
        assertThatThrownBy(() -> client.acquire(Set.of("user\tread")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not contain whitespace");
    }
}
