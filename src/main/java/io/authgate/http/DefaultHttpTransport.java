package io.authgate.http;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.authgate.application.port.HttpTransport;
import io.authgate.domain.exception.IdentityProviderException;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Minimal HTTP transport using {@code java.net.http.HttpClient}.
 * Zero framework dependencies — works in any Java 21 environment.
 */
public final class DefaultHttpTransport implements HttpTransport, Closeable {

    private static final String JSON_CONTENT_TYPE = "application/json";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration requestTimeout;

    public DefaultHttpTransport(Duration connectTimeout) {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        this.objectMapper = new ObjectMapper();
        this.requestTimeout = connectTimeout;
    }

    public DefaultHttpTransport() {
        this(Duration.ofSeconds(10));
    }

    @Override
    public TransportResponse postForm(String endpoint, Map<String, String> params) {
        var body = params.entrySet().stream()
                .filter(e -> e.getValue() != null)
                .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(Collectors.joining("&"));

        var request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(requestTimeout)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", JSON_CONTENT_TYPE)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        return execute(request);
    }

    @Override
    public TransportResponse fetchJson(String endpoint) {
        var request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(requestTimeout)
                .header("Accept", JSON_CONTENT_TYPE)
                .GET()
                .build();

        return execute(request);
    }

    @Override
    public void close() {
        httpClient.close();
    }

    private TransportResponse execute(HttpRequest request) {
        try {
            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            var contentType = response.headers().firstValue("Content-Type").orElse("");

            if (!contentType.contains("json")) {
                throw new IdentityProviderException(
                        "Expected JSON response from " + request.uri()
                                + " but received Content-Type: " + contentType
                                + " (HTTP " + response.statusCode() + ")");
            }

            Map<String, Object> body = objectMapper.readValue(response.body(), new TypeReference<>() {});
            return new TransportResponse(response.statusCode(), body);
        } catch (IdentityProviderException e) {
            throw e;
        } catch (IOException e) {
            throw new IdentityProviderException("HTTP request failed: " + request.uri(), e);
        } catch (InterruptedException e) {
            //TODO не оч хорошее решение, но HttpClient.send() может выбросить InterruptedException, и мы должны уважать это
            Thread.currentThread().interrupt();
            throw new IdentityProviderException("HTTP request interrupted: " + request.uri(), e);
        }
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
