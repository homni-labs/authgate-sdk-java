package io.authgate.application.port;

import java.time.Duration;

/**
 * Port for key-value caching with TTL support.
 *
 * <p>Default implementation: {@code InMemoryCacheStore} (ConcurrentHashMap with lazy expiration).
 * Users may provide external implementations (Redis, Memcached, etc.).</p>
 */
public interface CacheStore {

    /**
     * Retrieves a cached value by key.
     *
     * @return the cached value, or {@code null} if absent or expired
     */
    String get(String key);

    /**
     * Stores a value with the given TTL.
     * Overwrites any existing entry for the key.
     */
    void put(String key, String value, Duration ttl);

    /**
     * Removes a cached entry.
     */
    void evict(String key);
}
