package io.authgate.domain.exception;

/**
 * Thrown when a validated token does not satisfy required permissions.
 * Maps to HTTP 403 Forbidden.
 */
public final class AccessDeniedException extends AuthGateException {

    public AccessDeniedException(String reason) {
        super(reason);
    }
}
